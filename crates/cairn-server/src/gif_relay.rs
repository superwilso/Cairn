//! The GIF relay's rules. See `docs/14-gifs.md`.
//!
//! The instance relays opaque bytes between a member's client and a GIF provider, in the
//! shape Signal built for GIPHY: TLS runs end to end between the client and the provider
//! *through* the instance. The provider sees the search but not who asked; the instance
//! sees that a search happened, which provider host it went to, and how big the answer
//! was — but not what was searched for or which GIF came back.
//!
//! Every rule about that relay is here. `http.rs` only parses the request, dials what these
//! functions approved, and copies bytes within the limits they set — the same split as the
//! rest of the server, for the same reason: a rule in a handler is untested and bypassable.
//!
//! ## What the relay must never become
//!
//! An authenticated member can ask the instance to open a TCP connection somewhere. If
//! "somewhere" were theirs to choose, the instance would be an open proxy into its own
//! network — the database, the cloud metadata service, the admin panel on localhost. So
//! the destination is chosen from a **fixed list of names in this file**, on port 443 only,
//! and the addresses those names resolve to are checked again before dialling
//! ([`gif_upstream_permitted`]). The tests at the bottom are the attacks, kept.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};

use serde::{Deserialize, Serialize};

use cairn_proto::UserId;

use crate::state::{Instance, ServerError, CLAIM_WINDOW_MS};

/// How many GIF relay tunnels one account may open per window.
///
/// A tunnel is a TCP connection to one provider host, not a search: a client keeps a few
/// open and reuses them for a burst of requests, so opening the picker and typing a search
/// is usually a handful of these. Six hundred an hour is a person searching constantly;
/// past that it is a member using the operator's network as a pipe to the provider.
pub const MAX_GIF_TUNNELS_PER_WINDOW: usize = 600;

/// How many bytes one account may relay through GIF tunnels per window, both directions.
///
/// This is the operator's bandwidth, which `docs/13-customisation.md` §2 is explicit is
/// someone's real bill. A page of small previews is one to three megabytes; this allows
/// dozens of those an hour and bounds what one member can cost the operator.
pub const MAX_GIF_RELAY_BYTES_PER_WINDOW: u64 = 200 * 1024 * 1024;

/// The most one tunnel may carry before the instance closes it.
pub const MAX_GIF_TUNNEL_BYTES: u64 = 32 * 1024 * 1024;

/// A tunnel with no traffic in either direction for this long is closed.
pub const GIF_TUNNEL_IDLE_MS: u64 = 30_000;

/// The longest a tunnel may stay open, however busy. Without it a trickle of one byte per
/// idle period would hold a connection, and a file descriptor, open indefinitely.
pub const GIF_TUNNEL_MAX_LIFETIME_MS: u64 = 5 * 60_000;

/// A GIF provider an operator can configure.
///
/// Tenor is absent because its API shut down in June 2026, not by oversight.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GifProvider {
    Klipy,
    Giphy,
}

impl GifProvider {
    pub const ALL: [GifProvider; 2] = [GifProvider::Klipy, GifProvider::Giphy];

    pub const fn label(self) -> &'static str {
        match self {
            Self::Klipy => "klipy",
            Self::Giphy => "giphy",
        }
    }

    /// The environment variable an operator puts this provider's key in.
    pub const fn env_var(self) -> &'static str {
        match self {
            Self::Klipy => "CAIRN_KLIPY_API_KEY",
            Self::Giphy => "CAIRN_GIPHY_API_KEY",
        }
    }

    /// Every host the relay will open a tunnel to for this provider: its API and its media
    /// CDN, and nothing else.
    ///
    /// **This list is the security boundary of the relay.** Anything named here can be
    /// reached from inside the instance's network by any member, so it is a fixed list in
    /// the source rather than operator configuration — an operator who could add a host
    /// could add `localhost` by accident. KLIPY's comes from its published network
    /// requirements (docs.klipy.com/network-requirements, read October 2026), minus the bare
    /// `klipy.com` website, which no API call needs. GIPHY's are the hosts its API returns
    /// media on.
    pub const fn hosts(self) -> &'static [&'static str] {
        match self {
            Self::Klipy => {
                &["api.klipy.com", "static.klipy.com", "static1.klipy.com", "static2.klipy.com"]
            }
            Self::Giphy => &[
                "api.giphy.com",
                "i.giphy.com",
                "media.giphy.com",
                "media0.giphy.com",
                "media1.giphy.com",
                "media2.giphy.com",
                "media3.giphy.com",
                "media4.giphy.com",
            ],
        }
    }
}

/// The operator's GIF configuration: zero, one or both providers, each with its key.
///
/// Keys are redacted from `Debug` because they are operator credentials, even though they
/// are not secrets from the instance's own members — see [`Instance::gif_capability`].
#[derive(Clone, Default)]
pub struct GifRelayConfig {
    keys: Vec<(GifProvider, String)>,
    /// Where every approved tunnel actually connects, bypassing DNS. **For tests**, which
    /// need a provider on loopback; there is no environment variable for it, because an
    /// operator who could point the relay at an arbitrary address could point it inward.
    upstream_override: Option<SocketAddr>,
}

impl std::fmt::Debug for GifRelayConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GifRelayConfig")
            .field("providers", &self.keys.iter().map(|(p, _)| *p).collect::<Vec<_>>())
            .field("api_keys", &"<redacted>")
            .finish()
    }
}

impl GifRelayConfig {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a provider, refusing a key that could not be a key.
    ///
    /// The key is placed in a URL by the client — in the *path*, for KLIPY — so a key with
    /// a `/`, `?`, `#` or `&` in it would silently rewrite the request rather than fail.
    /// Both providers issue plain alphanumeric keys.
    pub fn with_provider(
        mut self,
        provider: GifProvider,
        api_key: &str,
    ) -> Result<Self, ServerError> {
        let api_key = api_key.trim();
        if api_key.is_empty() {
            return Err(ServerError::GifConfigInvalid(format!(
                "{} is set but empty",
                provider.env_var()
            )));
        }
        if api_key.len() > 256
            || !api_key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(ServerError::GifConfigInvalid(format!(
                "{} may contain only letters, digits, '-' and '_'",
                provider.env_var()
            )));
        }
        self.keys.retain(|(p, _)| *p != provider);
        self.keys.push((provider, api_key.to_owned()));
        self.keys.sort_by_key(|(p, _)| GifProvider::ALL.iter().position(|q| q == p));
        Ok(self)
    }

    /// Route every approved tunnel to `addr` instead of resolving the provider's hosts.
    /// The allowlist still applies to the *name* the client asked for. Tests only.
    #[doc(hidden)]
    pub fn with_upstream_override(mut self, addr: SocketAddr) -> Self {
        self.upstream_override = Some(addr);
        self
    }

    pub fn providers(&self) -> Vec<GifProvider> {
        self.keys.iter().map(|(p, _)| *p).collect()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

/// What a member's client needs to use one provider through the relay.
#[derive(Debug, Clone)]
pub struct GifCapability {
    pub provider: GifProvider,
    /// Handed to every authenticated member. See [`Instance::gif_capability`] for why that
    /// is unavoidable rather than careless.
    pub api_key: String,
    pub hosts: &'static [&'static str],
}

/// A tunnel the rules have approved, and the limits `http.rs` must hold it to.
#[derive(Debug, Clone)]
pub struct GifTunnelGrant {
    pub actor: UserId,
    /// Lower-cased, and one of a configured provider's [`GifProvider::hosts`].
    pub host: String,
    pub port: u16,
    /// Bytes this tunnel may carry, both directions together: the smaller of
    /// [`MAX_GIF_TUNNEL_BYTES`] and what is left of the account's window.
    pub max_bytes: u64,
    pub idle_timeout_ms: u64,
    pub max_lifetime_ms: u64,
    /// Set only by [`GifRelayConfig::with_upstream_override`].
    pub upstream_override: Option<SocketAddr>,
}

/// Tunnels opened and bytes relayed, per account. In memory, like the other limiters.
#[derive(Debug, Default)]
pub struct GifRelayLimiter {
    opens: HashMap<UserId, VecDeque<i64>>,
    bytes: HashMap<UserId, VecDeque<(i64, u64)>>,
}

impl GifRelayLimiter {
    /// Record an open, or refuse. Returns the bytes the account has left this window.
    ///
    /// Like the others, a refusal is not recorded, so a client that backs off on a 429
    /// recovers when the window rolls.
    fn admit(&mut self, actor: UserId, now_ms: i64) -> Result<u64, ServerError> {
        let expired = |at: i64| now_ms.saturating_sub(at) >= CLAIM_WINDOW_MS;
        let opens = self.opens.entry(actor).or_default();
        while opens.front().is_some_and(|at| expired(*at)) {
            opens.pop_front();
        }
        let bytes = self.bytes.entry(actor).or_default();
        while bytes.front().is_some_and(|(at, _)| expired(*at)) {
            bytes.pop_front();
        }
        let used: u64 = bytes.iter().map(|(_, n)| *n).sum();
        if opens.len() >= MAX_GIF_TUNNELS_PER_WINDOW || used >= MAX_GIF_RELAY_BYTES_PER_WINDOW {
            return Err(ServerError::RateLimited);
        }
        opens.push_back(now_ms);
        Ok(MAX_GIF_RELAY_BYTES_PER_WINDOW - used)
    }

    /// Charge bytes a tunnel actually carried. After the fact, so never refused: the bytes
    /// have already crossed, and the next `admit` is where the charge bites.
    fn charge(&mut self, actor: UserId, bytes: u64, now_ms: i64) {
        if bytes > 0 {
            self.bytes.entry(actor).or_default().push_back((now_ms, bytes));
        }
    }
}

/// Whether the relay may connect to an address a provider's hostname resolved to.
///
/// The allowlist is of *names*, and a name is only as trustworthy as the DNS answer for
/// it. A provider host that resolved to `127.0.0.1` or `169.254.169.254` — a poisoned
/// resolver, a hijacked record, split-horizon DNS inside the operator's network — would
/// otherwise turn the relay into a way for any member to reach the instance's own network.
/// Cheap to refuse, so refused.
pub fn gif_upstream_permitted(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            !(v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_unspecified()
                || v4.is_multicast()
                || v4.is_documentation()
                // 0.0.0.0/8, which some stacks route to the local host.
                || o[0] == 0
                // 100.64.0.0/10: carrier-grade NAT, and Tailscale's range — exactly where a
                // home instance's private services live (`docs/11-self-hosting.md`).
                || (o[0] == 100 && (64..128).contains(&o[1]))
                // 198.18.0.0/15, benchmarking; 240.0.0.0/4, reserved.
                || (o[0] == 198 && (o[1] == 18 || o[1] == 19))
                || o[0] >= 240)
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return gif_upstream_permitted(IpAddr::V4(v4));
            }
            let s = v6.segments();
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                // fc00::/7 unique-local, fe80::/10 link-local.
                || (s[0] & 0xfe00) == 0xfc00
                || (s[0] & 0xffc0) == 0xfe80
                // ::/96, the deprecated IPv4-compatible form, which some stacks still route
                // to the embedded IPv4 address.
                || (s[..6] == [0, 0, 0, 0, 0, 0])
                // 64:ff9b::/96 NAT64 would let a v6 name reach any v4 address, including
                // private ones, behind a NAT64 gateway.
                || (s[0] == 0x64 && s[1] == 0xff9b))
        }
    }
}

/// The signed action a tunnel request carries. The target is *inside* the signed action,
/// so a captured authorization cannot be replayed to open a tunnel to a different host —
/// `request_signing_bytes` length-prefixes the action, so no two targets collide.
pub fn gif_tunnel_action(target: &str) -> String {
    format!("gif_tunnel:{target}")
}

/// Split a tunnel target into host and port, accepting only the canonical spelling.
///
/// `rsplit_once`, so an IPv6 literal's colons cannot be mistaken for the port separator —
/// not that one would pass the allowlist, which is the point of not parsing further. The
/// port must be written exactly as the number it is: a probe found `api.klipy.com:0443`
/// being accepted as port 443. Harmless, since it is the same port, but the target is part
/// of what the device signed, and two spellings of one target is a gap with no use.
pub fn parse_tunnel_target(target: &str) -> Result<(&str, u16), ServerError> {
    let (host, port_text) = target.rsplit_once(':').ok_or(ServerError::GifTargetRefused)?;
    let port: u16 = port_text.parse().map_err(|_| ServerError::GifTargetRefused)?;
    if port.to_string() != port_text {
        return Err(ServerError::GifTargetRefused);
    }
    Ok((host, port))
}

/// The signed action for asking which providers this instance relays.
pub const GIF_CAPABILITY_ACTION: &str = "gif_capability";

/// The protocol name a client asks to upgrade to.
pub const GIF_TUNNEL_PROTOCOL: &str = "cairn-gif-tunnel";

impl Instance {
    /// Configure the GIF providers, or turn GIFs off with `None`. Operator action.
    pub fn set_gif_relay(&self, config: Option<GifRelayConfig>) {
        *self.gif_relay.lock().expect("gif relay mutex poisoned") =
            config.filter(|c| !c.is_empty());
    }

    /// What an authenticated member needs to search for GIFs: one entry per configured
    /// provider, empty when there are none — in which case a client's picker says so.
    ///
    /// ## The keys go to every member, and that is the honest shape of this design
    ///
    /// TLS runs between the client and the provider, so the instance cannot add the key to
    /// a request it cannot read: whoever builds the request must hold the key. Signal ships
    /// its GIPHY key inside the app for the same reason. So a key here is an
    /// **instance-scoped quota token, not a secret from members**: any member can extract
    /// it and use it directly, spending the operator's quota or getting the key revoked.
    /// What it is still kept from is strangers — this requires an authenticated account —
    /// and logs, which is why `GifRelayConfig` redacts it.
    pub fn gif_capability(&self, _actor: UserId) -> Vec<GifCapability> {
        let guard = self.gif_relay.lock().expect("gif relay mutex poisoned");
        let Some(config) = guard.as_ref() else { return Vec::new() };
        config
            .keys
            .iter()
            .map(|(provider, key)| GifCapability {
                provider: *provider,
                api_key: key.clone(),
                hosts: provider.hosts(),
            })
            .collect()
    }

    /// Approve a relay tunnel from `actor` to `host:port`, or refuse it.
    ///
    /// The rules, in order: the operator configured a provider; the port is 443; the host
    /// is exactly one of a *configured* provider's hosts, compared case-insensitively and
    /// with no normalisation beyond that (a trailing dot, a userinfo prefix, a
    /// percent-escape or an IP literal is simply not on the list); and the account is
    /// within its window.
    ///
    /// Counted before the upstream is dialled, so an attempt that fails upstream still
    /// counts — otherwise a member could probe the provider's reachability for free.
    pub fn authorize_gif_tunnel(
        &self,
        actor: UserId,
        host: &str,
        port: u16,
        now_ms: i64,
    ) -> Result<GifTunnelGrant, ServerError> {
        let (providers, upstream_override) = {
            let guard = self.gif_relay.lock().expect("gif relay mutex poisoned");
            let config = guard.as_ref().ok_or(ServerError::GifsDisabled)?;
            (config.providers(), config.upstream_override)
        };
        if port != 443 {
            return Err(ServerError::GifTargetRefused);
        }
        let host = host.to_ascii_lowercase();
        let allowed = providers.iter().any(|p| p.hosts().iter().any(|allowed| *allowed == host));
        if !allowed {
            return Err(ServerError::GifTargetRefused);
        }
        let remaining =
            self.gif_limiter.lock().expect("gif limiter mutex poisoned").admit(actor, now_ms)?;
        Ok(GifTunnelGrant {
            actor,
            host,
            port,
            max_bytes: remaining.min(MAX_GIF_TUNNEL_BYTES),
            idle_timeout_ms: GIF_TUNNEL_IDLE_MS,
            max_lifetime_ms: GIF_TUNNEL_MAX_LIFETIME_MS,
            upstream_override,
        })
    }

    /// Charge the bytes a finished tunnel carried against its account's window.
    pub fn record_gif_relay_bytes(&self, actor: UserId, bytes: u64, now_ms: i64) {
        self.gif_limiter.lock().expect("gif limiter mutex poisoned").charge(actor, bytes, now_ms);
    }
}

/// The relay's rules. Each refusal below was run against the relay as an attack first, and
/// is kept as the regression test for it.
#[cfg(test)]
mod tests {
    use super::*;

    fn configured(providers: &[GifProvider]) -> Instance {
        let inst = Instance::in_memory();
        let mut config = GifRelayConfig::new();
        for p in providers {
            config = config.with_provider(*p, "test-key_123").unwrap();
        }
        inst.set_gif_relay(Some(config));
        inst
    }

    #[test]
    fn with_no_provider_configured_there_is_no_capability_and_no_tunnel() {
        for inst in [Instance::in_memory(), configured(&[])] {
            let actor = UserId::new();
            assert!(inst.gif_capability(actor).is_empty(), "no key must mean no picker");
            assert!(matches!(
                inst.authorize_gif_tunnel(actor, "api.klipy.com", 443, 0),
                Err(ServerError::GifsDisabled)
            ));
        }
    }

    #[test]
    fn both_providers_can_be_configured_at_once_and_each_is_offered() {
        let inst = configured(&[GifProvider::Giphy, GifProvider::Klipy]);
        let offered: Vec<_> =
            inst.gif_capability(UserId::new()).iter().map(|c| c.provider).collect();
        assert_eq!(offered, [GifProvider::Klipy, GifProvider::Giphy], "a stable order for tabs");
        let actor = UserId::new();
        inst.authorize_gif_tunnel(actor, "api.klipy.com", 443, 0).unwrap();
        inst.authorize_gif_tunnel(actor, "media2.giphy.com", 443, 0).unwrap();
    }

    #[test]
    fn the_relay_reaches_only_the_configured_providers_hosts_on_443() {
        let inst = configured(&[GifProvider::Klipy]);
        let actor = UserId::new();
        for host in GifProvider::Klipy.hosts() {
            inst.authorize_gif_tunnel(actor, host, 443, 0).expect("a provider host is allowed");
        }
        // Case is the only normalisation, because DNS names are case-insensitive.
        inst.authorize_gif_tunnel(actor, "API.Klipy.COM", 443, 0).unwrap();

        let refused = [
            ("127.0.0.1", 443),
            ("localhost", 443),
            ("169.254.169.254", 443),
            ("[::1]", 443),
            ("::1", 443),
            ("10.0.0.1", 443),
            ("cairn-server", 443),
            ("db.internal", 443),
            ("metadata.google.internal", 443),
            // The bare website KLIPY lists, which no API call needs.
            ("klipy.com", 443),
            // The provider's own hosts, on another port.
            ("api.klipy.com", 80),
            ("api.klipy.com", 22),
            ("api.klipy.com", 8443),
            ("static.klipy.com", 6379),
            // Look-alikes and smuggling attempts: none of these is on the list, so none of
            // them is parsed for what it might mean.
            ("api.klipy.com.", 443),
            ("api.klipy.com.evil.example", 443),
            ("evilapi.klipy.com", 443),
            ("user@api.klipy.com", 443),
            ("api.klipy.com@127.0.0.1", 443),
            ("api.klipy.com%00", 443),
            ("api.klipy.com\0", 443),
            ("api.klipy.com:443", 443),
            ("api.klipy.com/../", 443),
            (" api.klipy.com", 443),
            ("", 443),
            // Another provider's host, while this instance is configured for KLIPY alone.
            ("api.giphy.com", 443),
        ];
        for (host, port) in refused {
            assert!(
                matches!(
                    inst.authorize_gif_tunnel(actor, host, port, 0),
                    Err(ServerError::GifTargetRefused)
                ),
                "{host:?}:{port} must be refused"
            );
        }
    }

    #[test]
    fn a_tunnel_target_has_one_spelling() {
        assert_eq!(parse_tunnel_target("api.klipy.com:443").unwrap(), ("api.klipy.com", 443));
        for bad in [
            "api.klipy.com",
            "api.klipy.com:0443",
            "api.klipy.com:+443",
            "api.klipy.com: 443",
            "api.klipy.com:",
            ":443x",
        ] {
            assert!(parse_tunnel_target(bad).is_err(), "{bad:?} must not parse");
        }
    }

    #[test]
    fn a_giphy_only_instance_does_not_reach_klipy() {
        let inst = configured(&[GifProvider::Giphy]);
        let actor = UserId::new();
        inst.authorize_gif_tunnel(actor, "api.giphy.com", 443, 0).unwrap();
        assert!(matches!(
            inst.authorize_gif_tunnel(actor, "api.klipy.com", 443, 0),
            Err(ServerError::GifTargetRefused)
        ));
    }

    #[test]
    fn tunnels_are_limited_per_account_and_the_limit_lifts_when_the_window_rolls() {
        let inst = configured(&[GifProvider::Klipy]);
        let (greedy, other) = (UserId::new(), UserId::new());
        for _ in 0..MAX_GIF_TUNNELS_PER_WINDOW {
            inst.authorize_gif_tunnel(greedy, "api.klipy.com", 443, 0).unwrap();
        }
        // Refusals are not recorded, so a client retrying on a 429 is not punished further.
        for t in 0..20 {
            assert!(matches!(
                inst.authorize_gif_tunnel(greedy, "api.klipy.com", 443, t),
                Err(ServerError::RateLimited)
            ));
        }
        inst.authorize_gif_tunnel(other, "api.klipy.com", 443, 0)
            .expect("one account's use must not spend another's");
        inst.authorize_gif_tunnel(greedy, "api.klipy.com", 443, CLAIM_WINDOW_MS)
            .expect("the window rolled");
    }

    #[test]
    fn relayed_bytes_are_bounded_per_account() {
        let inst = configured(&[GifProvider::Klipy]);
        let actor = UserId::new();
        let first = inst.authorize_gif_tunnel(actor, "api.klipy.com", 443, 0).unwrap();
        assert_eq!(first.max_bytes, MAX_GIF_TUNNEL_BYTES, "a fresh account gets a whole tunnel");

        // Leave less than one tunnel's worth: the next grant must shrink to what is left,
        // or one last tunnel could carry the account far past its window.
        let spent = MAX_GIF_RELAY_BYTES_PER_WINDOW - 1_000;
        inst.record_gif_relay_bytes(actor, spent, 0);
        let squeezed = inst.authorize_gif_tunnel(actor, "api.klipy.com", 443, 1).unwrap();
        assert_eq!(squeezed.max_bytes, 1_000);

        inst.record_gif_relay_bytes(actor, 1_000, 1);
        assert!(matches!(
            inst.authorize_gif_tunnel(actor, "api.klipy.com", 443, 2),
            Err(ServerError::RateLimited)
        ));
        assert!(inst.authorize_gif_tunnel(actor, "api.klipy.com", 443, CLAIM_WINDOW_MS).is_ok());
    }

    #[test]
    fn a_provider_name_resolving_inward_is_not_dialled() {
        let inward = [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.100.100.100",
            "0.0.0.0",
            "0.1.2.3",
            "255.255.255.255",
            "224.0.0.1",
            "::1",
            "::",
            "::127.0.0.1",
            "fe80::1",
            "fd00::1",
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
            "64:ff9b::a9fe:a9fe",
        ];
        for ip in inward {
            assert!(!gif_upstream_permitted(ip.parse().unwrap()), "{ip} must not be dialled");
        }
        for ip in ["151.101.1.1", "34.120.0.1", "2a04:4e42::1"] {
            assert!(gif_upstream_permitted(ip.parse().unwrap()), "{ip} is a public address");
        }
    }

    #[test]
    fn an_api_key_that_would_rewrite_the_request_url_is_refused() {
        for bad in
            ["", "   ", "key/../x", "key?x=1", "key#frag", "key&q=x", "key with space", "kéy"]
        {
            assert!(
                GifRelayConfig::new().with_provider(GifProvider::Klipy, bad).is_err(),
                "{bad:?} must not be accepted as a key"
            );
        }
        assert!(GifRelayConfig::new().with_provider(GifProvider::Giphy, "AbC123_-xyz").is_ok());
    }

    #[test]
    fn the_api_keys_never_appear_in_debug_output() {
        let config = GifRelayConfig::new()
            .with_provider(GifProvider::Klipy, "very-secret-key")
            .unwrap()
            .with_provider(GifProvider::Giphy, "another-secret")
            .unwrap();
        let shown = format!("{config:?}");
        assert!(!shown.contains("very-secret-key") && !shown.contains("another-secret"), "{shown}");
        assert!(shown.contains("<redacted>"));
    }
}
