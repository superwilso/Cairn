//! GIF search through the instance's relay, and the bytes for sending one.
//!
//! The design is `docs/14-gifs.md`, and it exists because the obvious implementation is a
//! content oracle on an encrypted conversation: a picker that queries the provider directly
//! tells it what this person typed, and a message carrying a provider URL makes every
//! *recipient* fetch from the provider when it renders. So:
//!
//! - **Searching** goes through a tunnel the instance relays ([`tunnel`]), with TLS running
//!   from here to the provider. The provider sees the search and the instance's address;
//!   the instance sees that a search happened and how big the answer was. Neither holds
//!   both halves — but on a small instance the provider can still tell its few users
//!   apart by timing, which `docs/14-gifs.md` §3 says plainly.
//! - **Previews** come through the same tunnels, as bytes. A frontend gets an opaque id
//!   per result and asks for its preview by id: it never sees a provider URL and so can
//!   never be made to fetch one directly.
//! - **Sending** fetches the chosen GIF the same way and hands the bytes to the ordinary
//!   attachment path, which seals them under a fresh key. Recipients download ciphertext
//!   from the instance like any photo and contact no provider at all.
//!
//! Advertising is removed here, below the UI, because non-negotiable #4 is not something a
//! frontend should be trusted to remember: KLIPY marks ads in its results as `type: "ad"`
//! carrying HTML to render, and nothing but `type: "gif"` survives [`parse_klipy`].

mod tunnel;

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rustls::{ClientConfig, RootCertStore};
use serde::{Deserialize, Serialize};

use crate::client::{Client, ClientError, GifProviderGrant};
use crate::transport::HttpTransport;

use tunnel::{Origin, ProviderConn};

/// How many results a search asks for. Fits a picker grid without scrolling far.
pub const RESULTS_PER_SEARCH: usize = 24;

/// The largest GIF this client will fetch to send. Well under the attachment ceiling: a GIF
/// is a reaction, and every byte is relayed through the operator's connection, stored on
/// their disk and downloaded by every recipient.
pub const MAX_GIF_SEND_BYTES: usize = 8 * 1024 * 1024;

/// The largest preview this client will fetch. Previews are the small renditions; anything
/// bigger is the provider sending something other than what was asked for.
pub const MAX_PREVIEW_BYTES: usize = 2 * 1024 * 1024;

/// The largest search response read. A page of 24 results is tens of kilobytes.
const MAX_API_BYTES: usize = 4 * 1024 * 1024;

/// GIPHY refuses longer queries; KLIPY documents no limit, so the same one is used for both.
const MAX_QUERY_CHARS: usize = 50;

/// How long a capability answer is believed before asking the instance again, so an
/// operator adding or removing a key is noticed without restarting the client.
const CAPABILITY_TTL: Duration = Duration::from_secs(10 * 60);

/// Idle connections kept per provider host. Previews are fetched in parallel; four lets a
/// grid fill quickly without opening a tunnel per image.
const POOL_PER_HOST: usize = 4;

/// Results remembered for preview and send. Old ones are forgotten past this.
const MAX_REMEMBERED: usize = 500;

#[derive(Debug, thiserror::Error)]
pub enum GifError {
    #[error("GIF search isn't configured on this instance")]
    NotConfigured,
    #[error("this instance does not offer GIF search from {0}")]
    UnknownProvider(String),
    #[error("that GIF is no longer in the picker; search again")]
    UnknownGif,
    #[error("GIF relay: {0}")]
    Relay(String),
    #[error("too many GIF searches for now; try again later")]
    RateLimited,
    #[error("{provider} answered {status}{hint}")]
    Provider { provider: &'static str, status: u16, hint: &'static str },
    #[error("network: {0}")]
    Io(String),
    #[error("TLS to the GIF provider failed: {0}")]
    Tls(String),
    #[error("the GIF provider sent a malformed {0}")]
    Malformed(&'static str),
    #[error("the GIF provider sent something that is not a GIF or WebP image")]
    NotAnImage,
    #[error("that GIF is too large to send")]
    TooLarge,
    #[error(transparent)]
    Client(#[from] ClientError),
}

/// A provider this instance offers, as a picker shows it.
///
/// The placeholder and attribution are the providers' own requirements, decided here so
/// that every frontend meets them rather than each remembering to: KLIPY requires its
/// search box to read "Search KLIPY", and GIPHY requires "Powered by GIPHY".
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GifProviderView {
    /// `"klipy"` or `"giphy"`; what [`Gifs::search`] takes.
    pub id: String,
    pub name: String,
    pub placeholder: String,
    pub attribution: Option<String>,
}

/// One search result, as a frontend sees it: an id to ask for the preview or to send, and
/// what to lay it out with. **No URL** — see the module note.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GifView {
    pub id: String,
    pub title: String,
    pub width: u32,
    pub height: u32,
}

/// Image bytes and their type, decided by sniffing the bytes rather than believing the
/// provider's label.
#[derive(Debug, Clone)]
pub struct GifMedia {
    pub bytes: Vec<u8>,
    pub mime: &'static str,
}

/// A GIF fetched and ready to hand to the attachment path.
#[derive(Debug, Clone)]
pub struct GifFile {
    pub name: String,
    pub mime: &'static str,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Provider {
    Klipy,
    Giphy,
}

impl Provider {
    fn parse(id: &str) -> Option<Self> {
        match id {
            "klipy" => Some(Self::Klipy),
            "giphy" => Some(Self::Giphy),
            _ => None,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Klipy => "KLIPY",
            Self::Giphy => "GIPHY",
        }
    }

    const fn api_host(self) -> &'static str {
        match self {
            Self::Klipy => "api.klipy.com",
            Self::Giphy => "api.giphy.com",
        }
    }

    fn view(self) -> GifProviderView {
        GifProviderView {
            id: match self {
                Self::Klipy => "klipy",
                Self::Giphy => "giphy",
            }
            .into(),
            name: self.name().into(),
            placeholder: format!("Search {}", self.name()),
            attribution: match self {
                Self::Klipy => None,
                Self::Giphy => Some("Powered by GIPHY".into()),
            },
        }
    }

    /// The request path for a search, or for what is trending when `query` is blank.
    ///
    /// Asks for moderate content filtering from both: a picker in a messenger is used in
    /// rooms with people who did not choose what turns up in it. No `customer_id`, locale
    /// or device parameters are sent — KLIPY documents them as optional and wants them for
    /// personalisation and ads, which is exactly what this client is not for.
    fn search_path(self, key: &str, query: &str) -> String {
        let q: String = query.trim().chars().take(MAX_QUERY_CHARS).collect();
        let per = RESULTS_PER_SEARCH;
        match (self, q.is_empty()) {
            (Self::Klipy, true) => format!(
                "/api/v1/{key}/gifs/trending?page=1&per_page={per}&content_filter=medium&format_filter=gif,webp"
            ),
            (Self::Klipy, false) => format!(
                "/api/v1/{key}/gifs/search?q={}&page=1&per_page={per}&content_filter=medium&format_filter=gif,webp",
                encode(&q)
            ),
            (Self::Giphy, true) => {
                format!("/v1/gifs/trending?api_key={key}&limit={per}&offset=0&rating=pg-13")
            }
            (Self::Giphy, false) => format!(
                "/v1/gifs/search?api_key={key}&q={}&limit={per}&offset=0&rating=pg-13&lang=en",
                encode(&q)
            ),
        }
    }

    fn hint(self, status: u16) -> &'static str {
        match status {
            401 | 403 => " — the instance's API key may be wrong, revoked, or not yet approved",
            429 => " — the instance's key is over its rate limit",
            _ => "",
        }
    }
}

/// Percent-encode a query value: unreserved characters stay, every other byte is escaped.
fn encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// A rendition at the provider: which host, which path, and what the provider says about it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Rendition {
    host: String,
    path: String,
    width: u32,
    height: u32,
    size: Option<u64>,
}

/// A parsed result, before it is checked against the hosts the instance will relay to.
#[derive(Debug, Clone)]
struct Found {
    title: String,
    preview: Rendition,
    /// Candidates to send, best first. The first within [`MAX_GIF_SEND_BYTES`] is used.
    send: Vec<Rendition>,
}

/// A result this session can preview or send.
#[derive(Debug, Clone)]
struct Remembered {
    provider: Provider,
    found: Found,
}

/// Split a media URL into host and path, or refuse it.
///
/// The URL came from the provider's JSON, which this client treats as untrusted input: it
/// must be `https`, carry no userinfo and no port other than 443, and its host must be one
/// the instance said it relays for that provider. Anything else is dropped, so a hostile or
/// compromised API cannot steer this client's tunnels anywhere the operator did not allow —
/// and could not have anyway, because the instance checks again.
fn rendition_at(url: &str, hosts: &[String]) -> Option<(String, String)> {
    let rest = url.strip_prefix("https://")?;
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(end);
    if authority.contains('@') {
        return None;
    }
    let host = match authority.split_once(':') {
        Some((h, "443")) => h,
        Some(_) => return None,
        None => authority,
    }
    .to_ascii_lowercase();
    if !hosts.iter().any(|h| h.eq_ignore_ascii_case(&host)) {
        return None;
    }
    let tail = tail.split('#').next().unwrap_or("");
    if tail.bytes().any(|b| b <= b' ' || b == 0x7f) {
        return None;
    }
    let path = if tail.starts_with('/') { tail.to_string() } else { format!("/{tail}") };
    Some((host, path))
}

fn as_u64(v: &serde_json::Value) -> Option<u64> {
    v.as_u64().or_else(|| v.as_str().and_then(|s| s.trim().parse().ok()))
}

fn dims(v: &serde_json::Value, w: &str, h: &str) -> (u32, u32) {
    let get = |k: &str| v.get(k).and_then(as_u64).unwrap_or(0).min(4096) as u32;
    (get(w), get(h))
}

fn klipy_rendition(
    file: &serde_json::Value,
    size: &str,
    format: &str,
    hosts: &[String],
) -> Option<Rendition> {
    let r = file.get(size)?.get(format)?;
    let (host, path) = rendition_at(r.get("url")?.as_str()?, hosts)?;
    let (width, height) = dims(r, "width", "height");
    Some(Rendition { host, path, width, height, size: r.get("size").and_then(as_u64) })
}

/// KLIPY's search and trending responses. Ads are dropped here; see the module note.
fn parse_klipy(body: &[u8], hosts: &[String]) -> Result<Vec<Found>, GifError> {
    let v: serde_json::Value =
        serde_json::from_slice(body).map_err(|_| GifError::Malformed("KLIPY response"))?;
    if v.get("result").and_then(|r| r.as_bool()) == Some(false) {
        return Err(GifError::Malformed("KLIPY response (result: false)"));
    }
    let items = v
        .get("data")
        .and_then(|d| d.get("data"))
        .and_then(|d| d.as_array())
        .ok_or(GifError::Malformed("KLIPY response"))?;
    let mut out = Vec::new();
    for item in items {
        // Only what is positively a GIF. An ad is `type: "ad"`; a type this client has
        // never heard of is treated the same way rather than given the benefit of the doubt.
        if item.get("type").and_then(|t| t.as_str()) != Some("gif") {
            continue;
        }
        let Some(file) = item.get("file") else { continue };
        let pick = |order: &[(&str, &str)]| -> Vec<Rendition> {
            order.iter().filter_map(|(s, f)| klipy_rendition(file, s, f, hosts)).collect()
        };
        let preview = pick(&[("sm", "webp"), ("sm", "gif"), ("xs", "webp"), ("xs", "gif")]);
        let send = pick(&[("md", "webp"), ("md", "gif"), ("sm", "webp"), ("sm", "gif")]);
        let Some(preview) = preview.into_iter().next() else { continue };
        if send.is_empty() {
            continue;
        }
        let title = item.get("title").and_then(|t| t.as_str()).unwrap_or("").to_string();
        out.push(Found { title, preview, send });
    }
    Ok(out)
}

fn giphy_rendition(
    images: &serde_json::Value,
    name: &str,
    webp: bool,
    hosts: &[String],
) -> Option<Rendition> {
    let r = images.get(name)?;
    let (url_key, size_key) = if webp { ("webp", "webp_size") } else { ("url", "size") };
    let (host, path) = rendition_at(r.get(url_key)?.as_str()?, hosts)?;
    let (width, height) = dims(r, "width", "height");
    Some(Rendition { host, path, width, height, size: r.get(size_key).and_then(as_u64) })
}

/// GIPHY's search and trending responses.
fn parse_giphy(body: &[u8], hosts: &[String]) -> Result<Vec<Found>, GifError> {
    let v: serde_json::Value =
        serde_json::from_slice(body).map_err(|_| GifError::Malformed("GIPHY response"))?;
    let items =
        v.get("data").and_then(|d| d.as_array()).ok_or(GifError::Malformed("GIPHY response"))?;
    let mut out = Vec::new();
    for item in items {
        // GIPHY's GIF endpoints return `type: "gif"`; anything else is not what was asked.
        if item.get("type").and_then(|t| t.as_str()).is_some_and(|t| t != "gif") {
            continue;
        }
        let Some(images) = item.get("images") else { continue };
        let pick = |order: &[(&str, bool)]| -> Vec<Rendition> {
            order.iter().filter_map(|(n, w)| giphy_rendition(images, n, *w, hosts)).collect()
        };
        let preview = pick(&[
            ("fixed_width_small", true),
            ("fixed_width_small", false),
            ("fixed_width", true),
            ("fixed_width", false),
        ]);
        let send = pick(&[
            ("original", true),
            ("downsized", false),
            ("fixed_width", true),
            ("fixed_width", false),
        ]);
        let Some(preview) = preview.into_iter().next() else { continue };
        if send.is_empty() {
            continue;
        }
        let title = item.get("title").and_then(|t| t.as_str()).unwrap_or("").to_string();
        out.push(Found { title, preview, send });
    }
    Ok(out)
}

/// What the bytes are, by their own magic numbers. A label from the provider is not
/// believed: these bytes become an attachment whose type decides how recipients render it.
pub fn sniff(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        Some("image/gif")
    } else if bytes.len() >= 12 && &bytes[..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
        Some("image/webp")
    } else {
        None
    }
}

/// A filename for a sent GIF, from its title. Recipients sanitise it again on save; this
/// keeps it readable.
fn file_name(title: &str, mime: &str) -> String {
    let stem: String = title
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == ' ' || *c == '-')
        .take(60)
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    let stem = if stem.is_empty() { "GIF".to_string() } else { stem };
    let ext = if mime == "image/webp" { "webp" } else { "gif" };
    format!("{stem}.{ext}")
}

/// GIF search for one signed-in device.
///
/// Shared (`Arc`) and internally locked, so a frontend can run searches and preview fetches
/// in parallel without holding the session lock that MLS state needs.
pub struct Gifs {
    client: Client<HttpTransport>,
    origin: Origin,
    instance_tls: Arc<ClientConfig>,
    provider_tls: Mutex<Arc<ClientConfig>>,
    capability: Mutex<Option<(Instant, Vec<GifProviderGrant>)>>,
    remembered: Mutex<HashMap<String, Remembered>>,
    next_id: AtomicU64,
    idle: Mutex<HashMap<String, Vec<ProviderConn>>>,
}

impl std::fmt::Debug for Gifs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Gifs")
    }
}

impl Gifs {
    pub fn new(client: Client<HttpTransport>) -> Result<Self, GifError> {
        let origin = Origin::parse(client.transport().base())?;
        let roots = tunnel::web_roots();
        Ok(Self {
            client,
            origin,
            instance_tls: tunnel::tls_config(roots.clone())?,
            provider_tls: Mutex::new(tunnel::tls_config(roots)?),
            capability: Mutex::new(None),
            remembered: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(1),
            idle: Mutex::new(HashMap::new()),
        })
    }

    /// Verify providers against these roots instead of the web PKI. **For tests**, which run
    /// a stand-in provider with its own certificate authority; nothing in a release build
    /// calls it.
    #[doc(hidden)]
    pub fn trust_provider_roots_for_tests(&self, ders: &[Vec<u8>]) -> Result<(), GifError> {
        let mut roots = RootCertStore::empty();
        for der in ders {
            roots
                .add(rustls::pki_types::CertificateDer::from(der.clone()))
                .map_err(|e| GifError::Tls(e.to_string()))?;
        }
        *self.provider_tls.lock().expect("gif tls lock") = tunnel::tls_config(roots)?;
        self.idle.lock().expect("gif pool lock").clear();
        Ok(())
    }

    fn grants(&self) -> Result<Vec<GifProviderGrant>, GifError> {
        let mut cached = self.capability.lock().expect("gif capability lock");
        if let Some((at, grants)) = cached.as_ref() {
            if at.elapsed() < CAPABILITY_TTL {
                return Ok(grants.clone());
            }
        }
        let grants = self.client.gif_capability()?;
        *cached = Some((Instant::now(), grants.clone()));
        Ok(grants)
    }

    /// The providers this instance relays, in the order it listed them. Empty means GIF
    /// search is not configured here, and a picker should say exactly that.
    pub fn providers(&self) -> Result<Vec<GifProviderView>, GifError> {
        Ok(self
            .grants()?
            .iter()
            .filter_map(|g| Provider::parse(&g.provider))
            .map(Provider::view)
            .collect())
    }

    fn grant(&self, provider: Provider) -> Result<GifProviderGrant, GifError> {
        let grants = self.grants()?;
        if grants.is_empty() {
            return Err(GifError::NotConfigured);
        }
        grants
            .into_iter()
            .find(|g| Provider::parse(&g.provider) == Some(provider))
            .ok_or_else(|| GifError::UnknownProvider(provider.name().into()))
    }

    /// Search `provider` for `query`, or list what is trending when the query is blank.
    pub fn search(&self, provider: &str, query: &str) -> Result<Vec<GifView>, GifError> {
        let p =
            Provider::parse(provider).ok_or_else(|| GifError::UnknownProvider(provider.into()))?;
        let grant = self.grant(p)?;
        if !grant.hosts.iter().any(|h| h == p.api_host()) {
            return Err(GifError::Relay(
                "the instance does not relay to the provider's API".into(),
            ));
        }
        let reply = self.get(p.api_host(), &p.search_path(&grant.api_key, query), MAX_API_BYTES)?;
        if reply.status != 200 {
            return Err(GifError::Provider {
                provider: p.name(),
                status: reply.status,
                hint: p.hint(reply.status),
            });
        }
        let found = match p {
            Provider::Klipy => parse_klipy(&reply.body, &grant.hosts)?,
            Provider::Giphy => parse_giphy(&reply.body, &grant.hosts)?,
        };

        let mut remembered = self.remembered.lock().expect("gif results lock");
        if remembered.len() + found.len() > MAX_REMEMBERED {
            remembered.clear();
        }
        Ok(found
            .into_iter()
            .map(|f| {
                let id = format!("gif-{}", self.next_id.fetch_add(1, Ordering::Relaxed));
                let view = GifView {
                    id: id.clone(),
                    title: f.title.clone(),
                    width: f.preview.width,
                    height: f.preview.height,
                };
                remembered.insert(id, Remembered { provider: p, found: f });
                view
            })
            .collect())
    }

    fn lookup(&self, id: &str) -> Result<Remembered, GifError> {
        self.remembered
            .lock()
            .expect("gif results lock")
            .get(id)
            .cloned()
            .ok_or(GifError::UnknownGif)
    }

    fn fetch(&self, provider: Provider, r: &Rendition, limit: usize) -> Result<GifMedia, GifError> {
        let reply = self.get(&r.host, &r.path, limit)?;
        if reply.status != 200 {
            return Err(GifError::Provider {
                provider: provider.name(),
                status: reply.status,
                hint: "",
            });
        }
        let mime = sniff(&reply.body).ok_or(GifError::NotAnImage)?;
        Ok(GifMedia { bytes: reply.body, mime })
    }

    /// The preview for a result from a search this session ran.
    pub fn preview(&self, id: &str) -> Result<GifMedia, GifError> {
        let r = self.lookup(id)?;
        self.fetch(r.provider, &r.found.preview, MAX_PREVIEW_BYTES)
    }

    /// Fetch a result's bytes to send: the best rendition within [`MAX_GIF_SEND_BYTES`].
    pub fn fetch_for_sending(&self, id: &str) -> Result<GifFile, GifError> {
        let r = self.lookup(id)?;
        let choice = r
            .found
            .send
            .iter()
            .find(|c| c.size.is_none_or(|s| s <= MAX_GIF_SEND_BYTES as u64))
            .ok_or(GifError::TooLarge)?;
        let media = self.fetch(r.provider, choice, MAX_GIF_SEND_BYTES)?;
        Ok(GifFile {
            name: file_name(&r.found.title, media.mime),
            mime: media.mime,
            bytes: media.bytes,
        })
    }

    /// One GET through the relay, on a pooled connection if a fresh one is idle.
    ///
    /// A pooled connection may have been closed by the instance's idle timer without this
    /// side noticing, so a failure on a *reused* one is retried once on a new tunnel. A
    /// failure on a new one is real.
    fn get(&self, host: &str, path: &str, limit: usize) -> Result<tunnel::Reply, GifError> {
        for _ in 0..2 {
            let pooled = {
                let mut idle = self.idle.lock().expect("gif pool lock");
                let list = idle.entry(host.to_string()).or_default();
                list.retain(ProviderConn::fresh);
                list.pop()
            };
            let reused = pooled.is_some();
            let mut conn = match pooled {
                Some(c) => c,
                None => self.connect(host)?,
            };
            match conn.get(path, limit) {
                Ok(reply) => {
                    if conn.fresh() {
                        let mut idle = self.idle.lock().expect("gif pool lock");
                        let list = idle.entry(conn.host().to_string()).or_default();
                        if list.len() < POOL_PER_HOST {
                            list.push(conn);
                        }
                    }
                    return Ok(reply);
                }
                Err(GifError::Io(_) | GifError::Tls(_)) if reused => continue,
                Err(e) => return Err(e),
            }
        }
        Err(GifError::Io("the relay connection kept closing".into()))
    }

    fn connect(&self, host: &str) -> Result<ProviderConn, GifError> {
        let (path, headers) = self.client.gif_tunnel_request(host)?;
        let pipe = tunnel::open(&self.origin, &self.instance_tls, &path, &headers)?;
        let tls = Arc::clone(&self.provider_tls.lock().expect("gif tls lock"));
        ProviderConn::handshake(pipe, host, &tls)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn klipy_hosts() -> Vec<String> {
        ["api.klipy.com", "static.klipy.com"].iter().map(|s| s.to_string()).collect()
    }

    fn klipy_item(kind: &str, slug: &str) -> serde_json::Value {
        let r = |size: &str, fmt: &str| {
            serde_json::json!({ "url": format!("https://static.klipy.com/ii/x/{slug}-{size}.{fmt}"),
                                "width": 220, "height": 120, "size": 1000 })
        };
        serde_json::json!({
            "id": 1, "slug": slug, "title": format!("{slug} title"), "type": kind,
            "file": {
                "md": { "gif": r("md", "gif"), "webp": r("md", "webp") },
                "sm": { "gif": r("sm", "gif"), "webp": r("sm", "webp") },
                "xs": { "gif": r("xs", "gif") }
            }
        })
    }

    #[test]
    fn klipy_advertising_never_reaches_the_picker() {
        let body = serde_json::json!({ "result": true, "data": { "data": [
            klipy_item("gif", "wave"),
            { "type": "ad", "content": "<html><script>track()</script></html>", "width": 300, "height": 250 },
            klipy_item("ad", "sponsored-but-shaped-like-a-gif"),
            klipy_item("sponsored", "unknown-kind"),
            klipy_item("gif", "nod"),
        ]}});
        let found = parse_klipy(body.to_string().as_bytes(), &klipy_hosts()).unwrap();
        let titles: Vec<_> = found.iter().map(|f| f.title.as_str()).collect();
        assert_eq!(titles, ["wave title", "nod title"], "only type gif survives");
        assert_eq!(found[0].preview.path, "/ii/x/wave-sm.webp");
        assert_eq!(found[0].send[0].path, "/ii/x/wave-md.webp");
    }

    #[test]
    fn a_media_url_off_the_relayed_hosts_is_dropped() {
        let hosts = klipy_hosts();
        assert_eq!(
            rendition_at("https://static.klipy.com/a.gif?x=1#frag", &hosts),
            Some(("static.klipy.com".into(), "/a.gif?x=1".into()))
        );
        assert!(rendition_at("https://STATIC.klipy.com:443/a.gif", &hosts).is_some());
        for bad in [
            "http://static.klipy.com/a.gif",
            "https://static.klipy.com:8443/a.gif",
            "https://user@static.klipy.com/a.gif",
            "https://static.klipy.com@127.0.0.1/a.gif",
            "https://127.0.0.1/a.gif",
            "https://evil.example/static.klipy.com/a.gif",
            "https://static.klipy.com.evil.example/a.gif",
            "https://static.klipy.com/a b.gif",
            "https://static.klipy.com/a\r\nHost: x",
            "//static.klipy.com/a.gif",
            "javascript:alert(1)",
        ] {
            assert_eq!(rendition_at(bad, &hosts), None, "{bad} must be dropped");
        }
    }

    #[test]
    fn giphy_results_are_parsed_with_string_numbers() {
        let hosts: Vec<String> = vec!["api.giphy.com".into(), "media1.giphy.com".into()];
        let body = serde_json::json!({ "data": [{
            "type": "gif", "id": "abc", "title": "Cat GIF",
            "images": {
                "fixed_width_small": { "url": "https://media1.giphy.com/media/abc/100w.gif", "width": "100", "height": "80",
                                       "webp": "https://media1.giphy.com/media/abc/100w.webp", "webp_size": "2000" },
                "original": { "url": "https://media1.giphy.com/media/abc/giphy.gif", "width": "480", "height": "384",
                              "webp": "https://media1.giphy.com/media/abc/giphy.webp", "webp_size": "900000" },
                "downsized": { "url": "https://media1.giphy.com/media/abc/giphy-downsized.gif", "size": "1500000" }
            }
        }, { "type": "sticker", "images": {} }]});
        let found = parse_giphy(body.to_string().as_bytes(), &hosts).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].preview.path, "/media/abc/100w.webp");
        assert_eq!((found[0].preview.width, found[0].preview.height), (100, 80));
        assert_eq!(found[0].send[0].size, Some(900_000));
        assert_eq!(found[0].send[1].path, "/media/abc/giphy-downsized.gif");
    }

    #[test]
    fn a_query_cannot_break_out_of_its_parameter() {
        let path = Provider::Giphy.search_path("KEY", "cats&api_key=stolen#x /?é");
        assert!(path.contains("q=cats%26api_key%3Dstolen%23x%20%2F%3F%C3%A9&"), "{path}");
        assert_eq!(path.matches("api_key=").count(), 1);
        let long = "a".repeat(500);
        assert!(Provider::Klipy
            .search_path("K", &long)
            .contains(&format!("q={}&", "a".repeat(50))));
        assert!(Provider::Klipy.search_path("K", "   ").contains("/gifs/trending?"));
    }

    #[test]
    fn nothing_identifying_is_sent_to_a_provider() {
        for p in [Provider::Klipy, Provider::Giphy] {
            for q in ["", "hello"] {
                let path = p.search_path("KEY", q);
                for leak in ["customer_id", "locale", "ad-", "random_id", "user"] {
                    assert!(!path.contains(leak), "{path} must not carry {leak}");
                }
            }
        }
    }

    #[test]
    fn only_gif_and_webp_bytes_are_accepted() {
        assert_eq!(sniff(b"GIF89a...."), Some("image/gif"));
        assert_eq!(sniff(b"RIFF\0\0\0\0WEBPVP8 "), Some("image/webp"));
        assert_eq!(sniff(b"<svg onload=alert(1)>"), None);
        assert_eq!(sniff(b"\x89PNG\r\n\x1a\n"), None);
        assert_eq!(sniff(b""), None);
    }

    #[test]
    fn the_providers_own_attribution_rules_are_carried_to_every_frontend() {
        assert_eq!(Provider::Klipy.view().placeholder, "Search KLIPY");
        assert_eq!(Provider::Giphy.view().attribution.as_deref(), Some("Powered by GIPHY"));
    }

    #[test]
    fn a_sent_gif_gets_a_readable_name() {
        assert_eq!(file_name("Happy  Dance!! <script>", "image/gif"), "Happy Dance script.gif");
        assert_eq!(file_name("", "image/webp"), "GIF.webp");
        assert_eq!(file_name("../../etc/passwd", "image/gif"), "etcpasswd.gif");
    }
}
