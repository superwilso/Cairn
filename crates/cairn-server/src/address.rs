//! Who is on the other end of a connection, as far as rate limiting is concerned.
//!
//! Registration is the one rule that cannot be keyed to an account, because it is where
//! accounts come from — so it is keyed to an address instead, and this module decides
//! which address. That is harder than reading the socket: behind the reverse proxy the
//! compose file ships, **every** request arrives from Caddy, so the socket address alone
//! would put every user of the instance into one shared budget.
//!
//! The fix everybody reaches for is `X-Forwarded-For`, and trusting it unconditionally is
//! worse than not limiting at all. Anyone can send the header, so a client talking to the
//! server directly could rotate it per request to evade their own limit, or set it to
//! someone else's address to spend that person's budget for them. So the header is read
//! **only** when the connection comes from a proxy the operator has named, and even then
//! only the entries that proxy itself wrote are believed.

use std::net::{IpAddr, Ipv6Addr};

/// The unit a per-address limit is charged to.
///
/// IPv6 is bucketed by `/64`, because a single host is routinely handed a whole `/64` and
/// can pick a fresh address from it for every request. Keying on the full address would
/// let one machine present 2^64 identities, which is the same as no limit.
///
/// `/64` rather than something coarser on purpose: mobile carriers give each subscriber
/// their own `/64` from a shared pool, so a `/56` or `/48` bucket would make strangers on
/// the same network share one budget. The cost is stated in `docs/11-self-hosting.md` —
/// someone holding a `/48` gets 65,536 buckets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AddressBucket(IpAddr);

impl AddressBucket {
    pub fn of(ip: IpAddr) -> Self {
        // A dual-stack listener reports IPv4 clients as `::ffff:a.b.c.d`. Without this, one
        // IPv4 client would be bucketed by the `/64` they share with every other IPv4
        // client on the internet.
        match ip.to_canonical() {
            IpAddr::V4(v4) => Self(IpAddr::V4(v4)),
            IpAddr::V6(v6) => {
                let masked = u128::from(v6) & !((1u128 << 64) - 1);
                Self(IpAddr::V6(Ipv6Addr::from(masked)))
            }
        }
    }
}

impl std::fmt::Display for AddressBucket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            IpAddr::V4(v4) => write!(f, "{v4}"),
            IpAddr::V6(v6) => write!(f, "{v6}/64"),
        }
    }
}

/// One address or network the operator has said is their own reverse proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Cidr {
    network: IpAddr,
    prefix: u8,
}

impl Cidr {
    fn parse(s: &str) -> Option<Self> {
        let (addr, prefix) = match s.split_once('/') {
            Some((a, p)) => (a.parse::<IpAddr>().ok()?, Some(p.parse::<u8>().ok()?)),
            None => (s.parse::<IpAddr>().ok()?, None),
        };
        let addr = addr.to_canonical();
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = prefix.unwrap_or(max);
        if prefix > max {
            return None;
        }
        Some(Self { network: addr, prefix })
    }

    fn contains(&self, ip: IpAddr) -> bool {
        match (self.network, ip.to_canonical()) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = u32::MAX.checked_shl(32 - u32::from(self.prefix)).unwrap_or(0);
                u32::from(net) & mask == u32::from(ip) & mask
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = u128::MAX.checked_shl(128 - u32::from(self.prefix)).unwrap_or(0);
                u128::from(net) & mask == u128::from(ip) & mask
            }
            _ => false,
        }
    }
}

/// The reverse proxies whose `X-Forwarded-For` the instance believes.
///
/// Empty by default, which means the header is ignored entirely and the socket address is
/// used. That is the safe failure: an operator who forgets to configure this behind a
/// proxy gets one shared, over-strict budget — registrations refused too early — rather
/// than a limit any client can walk around.
#[derive(Debug, Clone, Default)]
pub struct TrustedProxies(Vec<Cidr>);

impl TrustedProxies {
    /// Parse a comma-separated list of addresses or CIDR networks, e.g.
    /// `172.30.0.2, 10.0.0.0/8, fd00::/8`.
    pub fn parse(list: &str) -> Result<Self, String> {
        list.split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| Cidr::parse(s).ok_or_else(|| format!("not an address or CIDR network: '{s}'")))
            .collect::<Result<Vec<_>, _>>()
            .map(Self)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn trusts(&self, ip: IpAddr) -> bool {
        self.0.iter().any(|c| c.contains(ip))
    }

    /// The address of the client a request should be charged to.
    ///
    /// `forwarded_for` is every `X-Forwarded-For` value on the request, in order.
    ///
    /// Walks the header **right to left**, because each proxy appends the address it saw,
    /// so the rightmost entry was written by the proxy nearest to us and the leftmost by
    /// whoever sent the request first — which may be the attacker. The first entry that is
    /// not itself a trusted proxy is the client. Anything to its left is attacker-supplied
    /// and never read.
    pub fn client_address<'a>(
        &self,
        peer: IpAddr,
        forwarded_for: impl Iterator<Item = &'a str>,
    ) -> IpAddr {
        if !self.trusts(peer) {
            return peer;
        }
        let entries: Vec<&str> = forwarded_for.flat_map(|v| v.split(',')).map(str::trim).collect();
        let mut nearest = peer;
        for entry in entries.iter().rev() {
            let Some(hop) = parse_hop(entry) else {
                // A trusted proxy wrote something we cannot read. Everything to its left is
                // unreachable without trusting garbage, so stop at the last hop we could
                // verify. Over-strict (that hop is a proxy) rather than spoofable.
                return nearest;
            };
            if !self.trusts(hop) {
                return hop;
            }
            nearest = hop;
        }
        nearest
    }
}

/// One `X-Forwarded-For` entry. Usually a bare address; some proxies include a port.
fn parse_hop(entry: &str) -> Option<IpAddr> {
    entry
        .parse::<IpAddr>()
        .ok()
        .or_else(|| entry.parse::<std::net::SocketAddr>().ok().map(|s| s.ip()))
        .map(|ip| ip.to_canonical())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn proxies(s: &str) -> TrustedProxies {
        TrustedProxies::parse(s).unwrap()
    }

    #[test]
    fn a_direct_client_cannot_choose_its_own_address() {
        // No proxies configured: the header is the client's own claim and is ignored.
        let none = TrustedProxies::default();
        assert_eq!(
            none.client_address(ip("203.0.113.9"), ["198.51.100.1"].into_iter()),
            ip("203.0.113.9")
        );

        // Proxies configured, but this connection is not from one of them.
        let some = proxies("172.30.0.2");
        assert_eq!(
            some.client_address(ip("203.0.113.9"), ["198.51.100.1"].into_iter()),
            ip("203.0.113.9")
        );
    }

    #[test]
    fn behind_a_trusted_proxy_only_the_entry_it_wrote_is_believed() {
        let p = proxies("172.30.0.2");
        // The client prepended a forged address; the proxy appended the real one.
        let header = ["10.9.9.9, 198.51.100.7"];
        assert_eq!(p.client_address(ip("172.30.0.2"), header.into_iter()), ip("198.51.100.7"));
    }

    #[test]
    fn a_chain_of_trusted_proxies_is_walked_to_the_first_stranger() {
        let p = proxies("172.30.0.0/24, 10.0.0.1");
        let header = ["6.6.6.6", "198.51.100.7, 10.0.0.1"];
        assert_eq!(p.client_address(ip("172.30.0.2"), header.into_iter()), ip("198.51.100.7"));
    }

    #[test]
    fn an_unreadable_entry_from_a_trusted_proxy_stops_the_walk() {
        let p = proxies("172.30.0.2");
        assert_eq!(
            p.client_address(ip("172.30.0.2"), ["198.51.100.7, garbage"].into_iter()),
            ip("172.30.0.2")
        );
        // No header at all from the proxy — a health check, say — is charged to the proxy.
        assert_eq!(p.client_address(ip("172.30.0.2"), std::iter::empty()), ip("172.30.0.2"));
    }

    #[test]
    fn entries_with_ports_and_mapped_addresses_are_understood() {
        let p = proxies("172.30.0.2");
        assert_eq!(
            p.client_address(ip("::ffff:172.30.0.2"), ["198.51.100.7:4433"].into_iter()),
            ip("198.51.100.7")
        );
        assert_eq!(
            p.client_address(ip("172.30.0.2"), ["[2001:db8::1]:4433"].into_iter()),
            ip("2001:db8::1")
        );
    }

    #[test]
    fn one_ipv6_host_cannot_mint_fresh_buckets() {
        assert_eq!(
            AddressBucket::of(ip("2001:db8:1:2:aaaa::1")),
            AddressBucket::of(ip("2001:db8:1:2:ffff:ffff:ffff:ffff"))
        );
        assert_ne!(
            AddressBucket::of(ip("2001:db8:1:2::1")),
            AddressBucket::of(ip("2001:db8:1:3::1"))
        );
    }

    #[test]
    fn ipv4_clients_on_a_dual_stack_listener_are_not_lumped_together() {
        assert_eq!(
            AddressBucket::of(ip("::ffff:198.51.100.7")),
            AddressBucket::of(ip("198.51.100.7"))
        );
        assert_ne!(
            AddressBucket::of(ip("::ffff:198.51.100.7")),
            AddressBucket::of(ip("::ffff:198.51.100.8"))
        );
    }

    #[test]
    fn malformed_proxy_configuration_is_refused_rather_than_half_applied() {
        assert!(TrustedProxies::parse("172.30.0.2, caddy").is_err());
        assert!(TrustedProxies::parse("10.0.0.0/33").is_err());
        assert!(TrustedProxies::parse("").unwrap().is_empty());
    }

    #[test]
    fn cidr_edges() {
        let p = proxies("10.0.0.0/8, ::/0");
        assert!(p.trusts(ip("10.255.255.255")));
        assert!(!p.trusts(ip("11.0.0.0")));
        assert!(p.trusts(ip("2001:db8::1")));
        assert!(proxies("0.0.0.0/0").trusts(ip("8.8.8.8")));
    }
}
