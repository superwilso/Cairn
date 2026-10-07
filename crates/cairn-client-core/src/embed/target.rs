//! Where an http(s) URL goes, read the way a browser reads it.
//!
//! Every decision the embed code makes about a link — whether to fetch it, which platform
//! adapter it belongs to, which host a recipient is shown beside its card — has to agree with
//! where a browser would actually take somebody who opened it. A parser that disagrees with
//! the browser is how a card says one host while the link opens another.
//!
//! Each module used to split URLs by hand, and they disagreed with browsers in ways that were
//! found by probing rather than by reading:
//!
//! - **Backslash.** A browser treats `\` as `/` in an http(s) URL, so
//!   `https://evil.test\@instagram.com/p/abc/` goes to `evil.test`. Splitting the authority
//!   on `/` only read it as `instagram.com`, and the Instagram adapter accepted it as a post.
//! - **Numeric hosts.** `http://2130706433/`, `http://127.1/`, `http://0x7f000001/` and
//!   `http://0177.0.0.1/` are all `127.0.0.1` to the system resolver, and none of them parses
//!   as an [`std::net::IpAddr`]. The address policy treated them as public hostnames and the
//!   HTTP client connected to loopback.
//!
//! So there is one parser, and it follows the WHATWG URL rules that decide a destination.

/// The parts of an http(s) URL that decide where it goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Target<'a> {
    pub https: bool,
    /// Percent-decoded and lowercased; an IPv6 literal without its brackets. **No IDNA** — a
    /// non-ASCII host is returned as written, which is why a UI flags it rather than trusting
    /// what it looks like.
    pub host: String,
    /// Whether anything preceded an `@` in the authority. No real link to a public post
    /// needs userinfo, and it is the oldest way to make a URL look like it goes elsewhere.
    pub has_userinfo: bool,
    pub port: Option<&'a str>,
    /// Everything after the authority, starting with its terminator, or empty.
    pub rest: &'a str,
}

/// Split an http(s) URL the way a browser would. `None` for anything else.
///
/// The scheme match is case-sensitive, which refuses `HTTPS://…` rather than misreading it:
/// a false negative costs a preview, never a wrong destination.
pub(crate) fn target(url: &str) -> Option<Target<'_>> {
    let (https, after) = match url.strip_prefix("https://") {
        Some(r) => (true, r),
        None => (false, url.strip_prefix("http://")?),
    };
    // The authority ends at the first of these. `\` is on the list because browsers treat
    // it as `/` for http(s); leaving it off is the backslash bypass in the module docs.
    let end = after.find(['/', '\\', '?', '#']).unwrap_or(after.len());
    let (authority, rest) = after.split_at(end);
    // Userinfo is everything before the *last* `@`.
    let (has_userinfo, hostport) = match authority.rsplit_once('@') {
        Some((_, h)) => (true, h),
        None => (false, authority),
    };
    // An IPv6 literal is bracketed and full of colons, so the port cannot be split off
    // before the brackets are stripped — doing it the other way round turns `[::1]:80` into
    // `[`, which parses as no address at all and would sail through as public.
    let (host, port) = match hostport.strip_prefix('[') {
        Some(inside) => {
            let (v6, after) = inside.split_once(']')?;
            (v6, after.strip_prefix(':'))
        }
        None => match hostport.split_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (hostport, None),
        },
    };
    Some(Target { https, host: percent_decode(host)?.to_lowercase(), has_userinfo, port, rest })
}

/// Percent-decode a host, as a browser does before using it.
///
/// `None` for bytes that do not form UTF-8, which no real host does.
fn percent_decode(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            // `get` is `None` past the end or off a char boundary, so a stray `%` is literal.
            if let Some(b) = s.get(i + 1..i + 3).and_then(|h| u8::from_str_radix(h, 16).ok()) {
                out.push(b);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(out).ok()
}

/// The WHATWG IPv4 parser.
///
/// `None` when the host is a name; `Some(Err)` when it is shaped like a number but is not a
/// valid address (a browser refuses those too). The resolver accepts the same spellings
/// browsers do — one to four parts, each decimal, `0x` hex or leading-zero octal, the last
/// filling the remaining bytes — so this has to as well.
pub(crate) fn whatwg_ipv4(host: &str) -> Option<Result<std::net::Ipv4Addr, ()>> {
    let mut parts: Vec<&str> = host.split('.').collect();
    if parts.len() > 1 && parts.last() == Some(&"") {
        parts.pop();
    }
    fn hex_digits(p: &str) -> Option<&str> {
        p.strip_prefix("0x").or_else(|| p.strip_prefix("0X"))
    }
    let numeric = |p: &str| match hex_digits(p) {
        Some(h) => h.chars().all(|c| c.is_ascii_hexdigit()),
        None => !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()),
    };
    if !numeric(parts.last()?) {
        return None;
    }
    if parts.len() > 4 {
        return Some(Err(()));
    }
    let mut values = Vec::with_capacity(parts.len());
    for p in &parts {
        let parsed = match hex_digits(p) {
            Some("") => Ok(0),
            Some(h) => u64::from_str_radix(h, 16),
            None if p.len() > 1 && p.starts_with('0') => u64::from_str_radix(&p[1..], 8),
            None => p.parse::<u64>(),
        };
        match parsed {
            Ok(v) => values.push(v),
            Err(_) => return Some(Err(())),
        }
    }
    let (last, init) = values.split_last()?;
    let room = 256u64.pow(5 - values.len() as u32);
    if init.iter().any(|&v| v > 255) || *last >= room {
        return Some(Err(()));
    }
    let mut addr = *last;
    for (i, &v) in init.iter().enumerate() {
        addr += v << (8 * (3 - i));
    }
    Some(Ok(std::net::Ipv4Addr::from(addr as u32)))
}

/// The host a link really goes to, for display beside its card.
///
/// Computed from the URL, never from anything the card claims about itself — a card's
/// `site_name` is the sender's text, and this is the one thing on a card they cannot
/// choose independently of where the link leads.
pub fn destination_host(url: &str) -> Option<String> {
    let t = target(url)?;
    (!t.host.is_empty()).then_some(t.host)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_backslash_ends_the_authority_as_it_does_in_a_browser() {
        // Found by probing: splitting on `/` alone read this as `instagram.com`. A browser
        // opens `evil.test`, so that is what every decision here must be about.
        let t = target("https://evil.test\\@instagram.com/p/abc/").unwrap();
        assert_eq!(t.host, "evil.test");
        assert!(!t.has_userinfo, "the `@` is in the path once the authority has ended");
    }

    #[test]
    fn userinfo_is_never_mistaken_for_the_host() {
        let t = target("https://reuters.com@evil.test/story").unwrap();
        assert_eq!(t.host, "evil.test");
        assert!(t.has_userinfo);
        let t = target("https://a@b@evil.test/").unwrap();
        assert_eq!(t.host, "evil.test", "the last `@` is the one that counts");
    }

    #[test]
    fn the_host_is_percent_decoded_and_lowercased_like_a_browser() {
        assert_eq!(destination_host("https://EXAMPLE.com/").as_deref(), Some("example.com"));
        assert_eq!(destination_host("https://evil%2Etest/").as_deref(), Some("evil.test"));
    }

    #[test]
    fn ports_and_ipv6_literals_are_split_correctly() {
        let t = target("http://[::1]:8080/x").unwrap();
        assert_eq!((t.host.as_str(), t.port), ("::1", Some("8080")));
        let t = target("https://example.com:444/").unwrap();
        assert_eq!((t.host.as_str(), t.port), ("example.com", Some("444")));
    }

    #[test]
    fn every_numeric_spelling_of_loopback_is_recognised() {
        // What the resolver accepts, and what the old check did not.
        for host in ["127.0.0.1", "2130706433", "127.1", "0x7f000001", "0177.0.0.1", "0x7f.1"] {
            assert_eq!(
                whatwg_ipv4(host),
                Some(Ok(std::net::Ipv4Addr::LOCALHOST)),
                "{host} is 127.0.0.1"
            );
        }
    }

    #[test]
    fn names_are_names_and_malformed_numbers_are_refused() {
        assert_eq!(whatwg_ipv4("example.com"), None);
        assert_eq!(whatwg_ipv4("1.example"), None, "a name whose last label is not numeric");
        assert_eq!(whatwg_ipv4("1.2.3.4.5"), Some(Err(())));
        assert_eq!(whatwg_ipv4("256.1.1.1"), Some(Err(())));
        assert_eq!(whatwg_ipv4("09.1.1.1"), Some(Err(())), "9 is not an octal digit");
    }

    #[test]
    fn non_http_urls_have_no_destination() {
        for url in ["javascript:alert(1)", "file:///etc/passwd", "HTTPS://example.com/", "//x"] {
            assert_eq!(target(url), None, "{url}");
        }
    }
}
