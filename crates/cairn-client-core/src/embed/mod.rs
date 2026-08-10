//! Link cards, rendered on the sender's device.
//!
//! See `docs/05-embeds.md`. The whole point is where the fetch happens: **the sender's
//! client resolves the URL and puts the finished card inside the encrypted body**. The
//! server never learns the URL, and — this is the part clients get wrong — *the recipient
//! never contacts the platform either*. A client that resolves a received URL to draw its
//! card has moved the IP leak onto someone who never opted in and cannot see it happened.
//!
//! So there is deliberately no function here that takes a received [`Card`] and fetches
//! anything. [`unfurl`] is for links the local user typed.
//!
//! ## A card is a claim, not a fact
//!
//! Everything in a [`Card`] is chosen by the sender. A modified client can put a reputable
//! outlet's name and title over any link at all, and no one can check it: in T1/T2 the
//! server cannot read the message, and in an open-source client stripping a client-side
//! check is an afternoon's work (`docs/05-embeds.md` §3, A12).
//!
//! **This is not fixable**, and it is the price of moving the unfurl off the server. What
//! follows from it is a UI rule, not a crypto one: a card must read as something the sender
//! supplied, the underlying URL stays visible, and **no trust signal may be derived from
//! the card's own contents** — that would be asking the attacker what to believe. See
//! [`Card::claimed_source`], which is named to make misuse awkward.
//!
//! ## No images yet
//!
//! [`Card::image_url`] records where an image *was*, and nothing fetches or re-hosts it.
//! Re-hosting means bytes in the envelope, and `docs/05-embeds.md` requires the server's
//! per-message full-state rewrite to be fixed first. Text cards are a few hundred bytes and
//! do not move that; thumbnails would. Images land with attachments (M6).

pub mod instagram;

use serde::{Deserialize, Serialize};

/// A link preview, as assembled by the sender's device.
///
/// Every field is optional because most of the web supplies most of them most of the time,
/// and a card missing a description is still better than a bare URL. A card with *nothing*
/// but a URL is not worth sending — see [`Card::is_useful`].
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Card {
    /// The URL the card describes. Always present and always shown: it is the only part a
    /// recipient can evaluate for themselves.
    pub url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// The site name the page claimed, e.g. `og:site_name`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub site_name: Option<String>,
    /// Where the preview image was, if the page named one. **Not fetched, not re-hosted.**
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_url: Option<String>,
    /// Which step of the fallback chain produced this.
    ///
    /// Carried so a UI can say a less private path was used rather than silently degrading
    /// (`docs/05-embeds.md`, "Fallback chain").
    #[serde(default)]
    pub source: CardSource,
}

/// How a card was obtained. Ordered most private first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CardSource {
    /// Fetched by the sender with a logged-in session for that platform.
    Authenticated,
    /// Fetched by the sender, no session — OpenGraph or oEmbed.
    #[default]
    Public,
    /// Obtained via a third-party proxy such as `fxtwitter`. **The proxy saw the URL.**
    Proxy,
}

impl CardSource {
    /// Text a UI must show when this is anything but the most private path.
    pub const fn caveat(self) -> Option<&'static str> {
        match self {
            CardSource::Authenticated | CardSource::Public => None,
            CardSource::Proxy => Some("preview fetched via a third-party proxy"),
        }
    }
}

impl Card {
    /// A card carrying nothing beyond its URL, for the bare-link fallback.
    pub fn bare(url: impl Into<String>) -> Self {
        Self { url: url.into(), ..Self::default() }
    }

    /// Whether this card says anything the URL does not.
    ///
    /// A client should send a bare link rather than an empty card: an empty card is chrome
    /// that implies a lookup happened and found something.
    pub fn is_useful(&self) -> bool {
        self.title.is_some() || self.description.is_some()
    }

    /// The source this card *claims* to come from.
    ///
    /// Named `claimed_` on purpose. It is sender-controlled text and must never be rendered
    /// as an attribution, a verification badge, or anything a user could read as the
    /// platform vouching for the content.
    pub fn claimed_source(&self) -> Option<&str> {
        self.site_name.as_deref()
    }

    /// Truncate every field to sane limits.
    ///
    /// Applied to cards **on receipt as well as on send**: the sender controls these
    /// bytes, so a hostile client can put a megabyte of text in a title and either blow up
    /// a recipient's layout or push the message past what the server accepts.
    pub fn clamp(mut self) -> Self {
        fn cut(value: Option<String>, max: usize) -> Option<String> {
            value.map(|mut s| {
                if s.chars().count() > max {
                    s = s.chars().take(max).collect::<String>() + "…";
                }
                s
            })
        }
        self.url = self.url.chars().take(MAX_URL).collect();
        self.title = cut(self.title, MAX_TITLE);
        self.description = cut(self.description, MAX_DESCRIPTION);
        self.site_name = cut(self.site_name, MAX_SITE_NAME);
        self.image_url = cut(self.image_url, MAX_URL);
        self
    }
}

const MAX_URL: usize = 2_048;
const MAX_TITLE: usize = 200;
const MAX_DESCRIPTION: usize = 500;
const MAX_SITE_NAME: usize = 100;

#[derive(Debug, thiserror::Error)]
pub enum UnfurlError {
    #[error("not an http(s) URL")]
    NotHttp,
    #[error("refusing to fetch a private or loopback address: {0}")]
    PrivateAddress(String),
    #[error("fetch failed: {0}")]
    Fetch(String),
    #[error("the page is not html")]
    NotHtml,
}

/// Reject URLs that point somewhere a link preview has no business reaching.
///
/// The sender chose the link, so this is not the server-side SSRF problem — but a pasted
/// link is still attacker-chosen text, and "fetch this for me" pointed at `127.0.0.1` or
/// `192.168.x.x` turns a chat message into a probe of the sender's own network, with the
/// result rendered back into the conversation. Cheap to refuse, so refuse.
///
/// Host-based and therefore **incomplete**: it does not resolve DNS, so a hostname that
/// resolves to a private address still passes, and redirects are followed by the HTTP
/// client without re-checking. Closing those needs a resolver hook, which is recorded in
/// `docs/05-embeds.md` rather than implied away here.
pub fn is_fetchable(url: &str) -> Result<(), UnfurlError> {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .ok_or(UnfurlError::NotHttp)?;

    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let authority = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    // An IPv6 literal is bracketed and full of colons, so the port cannot be split off
    // before the brackets are stripped — doing it the other way round turns `[::1]:80`
    // into `[`, which parses as no address at all and would sail through as public.
    let host = match authority.strip_prefix('[').and_then(|rest| rest.split_once(']')) {
        Some((inside, _port)) => inside.to_ascii_lowercase(),
        None => authority.split(':').next().unwrap_or("").to_ascii_lowercase(),
    };

    if host.is_empty() {
        return Err(UnfurlError::NotHttp);
    }
    if host == "localhost" || host.ends_with(".localhost") || host.ends_with(".internal") {
        return Err(UnfurlError::PrivateAddress(host));
    }
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        let private = match ip {
            std::net::IpAddr::V4(v4) => {
                v4.is_loopback()
                    || v4.is_private()
                    || v4.is_link_local()
                    || v4.is_broadcast()
                    || v4.is_unspecified()
                    // 100.64.0.0/10, carrier-grade NAT and Tailscale's range.
                    || (v4.octets()[0] == 100 && (64..128).contains(&v4.octets()[1]))
            }
            std::net::IpAddr::V6(v6) => {
                v6.is_loopback()
                    || v6.is_unspecified()
                    // fc00::/7 unique-local and fe80::/10 link-local.
                    || (v6.octets()[0] & 0xfe) == 0xfc
                    || (v6.octets()[0] == 0xfe && (v6.octets()[1] & 0xc0) == 0x80)
            }
        };
        if private {
            return Err(UnfurlError::PrivateAddress(host));
        }
    }
    Ok(())
}

/// Pull OpenGraph and `<title>` metadata out of an HTML document.
///
/// Hand-rolled rather than pulling in an HTML parser. This is a security product and every
/// dependency is supply chain; the job is small and the failure mode is benign — a card
/// that comes back empty degrades to a bare link, which is the fallback anyway.
///
/// It reads only `<meta>` and `<title>`, never executes anything, and never follows a
/// reference out of the document (`docs/05-embeds.md`: "never execute remote code to
/// produce a card").
pub fn parse_metadata(html: &str, url: &str) -> Card {
    // Only the head matters, and stopping there bounds the work on a hostile page.
    let head = html.get(..html.find("</head>").unwrap_or(html.len().min(64 * 1024)));
    let head = head.unwrap_or(html);

    let mut card = Card { url: url.to_string(), ..Card::default() };

    for tag in head.split('<').filter(|t| t.len() > 4 && t[..4].eq_ignore_ascii_case("meta")) {
        let Some(content) = attribute(tag, "content") else { continue };
        let key = attribute(tag, "property").or_else(|| attribute(tag, "name")).unwrap_or_default();

        match key.to_ascii_lowercase().as_str() {
            "og:title" | "twitter:title" => card.title.get_or_insert(content),
            "og:description" | "twitter:description" | "description" => {
                card.description.get_or_insert(content)
            }
            "og:site_name" => card.site_name.get_or_insert(content),
            "og:image" | "twitter:image" => card.image_url.get_or_insert(content),
            _ => continue,
        };
    }

    // `<title>` is the last resort, since og:title is what the page chose for sharing.
    if card.title.is_none() {
        if let Some(start) = find_ignore_case(head, "<title") {
            if let Some(open) = head[start..].find('>') {
                let from = start + open + 1;
                if let Some(end) = find_ignore_case(&head[from..], "</title") {
                    let text = decode_entities(head[from..from + end].trim());
                    if !text.is_empty() {
                        card.title = Some(text);
                    }
                }
            }
        }
    }

    if card.site_name.is_none() {
        card.site_name = host_of(url).map(str::to_string);
    }

    card.clamp()
}

fn find_ignore_case(haystack: &str, needle: &str) -> Option<usize> {
    let lower = haystack.to_ascii_lowercase();
    lower.find(needle)
}

/// The value of `name="…"` or `name='…'` in a tag.
fn attribute(tag: &str, name: &str) -> Option<String> {
    let lower = tag.to_ascii_lowercase();
    let mut from = 0;
    while let Some(at) = lower[from..].find(name) {
        let start = from + at;
        let after = start + name.len();
        // Must be a whole attribute name, not a suffix of another one.
        let preceded_ok = start == 0
            || lower.as_bytes()[start - 1].is_ascii_whitespace()
            || lower.as_bytes()[start - 1] == b'"'
            || lower.as_bytes()[start - 1] == b'\'';
        let rest = &tag[after..];
        let trimmed = rest.trim_start();
        if preceded_ok && trimmed.starts_with('=') {
            let value = trimmed[1..].trim_start();
            let quote = value.chars().next()?;
            if quote == '"' || quote == '\'' {
                let end = value[1..].find(quote)?;
                return Some(decode_entities(&value[1..1 + end]));
            }
            let end = value.find(|c: char| c.is_whitespace() || c == '>').unwrap_or(value.len());
            return Some(decode_entities(&value[..end]));
        }
        from = after;
    }
    None
}

/// The handful of entities that actually appear in titles.
fn decode_entities(text: &str) -> String {
    text.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&apos;", "'")
        .replace("&nbsp;", " ")
        .trim()
        .to_string()
}

fn host_of(url: &str) -> Option<&str> {
    let rest = url.strip_prefix("https://").or_else(|| url.strip_prefix("http://"))?;
    let host = rest.split(['/', '?', '#']).next()?;
    let host = host.rsplit_once('@').map_or(host, |(_, h)| h);
    Some(host.split(':').next().unwrap_or(host))
}

/// The first http(s) URL in a message, if any.
pub fn first_url(text: &str) -> Option<&str> {
    text.split_whitespace().find(|word| word.starts_with("http://") || word.starts_with("https://"))
}

#[cfg(feature = "http")]
mod fetch {
    use super::{is_fetchable, parse_metadata, Card, CardSource, UnfurlError};

    /// Bytes of a page to read before giving up.
    ///
    /// Metadata lives in the head, so a page that has not declared itself in 512 KB is not
    /// going to. Bounded because the response is attacker-controlled length.
    const MAX_BODY: u64 = 512 * 1024;

    /// Fetch `url` and build a card from its metadata.
    ///
    /// **Only ever call this for a URL the local user supplied.** Calling it for one that
    /// arrived in a message would contact the platform from the recipient's address, which
    /// is precisely what this design exists to avoid.
    ///
    /// A failure is not an error worth surfacing loudly — it degrades to a bare link, which
    /// is the last step of the fallback chain and always works.
    pub fn unfurl(url: &str) -> Result<Card, UnfurlError> {
        is_fetchable(url)?;
        fetch_and_parse(url)
    }

    /// Unfurl, falling back to a configured proxy for links the site itself will not serve.
    ///
    /// Only Instagram today, and only because Instagram shows a login wall to anonymous
    /// visitors — the ordinary path returns a card with nothing in it. Everything else takes
    /// the direct path unchanged.
    ///
    /// The proxy is tried **only after** the direct fetch has failed to produce anything
    /// useful, so a link that works without one never reaches a third party. Order matters
    /// here in a way it does not for an ordinary fallback: each attempt is a URL disclosed to
    /// somebody.
    ///
    /// A card built this way carries [`CardSource::Proxy`], whose `caveat()` a client must
    /// display. Returning a proxy-built card marked `Public` would be the specific lie
    /// `docs/05-embeds.md` forbids.
    pub fn unfurl_with_proxy(
        url: &str,
        policy: &super::instagram::ProxyPolicy,
    ) -> Result<Card, UnfurlError> {
        let direct = unfurl(url);
        if let Ok(card) = &direct {
            if card.is_useful() {
                return direct;
            }
        }

        // Not an Instagram post, or proxying is off: keep whatever the direct path said,
        // including its error. Falling through to a proxy for arbitrary URLs would send
        // links to a third party that the user never opted into sharing.
        let Some(link) = super::instagram::parse(url) else { return direct };
        if !policy.is_enabled() {
            return direct;
        }

        for candidate in super::instagram::proxy_urls(&link, policy) {
            if is_fetchable(&candidate).is_err() {
                continue;
            }
            if let Ok(mut card) = fetch_and_parse(&candidate) {
                if card.is_useful() {
                    // The card describes the *original* link, not the proxy's URL. A
                    // recipient evaluating where a message points must see where it really
                    // points — the proxy is an implementation detail of how the preview was
                    // obtained, and `source` is where that is disclosed.
                    card.url = url.to_string();
                    card.source = CardSource::Proxy;
                    return Ok(card);
                }
            }
        }
        direct
    }

    /// The transport half, with the address policy already applied.
    ///
    /// Split out so tests can drive the HTTP and parsing path against a loopback server,
    /// which [`is_fetchable`] refuses by design. Private, and the only public entry point
    /// applies the check first — a caller cannot reach this to skip it.
    pub(super) fn fetch_and_parse(url: &str) -> Result<Card, UnfurlError> {
        let agent = ureq::Agent::new_with_config(
            ureq::Agent::config_builder().http_status_as_error(false).build(),
        );
        // A generic desktop user-agent: many sites serve no OpenGraph at all without one.
        // It is also the sender's fingerprint, which is the leak `docs/05-embeds.md` §1
        // says must be opt-in per platform — recorded there, not solved here.
        let mut response = agent
            .get(url)
            .header("user-agent", "Mozilla/5.0 (compatible; Cairn link preview)")
            .header("accept", "text/html,application/xhtml+xml")
            .call()
            .map_err(|e| UnfurlError::Fetch(e.to_string()))?;

        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_ascii_lowercase();
        if !content_type.is_empty() && !content_type.contains("html") {
            return Err(UnfurlError::NotHtml);
        }

        let body = response
            .body_mut()
            .with_config()
            .limit(MAX_BODY)
            .read_to_string()
            .map_err(|e| UnfurlError::Fetch(e.to_string()))?;

        let mut card = parse_metadata(&body, url);
        card.source = CardSource::Public;
        Ok(card)
    }
}

#[cfg(feature = "http")]
pub use fetch::{unfurl, unfurl_with_proxy};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opengraph_metadata_becomes_a_card() {
        let html = r#"<html><head>
            <meta property="og:title" content="A headline &amp; a half">
            <meta property="og:description" content="What the page says about itself.">
            <meta property="og:site_name" content="Example News">
            <meta property="og:image" content="https://example.com/img.png">
            </head><body>ignored</body></html>"#;
        let card = parse_metadata(html, "https://example.com/story");

        assert_eq!(card.title.as_deref(), Some("A headline & a half"));
        assert_eq!(card.description.as_deref(), Some("What the page says about itself."));
        assert_eq!(card.claimed_source(), Some("Example News"));
        assert_eq!(card.image_url.as_deref(), Some("https://example.com/img.png"));
        assert!(card.is_useful());
    }

    #[test]
    fn a_title_tag_is_used_when_opengraph_is_absent() {
        let html = "<html><head><title>  Plain old title  </title></head></html>";
        let card = parse_metadata(html, "https://example.com/");
        assert_eq!(card.title.as_deref(), Some("Plain old title"));
        // The host stands in for a site name the page never gave.
        assert_eq!(card.claimed_source(), Some("example.com"));
    }

    #[test]
    fn a_page_with_no_metadata_produces_nothing_worth_sending() {
        let card = parse_metadata("<html><head></head><body>hi</body></html>", "https://x.test/");
        assert!(!card.is_useful(), "an empty card implies a lookup that found something");
    }

    #[test]
    fn a_hostile_title_cannot_blow_up_the_message() {
        // Card fields are sender-controlled, and this runs on receipt too.
        let huge = "x".repeat(100_000);
        let html = format!("<html><head><title>{huge}</title></head></html>");
        let card = parse_metadata(&html, "https://example.com/");
        assert!(card.title.as_ref().unwrap().chars().count() <= MAX_TITLE + 1);
    }

    #[test]
    fn a_card_never_becomes_a_reason_to_trust_it() {
        // There is no API returning "verified" or "official" — the only accessor for the
        // claimed origin is named to make its status obvious at the call site.
        let card = Card {
            url: "https://evil.test/x".into(),
            title: Some("Reuters".into()),
            site_name: Some("Reuters".into()),
            ..Card::default()
        };
        assert_eq!(card.claimed_source(), Some("Reuters"));
        assert_eq!(card.url, "https://evil.test/x", "the real URL stays inspectable");
    }

    #[test]
    fn a_proxy_is_never_reached_for_a_link_that_is_not_instagram() {
        // The rule that keeps this feature honest: a configured proxy exists for Instagram,
        // not as a general fallback. Falling through for arbitrary URLs would send links to
        // a third party that the user opted into sharing with nobody.
        //
        // Asserted at the level that decides it — `instagram::parse` returning `None` is
        // what makes `unfurl_with_proxy` return the direct result untouched.
        let policy = instagram::ProxyPolicy::with_hosts(["kkinstagram.com"]);
        assert!(policy.is_enabled());
        for other in [
            "https://example.com/article",
            "https://twitter.com/someone/status/1",
            "https://instagram.com/someone/",
        ] {
            assert!(
                instagram::parse(other).is_none(),
                "{other} must not route through the Instagram proxy"
            );
        }
    }

    #[test]
    fn a_proxied_card_describes_the_original_link_and_says_it_was_proxied() {
        // Two properties a recipient depends on. The URL must be the one the sender actually
        // shared — a card pointing at `kkinstagram.com` would misrepresent where the message
        // leads — and the source must say a third party was involved, since `caveat()` is
        // what a client displays.
        let mut card = parse_metadata(
            r#"<html><head><meta property="og:title" content="a post"></head></html>"#,
            "https://kkinstagram.com/p/abc123",
        );
        card.url = "https://instagram.com/p/abc123/".to_string();
        card.source = CardSource::Proxy;

        assert_eq!(card.url, "https://instagram.com/p/abc123/");
        assert!(!card.url.contains("kkinstagram"), "the proxy must not appear as the link");
        assert!(card.source.caveat().is_some(), "a proxied card must carry its caveat");
    }

    #[test]
    fn loopback_and_private_addresses_are_refused() {
        // "Unfurl this for me" pointed at a LAN address turns a message into a probe of
        // the sender's own network.
        for url in [
            "http://127.0.0.1/admin",
            "http://localhost:8080/",
            "http://192.168.1.1/",
            "http://10.0.0.5/",
            "http://172.16.4.2/",
            "http://169.254.169.254/latest/meta-data/",
            "http://[::1]:80/",
            "http://100.64.1.1/",
            "http://box.internal/",
            "http://user@127.0.0.1/",
        ] {
            assert!(
                matches!(is_fetchable(url), Err(UnfurlError::PrivateAddress(_))),
                "must refuse {url}"
            );
        }
    }

    #[test]
    fn ordinary_public_urls_are_allowed() {
        for url in ["https://example.com/a", "http://93.184.216.34/", "https://sub.example.co.uk/"]
        {
            assert!(is_fetchable(url).is_ok(), "must allow {url}");
        }
    }

    #[test]
    fn non_http_schemes_are_refused() {
        for url in ["file:///etc/passwd", "ftp://example.com/", "javascript:alert(1)", "://x"] {
            assert!(matches!(is_fetchable(url), Err(UnfurlError::NotHttp)), "must refuse {url}");
        }
    }

    /// A one-shot HTTP server returning `body` with `content_type`.
    ///
    /// Computes its own `Content-Length`: a hand-written one that undercounts silently
    /// truncates the response, and the resulting card looks merely incomplete rather than
    /// broken — which is exactly how the first version of this test lied.
    #[cfg(feature = "http")]
    fn serve_once(content_type: &str, body: &str) -> String {
        use std::io::{Read, Write};
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf);
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            }
        });
        format!("http://{addr}/page")
    }

    #[test]
    #[cfg(feature = "http")]
    fn a_real_response_becomes_a_card() {
        // Exercises the transport, the content-type check and the parse together. Uses the
        // policy-free seam because `is_fetchable` refuses loopback, which is the point of it.
        let url = serve_once(
            "text/html; charset=utf-8",
            r#"<html><head><meta property="og:title" content="Fetched for real">
               <meta property="og:site_name" content="Test Site"></head></html>"#,
        );
        let card = super::fetch::fetch_and_parse(&url).expect("a card");
        assert_eq!(card.title.as_deref(), Some("Fetched for real"));
        assert_eq!(card.claimed_source(), Some("Test Site"));
        assert_eq!(card.source, CardSource::Public);
    }

    #[test]
    #[cfg(feature = "http")]
    fn a_non_html_response_is_refused_before_it_is_parsed() {
        // Without this a link to a 4 GB video would be read into memory looking for a title.
        let url = serve_once("image/png", "abcd");
        assert!(matches!(super::fetch::fetch_and_parse(&url), Err(UnfurlError::NotHtml)));
    }

    #[test]
    #[cfg(feature = "http")]
    fn the_public_entry_point_still_enforces_the_address_policy() {
        // The seam above must not be a way around the check. `unfurl` is the only public
        // door, and it refuses loopback even though a server is listening there.
        let url = serve_once("text/html", "<html></html>");
        assert!(matches!(unfurl(&url), Err(UnfurlError::PrivateAddress(_))));
    }

    #[test]
    fn a_less_private_path_is_recorded_so_a_ui_can_say_so() {
        assert!(CardSource::Public.caveat().is_none());
        assert!(CardSource::Proxy.caveat().is_some(), "a proxy saw the URL; the user must know");
    }

    #[test]
    fn the_first_link_in_a_message_is_found() {
        assert_eq!(
            first_url("look at https://example.com/x it is good"),
            Some("https://example.com/x")
        );
        assert_eq!(first_url("no links here"), None);
    }

    #[test]
    fn attributes_are_matched_whole_not_as_suffixes() {
        // `twitter:title` must not satisfy a search for `title`, or the wrong content wins.
        let html = r#"<head><meta name="twitter:title" content="from twitter"></head>"#;
        let card = parse_metadata(html, "https://example.com/");
        assert_eq!(card.title.as_deref(), Some("from twitter"));
    }

    #[test]
    fn single_quoted_attributes_parse() {
        let html = "<head><meta property='og:title' content='single quoted'></head>";
        assert_eq!(
            parse_metadata(html, "https://example.com/").title.as_deref(),
            Some("single quoted")
        );
    }
}
