//! Instagram links, and the one rung of the fallback chain that can ship today.
//!
//! ## Why this is the proxy rung and not the authenticated one
//!
//! [`docs/05-embeds.md`](../../../../docs/05-embeds.md) sequences Instagram support in five
//! steps and puts the *authenticated* unfurl — link your account, drive a WebView, extract
//! the media — at steps 1–4. Every one of those is blocked today:
//!
//! - A session cookie is a credential for someone's real social account, and client state is
//!   still written unencrypted. That waits on platform keystores.
//! - Extraction needs a renderer, and the only defensible one is the OS WebView behind an
//!   FFI seam. There is no native client yet, and a terminal has no WebView.
//!
//! Step 5, the proxy rung, is the part the doc says "can ship **before** any of the others
//! and is the cheapest real improvement available today". This is that.
//!
//! ## What a proxy actually buys, stated plainly
//!
//! Instagram serves a login wall to anonymous fetches, so the ordinary OpenGraph path
//! returns nothing worth showing. A proxy host re-serves the post with real OpenGraph tags,
//! which is why people use them.
//!
//! **It does not make anything private. It moves the leak.** Instagram stops seeing the
//! sender's fetch and a third party starts. `CardSource::Proxy` carries the caveat a client
//! must display, and this is opt-in per [`ProxyPolicy`] precisely so nobody's link is handed
//! to a stranger by default.
//!
//! The **recipient** is protected either way — the card travels inside the encrypted body
//! and their device fetches nothing. That property is what the whole embed design exists
//! for, and the proxy rung does not weaken it.
//!
//! ## Why a list rather than a name
//!
//! These proxies are volunteer-run and they rotate: `kkinstagram`, `ddinstagram`,
//! `instagramez`, `fxig`, `d.vx` are all in circulation and none is dependable. §2 of the
//! design doc says to assume adapter breakage and degrade gracefully, so the host is
//! configuration with an ordered fallback, not a constant compiled into a security product.

use serde::{Deserialize, Serialize};

/// What kind of Instagram link this is.
///
/// Kept as an enum rather than a string because the path segment is copied into a URL that
/// gets sent to a third party — a free-form segment there is how a rewriting bug becomes an
/// open redirect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkKind {
    /// `/p/<shortcode>` — a post, possibly a carousel.
    Post,
    /// `/reel/<shortcode>` — short video.
    Reel,
    /// `/tv/<shortcode>` — the old IGTV path, still in circulation.
    Tv,
}

impl LinkKind {
    const fn segment(self) -> &'static str {
        match self {
            LinkKind::Post => "p",
            LinkKind::Reel => "reel",
            LinkKind::Tv => "tv",
        }
    }
}

/// A recognised Instagram post link, reduced to the two things worth keeping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstagramLink {
    pub kind: LinkKind,
    /// The post's shortcode. Validated to the alphabet Instagram actually uses, so nothing
    /// from the original URL can smuggle a path or a query into the rewritten one.
    pub shortcode: String,
}

/// Hosts that serve Instagram itself.
///
/// Matched exactly, never by suffix. `instagram.com.evil.test` and `notinstagram.com` both
/// end or start with the right letters and belong to somebody else — treating either as
/// Instagram would hand a stranger's URL to a proxy, which is the precise leak this module
/// is supposed to be managing.
const INSTAGRAM_HOSTS: [&str; 3] = ["instagram.com", "www.instagram.com", "m.instagram.com"];

/// Longest shortcode worth accepting. Instagram's are 11 characters, occasionally longer for
/// newer ids; this is a sanity bound rather than a claim about their format.
const MAX_SHORTCODE_LEN: usize = 32;

/// Which proxy hosts a client may use, in order of preference.
///
/// **Empty by default, which means disabled.** `docs/05-embeds.md` §"Opt-in per platform"
/// requires that linking one platform never implies another and that a less private path is
/// never taken silently. An empty policy degrades to a bare link, which is the correct
/// behaviour rather than a broken one.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyPolicy {
    hosts: Vec<String>,
}

impl ProxyPolicy {
    /// No proxy. Instagram links stay bare links.
    pub fn disabled() -> Self {
        Self::default()
    }

    /// Enable an ordered list of proxy hosts.
    ///
    /// Order is preference: a caller tries each in turn and stops at the first that answers
    /// with something useful. Hosts that are empty or obviously not hostnames are dropped
    /// rather than rejected, so one bad line in a config file does not disable previews
    /// entirely.
    pub fn with_hosts<I, S>(hosts: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            hosts: hosts
                .into_iter()
                .map(Into::into)
                .map(|h| h.trim().trim_end_matches('/').to_ascii_lowercase())
                .filter(|h| !h.is_empty() && !h.contains('/') && h.contains('.'))
                .collect(),
        }
    }

    pub fn is_enabled(&self) -> bool {
        !self.hosts.is_empty()
    }

    pub fn hosts(&self) -> &[String] {
        &self.hosts
    }
}

/// Recognise an Instagram post link, or decline.
///
/// Declines everything it is not certain about. A false negative costs a preview; a false
/// positive sends somebody else's URL to a third-party host.
pub fn parse(url: &str) -> Option<InstagramLink> {
    let rest = url.strip_prefix("https://").or_else(|| url.strip_prefix("http://"))?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i + 1..]),
        None => (rest, ""),
    };

    // Userinfo is stripped before the host is read: `https://instagram.com@evil.test/p/x`
    // has authority `instagram.com@evil.test` and host `evil.test`, and reading it the
    // other way round is a classic way to be fooled about where a URL points.
    let authority = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let host = authority.split(':').next()?.to_ascii_lowercase();
    if !INSTAGRAM_HOSTS.contains(&host.as_str()) {
        return None;
    }

    // The query is dropped, deliberately and before anything else looks at it. Instagram
    // share links carry `?igsh=...`, a share-tracking token tied to the person who copied
    // the link — forwarding that to a proxy would hand over exactly the identifier the
    // sender did not choose to share.
    let path = path.split(['?', '#']).next().unwrap_or("");
    let mut segments = path.split('/').filter(|s| !s.is_empty());

    let kind = match segments.next()? {
        "p" => LinkKind::Post,
        "reel" | "reels" => LinkKind::Reel,
        "tv" => LinkKind::Tv,
        _ => return None,
    };
    let shortcode = segments.next()?;

    // Anything past the shortcode means a shape this does not understand, and guessing is
    // how a rewrite starts pointing somewhere unintended.
    if segments.next().is_some() {
        return None;
    }
    if !is_shortcode(shortcode) {
        return None;
    }

    Some(InstagramLink { kind, shortcode: shortcode.to_string() })
}

/// Instagram shortcodes are URL-safe base64: letters, digits, `-` and `_`.
///
/// Checked rather than assumed, because this string is interpolated into a URL sent to a
/// third party. A shortcode containing `/`, `?` or `.` could redirect that request.
fn is_shortcode(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_SHORTCODE_LEN
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// The proxy URLs to try for this link, in preference order.
///
/// Built from the *parsed* parts rather than by string-substituting the original URL. A
/// substitution would carry across whatever else the input contained; this can only ever
/// produce `https://<configured host>/<kind>/<validated shortcode>`.
pub fn proxy_urls(link: &InstagramLink, policy: &ProxyPolicy) -> Vec<String> {
    policy
        .hosts
        .iter()
        .map(|host| format!("https://{}/{}/{}", host, link.kind.segment(), link.shortcode))
        .collect()
}

/// The sentence a user must see before a proxy is used on their behalf.
///
/// Returned as text rather than printed so every client shows the same thing — this is a
/// disclosure, and five native clients each writing their own wording is how one of them
/// ends up understating it.
pub const fn disclosure() -> &'static str {
    "Instagram shows nothing to logged-out visitors, so a preview has to come from a \
     third-party proxy. That proxy will see the link — not the message, and not who \
     receives it. Instagram will not see you fetch it. This does not make the link \
     private; it changes who learns about it."
}

#[cfg(test)]
mod tests {
    use super::*;

    fn link(url: &str) -> Option<InstagramLink> {
        parse(url)
    }

    #[test]
    fn a_lookalike_host_is_not_instagram() {
        // The failure that matters. Treating any of these as Instagram would send a URL
        // belonging to somebody else to a third-party proxy — the exact leak this module is
        // supposed to be managing, caused by the code meant to manage it.
        for hostile in [
            "https://instagram.com.evil.test/p/abc123/",
            "https://notinstagram.com/p/abc123/",
            "https://evil.test/instagram.com/p/abc123/",
            "https://instagram.com@evil.test/p/abc123/",
            "https://www.instagram.com.co/p/abc123/",
            "https://fakeinstagram.com/p/abc123/",
        ] {
            assert_eq!(link(hostile), None, "{hostile} must not be treated as Instagram");
        }
    }

    #[test]
    fn the_real_hosts_are_recognised() {
        // Counterfactual: a matcher that refused everything would pass the test above and
        // make the feature dead code.
        for good in [
            "https://instagram.com/p/abc123/",
            "https://www.instagram.com/p/abc123/",
            "https://m.instagram.com/p/abc123/",
        ] {
            assert_eq!(link(good).unwrap().shortcode, "abc123", "{good} should parse");
        }
    }

    #[test]
    fn share_tracking_parameters_never_reach_the_proxy() {
        // An Instagram share link carries `igsh=`, a token tied to whoever copied it.
        // Forwarding that to a third party would hand over an identifier the sender never
        // chose to share — worse than the URL itself.
        let parsed = link("https://www.instagram.com/p/abc123/?igsh=SECRETTOKEN&utm_source=x")
            .expect("a share link is still a post link");
        assert_eq!(parsed.shortcode, "abc123");

        let policy = ProxyPolicy::with_hosts(["kkinstagram.com"]);
        let urls = proxy_urls(&parsed, &policy);
        assert_eq!(urls, vec!["https://kkinstagram.com/p/abc123"]);
        assert!(
            !urls[0].contains("igsh") && !urls[0].contains("SECRETTOKEN"),
            "the tracking token must not survive the rewrite: {}",
            urls[0]
        );
    }

    #[test]
    fn a_shortcode_cannot_redirect_the_rewritten_url() {
        // The shortcode is interpolated into a URL aimed at a third party. If it could
        // contain a slash, a dot or a scheme, the rewrite would point somewhere else
        // entirely while looking like an ordinary preview.
        for hostile in [
            "https://instagram.com/p/..%2f..%2fevil/",
            "https://instagram.com/p/abc.evil.test/",
            "https://instagram.com/p/abc%2f@evil.test/",
            "https://instagram.com/p/abc?x=1/extra/",
        ] {
            let parsed = link(hostile);
            if let Some(parsed) = parsed {
                let urls = proxy_urls(&parsed, &ProxyPolicy::with_hosts(["kkinstagram.com"]));
                assert_eq!(
                    urls[0],
                    format!("https://kkinstagram.com/p/{}", parsed.shortcode),
                    "a parsed shortcode must not change where the URL points"
                );
                assert!(
                    !parsed.shortcode.contains('/') && !parsed.shortcode.contains('.'),
                    "shortcode {:?} would redirect the request",
                    parsed.shortcode
                );
            }
        }
    }

    #[test]
    fn every_link_shape_instagram_uses_is_handled() {
        assert_eq!(link("https://instagram.com/p/abc123/").unwrap().kind, LinkKind::Post);
        assert_eq!(link("https://instagram.com/reel/abc123/").unwrap().kind, LinkKind::Reel);
        assert_eq!(link("https://instagram.com/reels/abc123/").unwrap().kind, LinkKind::Reel);
        assert_eq!(link("https://instagram.com/tv/abc123/").unwrap().kind, LinkKind::Tv);
    }

    #[test]
    fn a_profile_or_the_homepage_is_not_a_post() {
        // Only post-shaped links get a preview. A profile URL sent to a proxy would leak
        // which *person* was being looked at, for no card in return.
        for not_a_post in [
            "https://instagram.com/",
            "https://instagram.com/someone/",
            "https://instagram.com/explore/tags/rust/",
            "https://instagram.com/p/",
        ] {
            assert_eq!(link(not_a_post), None, "{not_a_post} is not a post link");
        }
    }

    #[test]
    fn proxying_is_off_until_someone_turns_it_on() {
        // `05-embeds.md`: opt-in per platform, never globally on. A default-enabled proxy
        // would hand every Instagram link a user pasted to a third party without asking.
        let policy = ProxyPolicy::disabled();
        assert!(!policy.is_enabled());
        let parsed = link("https://instagram.com/p/abc123/").unwrap();
        assert!(
            proxy_urls(&parsed, &policy).is_empty(),
            "with no policy there must be nowhere to send the link"
        );
    }

    #[test]
    fn hosts_are_tried_in_the_order_configured() {
        // These proxies are volunteer-run and rotate; the fallback order is the whole
        // reason this is a list rather than a constant.
        let policy = ProxyPolicy::with_hosts(["kkinstagram.com", "ddinstagram.com"]);
        let parsed = link("https://instagram.com/reel/xyz789/").unwrap();
        assert_eq!(
            proxy_urls(&parsed, &policy),
            vec!["https://kkinstagram.com/reel/xyz789", "https://ddinstagram.com/reel/xyz789"]
        );
    }

    #[test]
    fn a_malformed_configured_host_is_dropped_not_used() {
        // One bad line in a config file must not turn into a request somewhere unintended,
        // and must not disable the working entries either.
        let policy = ProxyPolicy::with_hosts([
            "",
            "   ",
            "not-a-host",
            "https://kkinstagram.com/path",
            "KKInstagram.com/",
            "ddinstagram.com",
        ]);
        assert_eq!(
            policy.hosts(),
            ["kkinstagram.com", "ddinstagram.com"],
            "only well-formed hosts survive, normalised"
        );
    }

    #[test]
    fn no_input_can_aim_the_rewrite_at_another_host() {
        // The invariant, over a table rather than one case at a time: whatever `parse`
        // decides to accept, the URL it produces must point at a configured proxy and
        // nowhere else. A shortcode that smuggled `@` or `/` past validation would turn a
        // preview fetch into a request to somebody else's server.
        //
        // Found by probing rather than reasoning — the probe threw these at it and printed
        // where each one ended up.
        let policy = ProxyPolicy::with_hosts(["kkinstagram.com"]);
        for input in [
            "https://instagram.com.evil.test/p/a/",
            "https://instagram.com@evil.test/p/a/",
            "https://instagram.com:80@evil.test/p/a/",
            "https://user:pass@instagram.com/p/abc/",
            "https://INSTAGRAM.COM/p/abc/",
            "https://instagram.com/p/abc%2f%2fevil.test",
            "https://instagram.com/p/a@evil.test",
            "https://instagram.com/p/a:80",
            "https://instagram.com/p/a?next=https://evil.test",
            "https://instagram.com/p/a#@evil.test",
            "https://instagram.com//p/abc/",
            "https://instagram.com/p//abc/",
            "https://instagram.com/p/\\evil.test",
            "javascript:alert(1)//instagram.com/p/abc",
            "//instagram.com/p/abc",
            "https://xn--instagram-hf0c.com/p/abc/",
            "https://instagram.com./p/abc/",
            "https://instagram.com/p/\u{ff41}\u{ff42}\u{ff43}",
        ] {
            let Some(parsed) = parse(input) else { continue };
            let out = &proxy_urls(&parsed, &policy)[0];
            let authority =
                out.strip_prefix("https://").and_then(|r| r.split('/').next()).unwrap_or("");
            assert_eq!(
                authority, "kkinstagram.com",
                "{input} rewrote to {out}, whose authority is not the configured proxy"
            );
        }
    }

    #[test]
    fn the_disclosure_does_not_claim_privacy_it_cannot_deliver() {
        // Non-negotiable #3 applied to a sentence. The proxy moves the leak; a disclosure
        // implying it removes one would be worse than showing nothing.
        let text = disclosure();
        assert!(text.contains("will see the link"), "it must say the proxy sees the link");
        assert!(
            text.contains("does not make the link private"),
            "it must not let a reader conclude this is a privacy feature"
        );
    }
}
