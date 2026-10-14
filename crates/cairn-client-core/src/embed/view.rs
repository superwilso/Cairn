//! A card as a frontend shows it — every decision about what is safe to show made here.
//!
//! The UI receives this and renders strings with `textContent`. It does not parse the URL,
//! decide whether a card matches its message, work out what kind of post a link is, or
//! choose a caveat; each of those is a judgement about sender-controlled data, and
//! ADR-008 keeps those below the FFI line.

use serde::{Deserialize, Serialize};

use super::{instagram, oembed, target, Card};

/// What a frontend renders for one card.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CardView {
    /// The link, exactly as it appears in the message.
    pub url: String,
    /// Where the link really goes, read the way a browser reads it. **Computed from the
    /// URL, never from the card** — this is the one thing on a card a sender cannot set
    /// independently of where the link leads, so it is what a UI shows prominently.
    pub host: String,
    /// Set when the host deserves a second look before anyone opens it.
    pub host_warning: Option<String>,
    pub title: Option<String>,
    pub description: Option<String>,
    /// The site the card *claims* to be from. Sender text; never a verification.
    pub claimed_site: Option<String>,
    pub author: Option<String>,
    /// The platform this link belongs to, decided by parsing the URL's host — e.g.
    /// `"Instagram"`. `None` for the general web.
    pub platform: Option<String>,
    /// What kind of post the URL's shape says this is — `"Reel"`, `"Post"`, `"Short"`,
    /// `"Video"` — also from the URL, not the card.
    pub kind: Option<String>,
    /// Whether to lay the card out as a vertical video: a reel, a short, a TikTok.
    pub portrait: bool,
    /// A `data:` URI for the sender's thumbnail. Never a remote URL: rendering a remote
    /// image would have the recipient contact the platform.
    pub thumbnail: Option<String>,
    /// Text a UI must show — today, that a third-party proxy saw the link.
    pub caveat: Option<String>,
}

impl Card {
    /// The card as a frontend should show it beside `body`, or `None` if it should not be
    /// shown at all.
    ///
    /// **Not shown** when the card's URL is not a link in the message. The card's `url`
    /// and the message's text are both the sender's, and they can disagree: a hostile
    /// client can attach a card for `reuters.com` to a message whose link goes to
    /// `evil.test`. The recipient copies or clicks the link in the text, so a card for
    /// anything else is a disguise, and is dropped rather than explained.
    ///
    /// Also not shown when its destination cannot be read, or when it says nothing — unless
    /// the link is a recognised post on a platform, where "Instagram reel · open link" is
    /// worth showing and is derived from the URL alone, not invented.
    pub fn view_for(&self, body: &str) -> Option<CardView> {
        let card = self.clone().clamp();
        if !body.split_whitespace().any(|word| word == card.url) {
            return None;
        }
        let target = target::target(&card.url)?;
        if target.host.is_empty() {
            return None;
        }
        let (platform, kind, portrait_by_url) = classify(&card.url);
        if !card.is_useful() && platform.is_none() {
            return None;
        }

        let host_warning = if target.has_userinfo {
            Some("This link has text before an @ that is not where it goes.".to_string())
        } else if !target.host.is_ascii() || target.host.split('.').any(|l| l.starts_with("xn--")) {
            Some("This address uses non-Latin characters, which can imitate other sites.".into())
        } else {
            None
        };

        let thumbnail = card.thumbnail.as_ref();
        Some(CardView {
            host: target.host,
            host_warning,
            title: card.title.clone(),
            description: card.description.clone(),
            claimed_site: card.site_name.clone(),
            author: card.author.clone(),
            platform: platform.map(str::to_string),
            kind: kind.map(str::to_string),
            portrait: portrait_by_url || thumbnail.is_some_and(|t| t.is_portrait()),
            thumbnail: thumbnail.map(|t| t.data_uri()),
            caveat: card.source.caveat().map(str::to_string),
            url: card.url,
        })
    }
}

/// The URL to hand the system browser when someone clicks a card, or `None` to refuse.
///
/// Only http(s) with a readable host, and none of the characters that make a URL mean
/// different things to different parsers — whitespace, controls, quotes, angle brackets,
/// backslashes. The opener receives exactly the string a recipient saw, so what opens is
/// what the card's host line said would.
pub fn openable(url: &str) -> Option<String> {
    let t = target::target(url)?;
    if t.host.is_empty() || url.len() > 2_048 {
        return None;
    }
    let bad = |c: char| c.is_whitespace() || c.is_control() || "\"'<>\\`^{}|".contains(c);
    (!url.chars().any(bad)).then(|| url.to_string())
}

/// Platform, kind and whether the format is vertical video — all from the URL's shape.
fn classify(url: &str) -> (Option<&'static str>, Option<&'static str>, bool) {
    if let Some(link) = instagram::parse(url) {
        let (kind, portrait) = match link.kind {
            instagram::LinkKind::Reel => ("Reel", true),
            instagram::LinkKind::Post => ("Post", false),
            instagram::LinkKind::Tv => ("Video", true),
        };
        return (Some("Instagram"), Some(kind), portrait);
    }
    if let Some(link) = oembed::parse(url) {
        let shape = link.shape();
        return (Some(link.platform.name()), Some(shape.0), shape.1);
    }
    (None, None, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn card(url: &str) -> Card {
        Card { url: url.into(), title: Some("A title".into()), ..Card::default() }
    }

    #[test]
    fn a_card_for_a_link_the_message_does_not_contain_is_not_shown() {
        // Both halves are the sender's. A card describing reuters.com attached to a message
        // linking evil.test is the disguise this check exists for.
        let disguised = card("https://reuters.com/world");
        assert!(disguised.view_for("read this https://evil.test/world").is_none());
        // Counterfactual: the same card beside its own link is shown.
        assert!(disguised.view_for("read this https://reuters.com/world").is_some());
    }

    #[test]
    fn the_host_shown_is_where_the_link_goes_not_what_the_card_claims() {
        let mut c = card("https://reuters.com@evil.test/world");
        c.site_name = Some("Reuters".into());
        let view = c.view_for("https://reuters.com@evil.test/world").unwrap();
        assert_eq!(view.host, "evil.test");
        assert_eq!(view.claimed_site.as_deref(), Some("Reuters"), "kept, labelled as a claim");
        assert!(view.host_warning.is_some(), "userinfo is called out");

        let c = card("https://evil.test\\@reuters.com/world");
        let view = c.view_for("https://evil.test\\@reuters.com/world").unwrap();
        assert_eq!(view.host, "evil.test", "a browser treats the backslash as a slash");
    }

    #[test]
    fn a_lookalike_host_is_flagged() {
        let c = card("https://xn--rcksack-r2a.example/");
        assert!(c.view_for("https://xn--rcksack-r2a.example/").unwrap().host_warning.is_some());
        let c = card("https://r\u{0435}uters.com/");
        assert!(c.view_for("https://r\u{0435}uters.com/").unwrap().host_warning.is_some());
        let c = card("https://reuters.com/");
        assert!(c.view_for("https://reuters.com/").unwrap().host_warning.is_none());
    }

    #[test]
    fn an_instagram_reel_with_no_metadata_still_gets_a_card_from_its_url_alone() {
        // What a login wall leaves: the URL and nothing else. The
        // card says only what the URL itself says — nothing is invented.
        let url = "https://www.instagram.com/reel/C5nYxQyOZ6V/?igsh=abc";
        let view = Card::bare(url).view_for(url).expect("a reel link is worth a card");
        assert_eq!(view.platform.as_deref(), Some("Instagram"));
        assert_eq!(view.kind.as_deref(), Some("Reel"));
        assert!(view.portrait);
        assert_eq!((view.title, view.description, view.thumbnail), (None, None, None));

        let post = "https://instagram.com/p/C5nYxQyOZ6V/";
        assert_eq!(Card::bare(post).view_for(post).unwrap().kind.as_deref(), Some("Post"));
    }

    #[test]
    fn an_empty_card_for_an_ordinary_link_is_not_shown() {
        // Chrome around nothing implies a lookup found something.
        assert!(Card::bare("https://example.com/").view_for("https://example.com/").is_none());
    }

    #[test]
    fn a_proxied_card_carries_its_caveat() {
        let mut c = card("https://instagram.com/reel/abc123/");
        c.source = super::super::CardSource::Proxy;
        let view = c.view_for("https://instagram.com/reel/abc123/").unwrap();
        assert!(view.caveat.unwrap().contains("third-party proxy"));
    }

    #[test]
    fn only_a_plain_web_link_is_handed_to_the_system_browser() {
        assert!(openable("https://www.instagram.com/reel/C5nYxQyOZ6V/?igsh=x").is_some());
        for refused in [
            "file:///etc/passwd",
            "javascript:alert(1)",
            "ms-settings:",
            "https://evil.test\\@instagram.com/",
            "https://a.test/\" --new-window",
            "https://a.test/ x",
            "https://a.test/\nx",
            "https:///nohost",
            "\"https://a.test/\"",
        ] {
            assert_eq!(openable(refused), None, "must refuse {refused:?}");
        }
    }

    #[test]
    fn a_thumbnail_reaches_the_ui_only_as_a_data_uri() {
        use base64::Engine as _;
        let mut c = card("https://example.com/");
        c.thumbnail = Some(Box::new(super::super::Thumbnail {
            mime: "image/jpeg".into(),
            width: 9,
            height: 16,
            data: base64::engine::general_purpose::STANDARD.encode([0xFF, 0xD8, 0xFF, 0xE0]),
        }));
        let view = c.view_for("https://example.com/").unwrap();
        assert!(view.thumbnail.unwrap().starts_with("data:image/jpeg;base64,"));
        assert!(view.portrait, "a portrait thumbnail lays out as one");
    }
}
