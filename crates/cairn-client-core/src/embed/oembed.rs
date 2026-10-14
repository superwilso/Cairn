//! Platform adapters for YouTube, TikTok, X and Reddit, via each platform's public oEmbed
//! endpoint.
//!
//! ## Why oEmbed for these four
//!
//! The generic OpenGraph path works for most of the web and badly for exactly the links
//! people paste most. X serves an empty shell to anything without JavaScript; Reddit blocks
//! unauthenticated page fetches outright; TikTok's pages are megabytes of script before the
//! head closes. Each of them also publishes an oEmbed endpoint that answers in a few hundred
//! bytes of JSON without a session, which is the fallback chain's second rung
//! (`docs/05-embeds.md`, "Public oEmbed / OpenGraph").
//!
//! **No new party learns anything.** Every endpoint here is run by the platform the link
//! already points at — the same organisation the OpenGraph fetch would have contacted — and
//! it is contacted from the same place, the sender's device. The recipient still fetches
//! nothing: the card travels inside the encrypted body.
//!
//! ## What is used from the response, and what is not
//!
//! oEmbed answers with an `html` field that is the platform's own embed: a `<blockquote>`
//! plus a `<script>`, or an `<iframe>`. **That HTML is never rendered.** Rendering it would
//! run the platform's script on the recipient's device and have it contact the platform —
//! the exact leak this design exists to prevent. Only text is taken: the title, the author,
//! and for X the post's words, stripped of every tag.
//!
//! ## The link's own words are not the platform's
//!
//! Found by trying it: X, TikTok and Reddit all resolve a post **by its numeric or base-36
//! id and ignore the rest of the path**. `x.com/notjack/status/20` comes back as jack's
//! post; a Reddit link written as `/r/IAmA/comments/<id>/` returns whichever subreddit that
//! id actually lives in. So the handle or subreddit in a URL is decoration a sender can
//! choose freely, and the card takes the author from the response instead — and says so
//! when the two disagree, because a link that names one account while leading to another's
//! post is exactly what someone would craft to mislead.
//!
//! ## Strict about hosts, in the style of `instagram.rs`
//!
//! Host matching is exact, never by suffix; any userinfo or explicit port declines; and the
//! URL sent to the endpoint is rebuilt from validated parts rather than copied, so share
//! trackers (`?si=` on YouTube, `?s=` on X) never leave the device and nothing in the input
//! can redirect the request. Probed with hostile inputs; see the tests.

use super::target::target;
use super::Card;

/// Which platform a link belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    YouTube,
    TikTok,
    X,
    Reddit,
}

impl Platform {
    /// The name a card shows as its site.
    ///
    /// Fixed here rather than read from the response's `provider_name`: which platform a link
    /// belongs to was decided by parsing its host, which is a better source than anything the
    /// fetched document says about itself.
    pub const fn name(self) -> &'static str {
        match self {
            Platform::YouTube => "YouTube",
            Platform::TikTok => "TikTok",
            Platform::X => "X",
            Platform::Reddit => "Reddit",
        }
    }
}

/// A recognised post link, reduced to what the platform needs to find it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OembedLink {
    pub platform: Platform,
    /// The id the platform resolves. Validated to that platform's alphabet, because it is
    /// interpolated into a URL.
    id: String,
    /// The handle (X, TikTok) or subreddit (Reddit) the link's path *names*. The platform
    /// ignores it — kept only to point out when it disagrees with the real one.
    named: Option<String>,
    /// A YouTube Short — vertical video, laid out like a reel.
    short: bool,
}

const YOUTUBE_HOSTS: [&str; 4] =
    ["youtube.com", "www.youtube.com", "m.youtube.com", "music.youtube.com"];
const YOUTU_BE: &str = "youtu.be";
const TIKTOK_HOSTS: [&str; 3] = ["tiktok.com", "www.tiktok.com", "m.tiktok.com"];
const X_HOSTS: [&str; 6] =
    ["x.com", "www.x.com", "mobile.x.com", "twitter.com", "www.twitter.com", "mobile.twitter.com"];
const REDDIT_HOSTS: [&str; 5] =
    ["reddit.com", "www.reddit.com", "old.reddit.com", "new.reddit.com", "np.reddit.com"];

/// Recognise a post link on one of the four platforms, or decline.
///
/// Declines everything it is not certain about. A false negative costs nothing — the link
/// takes the generic OpenGraph path — while a false positive would build a card from one
/// platform's answer for a link that leads somewhere else.
pub fn parse(url: &str) -> Option<OembedLink> {
    let t = target(url)?;
    // `http://` is accepted and harmless: the request this produces is always `https://` to
    // a fixed host, rebuilt from the validated id. Userinfo and ports are not — no genuine
    // share link carries either, and both are classic ways to dress up a destination.
    if t.has_userinfo || t.port.is_some() {
        return None;
    }
    // A browser reads `\` as `/`; anything carrying one is not a link a platform minted.
    if t.rest.contains('\\') {
        return None;
    }
    let (path, query) = split_path(t.rest);
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    let host = t.host.as_str();

    if YOUTUBE_HOSTS.contains(&host) {
        let id = match segments.as_slice() {
            ["watch"] => query_param(query, "v")?,
            ["shorts" | "live" | "embed", id] => id,
            _ => return None,
        };
        let short = segments.first() == Some(&"shorts");
        return youtube_id(id).then(|| OembedLink { short, ..link(Platform::YouTube, id, None) });
    }
    if host == YOUTU_BE {
        return match segments.as_slice() {
            [id] if youtube_id(id) => Some(link(Platform::YouTube, id, None)),
            _ => None,
        };
    }
    if TIKTOK_HOSTS.contains(&host) {
        return match segments.as_slice() {
            [handle, "video" | "photo", id] => {
                let handle = handle.strip_prefix('@')?;
                (is_handle(handle, 32, true) && is_digits(id, 25))
                    .then(|| link(Platform::TikTok, id, Some(handle)))
            }
            _ => None,
        };
    }
    if X_HOSTS.contains(&host) {
        return match segments.as_slice() {
            [handle, "status", id] | [handle, "status", id, "photo" | "video", _] => {
                (is_handle(handle, 15, false) && is_digits(id, 20))
                    .then(|| link(Platform::X, id, Some(handle)))
            }
            _ => None,
        };
    }
    if REDDIT_HOSTS.contains(&host) {
        return match segments.as_slice() {
            ["r", sub, "comments", id] | ["r", sub, "comments", id, _] => {
                (is_handle(sub, 21, false) && is_base36(id))
                    .then(|| link(Platform::Reddit, id, Some(sub)))
            }
            _ => None,
        };
    }
    None
}

fn link(platform: Platform, id: &str, named: Option<&str>) -> OembedLink {
    OembedLink { platform, id: id.to_string(), named: named.map(str::to_string), short: false }
}

impl OembedLink {
    /// What kind of post this is, and whether it is vertical video — from the URL's shape.
    pub fn shape(&self) -> (&'static str, bool) {
        match self.platform {
            Platform::YouTube if self.short => ("Short", true),
            Platform::YouTube => ("Video", false),
            Platform::TikTok => ("Video", true),
            Platform::X | Platform::Reddit => ("Post", false),
        }
    }

    /// The post's address, rebuilt from validated parts. Query, fragment and trackers gone.
    pub fn canonical_url(&self) -> String {
        let named = self.named.as_deref().unwrap_or("_");
        match self.platform {
            Platform::YouTube => format!("https://www.youtube.com/watch?v={}", self.id),
            Platform::TikTok => format!("https://www.tiktok.com/@{named}/video/{}", self.id),
            Platform::X => format!("https://x.com/{named}/status/{}", self.id),
            Platform::Reddit => format!("https://www.reddit.com/r/{named}/comments/{}/", self.id),
        }
    }

    /// The oEmbed request for this post.
    ///
    /// The host is a constant per platform, so whatever was pasted, the request goes to that
    /// platform and nowhere else. X's endpoint moved from `publish.twitter.com` to
    /// `publish.x.com` (the old one now answers 301); `dnt=true` asks it not to use the
    /// request for personalisation, which costs nothing to ask.
    pub fn endpoint(&self) -> String {
        let url = encode_component(&self.canonical_url());
        match self.platform {
            Platform::YouTube => format!("https://www.youtube.com/oembed?format=json&url={url}"),
            Platform::TikTok => format!("https://www.tiktok.com/oembed?url={url}"),
            Platform::X => {
                format!("https://publish.x.com/oembed?omit_script=true&dnt=true&url={url}")
            }
            Platform::Reddit => format!("https://www.reddit.com/oembed?url={url}"),
        }
    }
}

/// Build a card from an oEmbed response. `None` when it says nothing worth showing.
///
/// `original` is the URL as it appeared in the message, and is what the card describes —
/// the recipient must see the link the sender actually sent, not the rebuilt one.
pub fn card_from_response(link: &OembedLink, original: &str, json: &str) -> Option<Card> {
    let value: serde_json::Value = serde_json::from_str(json).ok()?;
    let field = |name: &str| {
        value.get(name).and_then(|v| v.as_str()).map(str::trim).filter(|s| !s.is_empty())
    };
    let author = field("author_name");
    let html = field("html").unwrap_or("");

    let (title, description, real) = match link.platform {
        Platform::YouTube => {
            (field("title").map(str::to_string), author.map(|a| format!("Video by {a}")), None)
        }
        Platform::TikTok => {
            let handle = field("author_unique_id")
                .map(str::to_string)
                .or_else(|| field("author_url").and_then(last_segment).map(|h| h.replace('@', "")));
            let by = match (author, &handle) {
                (Some(a), Some(h)) => Some(format!("by {a} (@{h})")),
                (Some(a), None) => Some(format!("by {a}")),
                (None, Some(h)) => Some(format!("by @{h}")),
                (None, None) => None,
            };
            (field("title").map(str::to_string), by, handle)
        }
        Platform::X => {
            let handle = field("author_url").and_then(last_segment);
            let title = match (author, &handle) {
                (Some(a), Some(h)) => Some(format!("{a} (@{h})")),
                (Some(a), None) => Some(a.to_string()),
                _ => None,
            };
            (title, first_paragraph_text(html), handle)
        }
        Platform::Reddit => {
            let sub = reddit_subreddit(html);
            let posted = match (author, &sub) {
                (Some(a), Some(s)) => Some(format!("Posted by u/{a} in r/{s}")),
                (Some(a), None) => Some(format!("Posted by u/{a}")),
                (None, Some(s)) => Some(format!("Posted in r/{s}")),
                (None, None) => None,
            };
            (field("title").map(str::to_string), posted, sub)
        }
    };

    // The link's own path named somebody; the platform says the post is somebody else's.
    let mismatch = match (&link.named, &real) {
        (Some(named), Some(real)) if !named.eq_ignore_ascii_case(real) => {
            Some(match link.platform {
                Platform::Reddit => {
                    format!("The link says r/{named}; the post is in r/{real}.")
                }
                _ => format!("The link says @{named}; the post is by @{real}."),
            })
        }
        _ => None,
    };
    let description = match (description, mismatch) {
        (Some(d), Some(m)) => Some(format!("{d}. {m}")),
        (d, m) => d.or(m),
    };

    let handle = match link.platform {
        Platform::YouTube => author.map(str::to_string),
        Platform::TikTok | Platform::X => real.as_ref().map(|h| format!("@{h}")),
        Platform::Reddit => author.map(|a| format!("u/{a}")),
    };

    let card = Card {
        url: original.to_string(),
        title,
        description,
        site_name: Some(link.platform.name().to_string()),
        // Where the platform's thumbnail is. The sender's client may fetch it to make
        // [`Card::thumbnail`]; a recipient never loads it.
        image_url: field("thumbnail_url").filter(|u| u.starts_with("https://")).map(String::from),
        source: super::CardSource::Public,
        author: handle,
        thumbnail: None,
    }
    .clamp();
    card.is_useful().then_some(card)
}

fn split_path(rest: &str) -> (&str, &str) {
    let rest = rest.split('#').next().unwrap_or("");
    match rest.split_once('?') {
        Some((path, query)) => (path, query),
        None => (rest, ""),
    }
}

fn query_param<'a>(query: &'a str, name: &str) -> Option<&'a str> {
    query.split('&').find_map(|pair| pair.strip_prefix(name)?.strip_prefix('='))
}

fn youtube_id(s: &str) -> bool {
    s.len() == 11 && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

fn is_digits(s: &str, max: usize) -> bool {
    !s.is_empty() && s.len() <= max && s.chars().all(|c| c.is_ascii_digit())
}

fn is_base36(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 12
        && s.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
}

fn is_handle(s: &str, max: usize, dots: bool) -> bool {
    !s.is_empty()
        && s.len() <= max
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || (dots && c == '.'))
}

fn last_segment(url: &str) -> Option<String> {
    let seg = url.trim_end_matches('/').rsplit('/').next()?;
    (!seg.is_empty() && !seg.contains(':')).then(|| seg.to_string())
}

/// Percent-encode everything but RFC 3986's unreserved characters.
fn encode_component(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// The text of the first `<p>` in an embed — X puts the post's words there.
fn first_paragraph_text(html: &str) -> Option<String> {
    let lower = html.to_ascii_lowercase();
    let open = lower.find("<p")?;
    let start = open + lower[open..].find('>')? + 1;
    let end = start + lower[start..].find("</p>")?;
    let text = strip_tags(&html[start..end]);
    (!text.is_empty()).then_some(text)
}

/// The subreddit a Reddit embed's links say the post lives in.
fn reddit_subreddit(html: &str) -> Option<String> {
    let marker = "href=\"https://www.reddit.com/r/";
    let at = html.find(marker)? + marker.len();
    let sub = html[at..].split(['/', '"']).next()?;
    is_handle(sub, 21, false).then(|| sub.to_string())
}

/// Tags removed, `<br>` as a space, entities decoded, whitespace collapsed. Text only — the
/// output is shown with `textContent`, but nothing here relies on that.
fn strip_tags(html: &str) -> String {
    let mut out = String::with_capacity(html.len());
    let mut in_tag = false;
    let mut tag = String::new();
    for c in html.chars() {
        match (in_tag, c) {
            (false, '<') => {
                in_tag = true;
                tag.clear();
            }
            (true, '>') => {
                in_tag = false;
                if tag.to_ascii_lowercase().starts_with("br") {
                    out.push(' ');
                }
            }
            (true, c) => tag.push(c),
            (false, c) => out.push(c),
        }
    }
    let decoded = decode_entities(&out);
    decoded.split_whitespace().collect::<Vec<_>>().join(" ")
}

pub(super) fn decode_entities(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(amp) = rest.find('&') {
        out.push_str(&rest[..amp]);
        let after = &rest[amp + 1..];
        let decoded = after.find(';').filter(|&semi| semi <= 10).and_then(|semi| {
            let name = &after[..semi];
            let ch = match name {
                "amp" => Some('&'),
                "lt" => Some('<'),
                "gt" => Some('>'),
                "quot" => Some('"'),
                "apos" => Some('\''),
                "nbsp" => Some(' '),
                "mdash" => Some('—'),
                "ndash" => Some('–'),
                "hellip" => Some('…'),
                _ => {
                    let num = name.strip_prefix('#')?;
                    let code = match num.strip_prefix(['x', 'X']) {
                        Some(hex) => u32::from_str_radix(hex, 16).ok()?,
                        None => num.parse().ok()?,
                    };
                    char::from_u32(code).filter(|c| !c.is_control())
                }
            }?;
            Some((ch, semi))
        });
        match decoded {
            Some((ch, semi)) => {
                out.push(ch);
                rest = &after[semi + 1..];
            }
            None => {
                out.push('&');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // Trimmed from what each endpoint actually returned on 2026-10-07, fetched from this
    // project's development container. `html` is kept where the card reads it.
    const YOUTUBE: &str = r#"{"title":"Rick Astley - Never Gonna Give You Up (Official Video) (4K Remaster)","author_name":"Rick Astley","author_url":"https://www.youtube.com/@RickAstleyYT","type":"video","provider_name":"YouTube","thumbnail_url":"https://i.ytimg.com/vi/dQw4w9WgXcQ/hqdefault.jpg","html":"<iframe src=\"https://www.youtube.com/embed/dQw4w9WgXcQ?feature=oembed\"></iframe>"}"#;
    const TIKTOK: &str = r#"{"version":"1.0","type":"video","title":"Scramble up ur name & I’ll try to guess it😍❤️ #foryoupage #petsoftiktok #aesthetic","author_url":"https://www.tiktok.com/@scout2015","author_name":"Scout, Suki & Stella","provider_name":"TikTok","author_unique_id":"scout2015","thumbnail_url":"https://p16-common-sign.tiktokcdn-us.com/x.image","html":"<blockquote class=\"tiktok-embed\"></blockquote> <script async src=\"https://www.tiktok.com/embed.js\"></script>"}"#;
    const X: &str = r#"{"url":"https:\/\/x.com\/jack\/status\/20","author_name":"jack","author_url":"https:\/\/x.com\/jack","html":"<blockquote class=\"twitter-tweet\" data-dnt=\"true\"><p lang=\"en\" dir=\"ltr\">just setting up my twttr<\/p>&mdash; jack (@jack) <a href=\"https:\/\/x.com\/jack\/status\/20?ref_src=twsrc%5Etfw\">March 21, 2006<\/a><\/blockquote>\n\n","type":"rich","provider_name":"X"}"#;
    const REDDIT: &str = r#"{"author_name":"PresidentObama","html":"<blockquote class=\"reddit-embed-bq\" style=\"height:316px\" >\n<a href=\"https://www.reddit.com/r/IAmA/comments/z1c9z/i_am_barack_obama_president_of_the_united_states/\">I am Barack Obama, President of the United States -- AMA</a><br> by\n<a href=\"https://www.reddit.com/user/PresidentObama/\">u/PresidentObama</a> in\n<a href=\"https://www.reddit.com/r/IAmA/\">IAmA</a>\n</blockquote>\n<script async src=\"https://embed.reddit.com/widgets.js\" charset=\"UTF-8\"></script>","provider_name":"reddit","title":"I am Barack Obama, President of the United States -- AMA","type":"rich"}"#;

    fn host_of(url: &str) -> String {
        target(url).unwrap().host
    }

    #[test]
    fn every_common_link_shape_is_recognised() {
        // Counterfactual for the hostile table below: a parser that refused everything
        // would pass it and leave the adapters as dead code.
        for (url, platform) in [
            ("https://www.youtube.com/watch?v=dQw4w9WgXcQ", Platform::YouTube),
            ("https://youtube.com/watch?feature=share&v=dQw4w9WgXcQ&t=42", Platform::YouTube),
            ("https://m.youtube.com/watch?v=dQw4w9WgXcQ", Platform::YouTube),
            ("https://www.youtube.com/shorts/dQw4w9WgXcQ", Platform::YouTube),
            ("https://youtu.be/dQw4w9WgXcQ?si=SHARETOKEN", Platform::YouTube),
            ("https://www.tiktok.com/@scout2015/video/6718335390845095173", Platform::TikTok),
            ("https://www.tiktok.com/@a.b_c/photo/6718335390845095173?lang=en", Platform::TikTok),
            ("https://x.com/jack/status/20", Platform::X),
            ("https://twitter.com/jack/status/20?s=46&t=TRACKER", Platform::X),
            ("https://x.com/jack/status/20/photo/1", Platform::X),
            ("https://www.reddit.com/r/IAmA/comments/z1c9z/i_am_barack_obama/", Platform::Reddit),
            ("https://old.reddit.com/r/IAmA/comments/z1c9z", Platform::Reddit),
        ] {
            assert_eq!(parse(url).map(|l| l.platform), Some(platform), "{url}");
        }
    }

    #[test]
    fn a_lookalike_or_disguised_host_is_not_a_platform() {
        // The failure that matters: a link that leads elsewhere, carded with a platform's
        // answer for an id smuggled into it.
        for hostile in [
            "https://youtube.com@evil.test/watch?v=dQw4w9WgXcQ",
            "https://www.youtube.com:443@evil.test/watch?v=dQw4w9WgXcQ",
            "https://evil.test\\@www.youtube.com/watch?v=dQw4w9WgXcQ",
            "https://evil.test/www.youtube.com/watch?v=dQw4w9WgXcQ",
            "https://youtube.com.evil.test/watch?v=dQw4w9WgXcQ",
            "https://notyoutube.com/watch?v=dQw4w9WgXcQ",
            "https://www.youtube.com./watch?v=dQw4w9WgXcQ",
            "https://xn--youtube-9za.com/watch?v=dQw4w9WgXcQ",
            "https://youtu.be.evil.test/dQw4w9WgXcQ",
            "https://x.com.evil.test/jack/status/20",
            "https://evilx.com/jack/status/20",
            "https://twitter.com@evil.test/jack/status/20",
            "https://www.tiktok.com.evil.test/@a/video/1",
            "https://reddit.com.evil.test/r/x/comments/abc/",
            "https://user:pass@www.youtube.com/watch?v=dQw4w9WgXcQ",
            "https://www.youtube.com:8443/watch?v=dQw4w9WgXcQ",
            "javascript:alert(1)//www.youtube.com/watch?v=dQw4w9WgXcQ",
            "ftp://www.youtube.com/watch?v=dQw4w9WgXcQ",
        ] {
            assert_eq!(parse(hostile), None, "{hostile} must not be treated as a platform link");
        }
    }

    #[test]
    fn an_id_cannot_smuggle_anything_into_the_request() {
        // The id is interpolated into a URL sent to the platform. If it could carry `&`,
        // `/`, `%` or `@`, the request could ask about a different URL than the one shown.
        for hostile in [
            "https://www.youtube.com/watch?v=dQw4w9WgXc%26url%3Dhttps://evil.test",
            "https://www.youtube.com/watch?v=../../evil",
            "https://www.youtube.com/watch?v=dQw4w9WgXcQQ",
            "https://www.youtube.com/watch?vv=dQw4w9WgXcQ",
            "https://www.youtube.com/shorts/dQw4w9WgXcQ/extra",
            "https://x.com/jack/status/20abc",
            "https://x.com/ja%2fck/status/20",
            "https://x.com/jack/status/20/evil.test",
            "https://www.tiktok.com/scout2015/video/671833539",
            "https://www.tiktok.com/@scout/video/1@evil.test",
            "https://www.reddit.com/r/IAmA/comments/Z1C9Z/",
            "https://www.reddit.com/r/IA%2fmA/comments/z1c9z/",
            "https://www.reddit.com/r/IAmA/s/SHARELINK",
            "https://youtu.be/",
        ] {
            assert_eq!(parse(hostile), None, "{hostile} must be declined");
        }
    }

    #[test]
    fn whatever_is_accepted_the_request_goes_to_the_platform_and_asks_about_a_clean_url() {
        // The invariant over every shape accepted: the endpoint's host is that platform's
        // constant, and the URL it asks about carries no query from the input — so share
        // trackers stay on the device and nothing can redirect the request.
        for (url, endpoint_host, canonical_host) in [
            ("https://youtu.be/dQw4w9WgXcQ?si=SHARETOKEN", "www.youtube.com", "www.youtube.com"),
            ("http://m.youtube.com/watch?v=dQw4w9WgXcQ&si=T", "www.youtube.com", "www.youtube.com"),
            ("https://twitter.com/jack/status/20?s=46&t=TRACKER", "publish.x.com", "x.com"),
            ("https://www.tiktok.com/@a/video/1?_r=TRACK", "www.tiktok.com", "www.tiktok.com"),
            (
                "https://np.reddit.com/r/IAmA/comments/z1c9z/x/?utm=T",
                "www.reddit.com",
                "www.reddit.com",
            ),
        ] {
            let link = parse(url).unwrap();
            let endpoint = link.endpoint();
            assert!(endpoint.starts_with("https://"), "always https: {endpoint}");
            assert_eq!(host_of(&endpoint), endpoint_host, "{url}");
            let canonical = link.canonical_url();
            assert_eq!(host_of(&canonical), canonical_host);
            for tracker in ["SHARETOKEN", "TRACKER", "TRACK", "si=", "utm"] {
                assert!(!endpoint.contains(tracker), "{tracker} leaked into {endpoint}");
            }
        }
    }

    #[test]
    fn a_youtube_answer_becomes_a_card_for_the_link_as_sent() {
        let sent = "https://youtu.be/dQw4w9WgXcQ?si=SHARETOKEN";
        let card = card_from_response(&parse(sent).unwrap(), sent, YOUTUBE).unwrap();
        assert_eq!(card.url, sent, "the card describes the link the sender actually sent");
        assert_eq!(
            card.title.as_deref(),
            Some("Rick Astley - Never Gonna Give You Up (Official Video) (4K Remaster)")
        );
        assert_eq!(card.description.as_deref(), Some("Video by Rick Astley"));
        assert_eq!(card.claimed_source(), Some("YouTube"));
    }

    #[test]
    fn a_tiktok_answer_names_its_real_author() {
        let sent = "https://www.tiktok.com/@scout2015/video/6718335390845095173";
        let card = card_from_response(&parse(sent).unwrap(), sent, TIKTOK).unwrap();
        assert!(card.title.unwrap().starts_with("Scramble up ur name"));
        assert_eq!(card.description.as_deref(), Some("by Scout, Suki & Stella (@scout2015)"));
    }

    #[test]
    fn an_x_post_is_carded_with_its_words_and_no_markup() {
        let sent = "https://x.com/jack/status/20";
        let card = card_from_response(&parse(sent).unwrap(), sent, X).unwrap();
        assert_eq!(card.title.as_deref(), Some("jack (@jack)"));
        assert_eq!(card.description.as_deref(), Some("just setting up my twttr"));
        assert_eq!(card.claimed_source(), Some("X"));
    }

    #[test]
    fn a_link_naming_one_account_for_anothers_post_is_called_out() {
        // Probed against the live endpoint: `x.com/notjack/status/20` returns jack's post.
        // The handle in a URL is free text, so a card that trusted it would let a sender
        // put words in somebody else's mouth with a link that "looks like" theirs.
        let sent = "https://x.com/notjack/status/20";
        let card = card_from_response(&parse(sent).unwrap(), sent, X).unwrap();
        assert_eq!(card.title.as_deref(), Some("jack (@jack)"), "the author is the platform's");
        assert!(
            card.description.unwrap().contains("The link says @notjack; the post is by @jack."),
            "the disagreement must be shown"
        );

        let sent = "https://www.reddit.com/r/aww/comments/z1c9z/";
        let card = card_from_response(&parse(sent).unwrap(), sent, REDDIT).unwrap();
        assert_eq!(
            card.description.as_deref(),
            Some(
                "Posted by u/PresidentObama in r/IAmA. The link says r/aww; the post is in r/IAmA."
            )
        );
    }

    #[test]
    fn markup_in_a_response_never_survives_into_a_card() {
        // The embed HTML is the platform's script-bearing widget. Only text may come out.
        let hostile = r#"{"author_name":"<img src=x onerror=alert(1)>","author_url":"https://x.com/a","html":"<p>hi <script>alert(1)</script><b>there</b> &lt;img&gt; &#x41;</p>"}"#;
        let sent = "https://x.com/a/status/1";
        let card = card_from_response(&parse(sent).unwrap(), sent, hostile).unwrap();
        let text = card.description.unwrap();
        assert_eq!(text, "hi alert(1)there <img> A");
        // The author name is shown as text by the UI; it is not parsed as markup here.
        assert!(card.title.unwrap().contains("<img"), "names are data, rendered as text");
    }

    #[test]
    fn an_empty_or_broken_answer_falls_back_rather_than_sending_an_empty_card() {
        let sent = "https://www.youtube.com/watch?v=dQw4w9WgXcQ";
        let link = parse(sent).unwrap();
        assert!(card_from_response(&link, sent, "Not Found").is_none());
        assert!(card_from_response(&link, sent, "{}").is_none());
        assert!(card_from_response(&link, sent, r#"{"title":"   "}"#).is_none());
    }
}
