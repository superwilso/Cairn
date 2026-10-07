//! The network half of link previews: page, oEmbed, proxy and thumbnail fetches.
//!
//! **Only ever called for a URL the local user supplied.** Calling any of this for a link
//! that arrived in a message would contact the platform from the recipient's address, which
//! is precisely what the embed design exists to avoid.
//!
//! ## Bounded in time, end to end
//!
//! Every fetch in one preview shares a single deadline, [`FETCH_TIMEOUT`]. Before it existed
//! the HTTP client had no timeout at all, so a server that accepted the connection and then
//! trickled a byte a second held the unfurl — and, in a frontend that awaited it before
//! sending, the message — indefinitely. Five seconds is long enough for a slow page and
//! short enough that a preview never feels like the message is stuck.

use std::time::{Duration, Instant};

#[cfg(test)]
use super::Thumbnail;
use super::UnfurlError;
use super::{instagram, is_fetchable, oembed, parse_metadata, thumbnail, Card, CardSource};

/// The most one preview may take, every request in it included.
pub const FETCH_TIMEOUT: Duration = Duration::from_secs(5);

/// Bytes of a page to read before giving up.
///
/// Metadata lives in the head, so a page that has not declared itself in 512 KB is not going
/// to. Bounded because the response is attacker-controlled length.
const MAX_BODY: u64 = 512 * 1024;
/// An oEmbed answer is a few hundred bytes; anything near this is not one.
const MAX_OEMBED: u64 = 64 * 1024;
/// The largest image downloaded to make a thumbnail. The re-encoded result is far smaller
/// ([`thumbnail::MAX_BYTES`]); this bounds what is read off the wire to get there.
const MAX_IMAGE: u64 = 2 * 1024 * 1024;

/// A generic user-agent: many sites serve no OpenGraph at all without one. It is also the
/// sender's fingerprint, which is the leak `docs/05-embeds.md` §1 says must be opt-in per
/// platform — recorded there, not solved here.
///
/// **Honest on purpose.** The Instagram proxies probed on 2026-10-07 only serve metadata to
/// user-agents they recognise as a known chat app's crawler, and redirect everybody else
/// to instagram.com. Claiming to be another product's crawler would get previews, and it is
/// not this project's call to make silently; it is recorded in `docs/05-embeds.md` for the
/// owner.
const USER_AGENT: &str = "Mozilla/5.0 (compatible; Cairn link preview)";

#[derive(Clone, Copy)]
struct Deadline(Instant);

impl Deadline {
    fn start() -> Self {
        Self(Instant::now() + FETCH_TIMEOUT)
    }

    fn remaining(self) -> Result<Duration, UnfurlError> {
        let left = self.0.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(UnfurlError::Fetch("timed out".into()));
        }
        Ok(left)
    }
}

/// Whether a request may follow redirects.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Redirects {
    Follow,
    /// For a third-party proxy. One probed on 2026-10-07 answered every request with a
    /// redirect to an advertising network; following it would hand the user's IP to a
    /// party they never chose. A proxy that redirects is a proxy that did not answer.
    Refuse,
}

fn get(
    url: &str,
    accept: &str,
    deadline: Deadline,
    redirects: Redirects,
) -> Result<ureq::http::Response<ureq::Body>, UnfurlError> {
    let mut config = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .timeout_global(Some(deadline.remaining()?));
    if redirects == Redirects::Refuse {
        config = config.max_redirects(0);
    }
    let response = ureq::Agent::new_with_config(config.build())
        .get(url)
        .header("user-agent", USER_AGENT)
        .header("accept", accept)
        .call()
        .map_err(|e| UnfurlError::Fetch(e.to_string()))?;
    if response.status().is_redirection() {
        return Err(UnfurlError::Fetch("redirected".into()));
    }
    Ok(response)
}

fn content_type(response: &ureq::http::Response<ureq::Body>) -> String {
    response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_ascii_lowercase()
}

/// Fetch `url` and build a card: the platform's oEmbed answer for a recognised post, the
/// page's OpenGraph otherwise, and a thumbnail when either names an image.
///
/// A failure is not an error worth surfacing loudly — it degrades to a bare link, which is
/// the last step of the fallback chain and always works.
pub fn unfurl(url: &str) -> Result<Card, UnfurlError> {
    is_fetchable(url)?;
    let deadline = Deadline::start();
    let mut card = direct(url, deadline)?;
    attach_thumbnail(&mut card, deadline);
    Ok(card)
}

fn direct(url: &str, deadline: Deadline) -> Result<Card, UnfurlError> {
    // oEmbed first for the four platforms whose pages do not serve usable OpenGraph. Same
    // organisation, same device: no new party learns the link (see `oembed`).
    if let Some(link) = oembed::parse(url) {
        if let Ok(card) = fetch_oembed(&link, url, deadline) {
            return Ok(card);
        }
    }
    let mut card = fetch_and_parse_within(url, deadline, Redirects::Follow)?;
    if instagram::parse(url).is_some() {
        instagram::tidy(&mut card);
    }
    Ok(card)
}

/// Unfurl, falling back to a configured proxy for links the site itself will not serve.
///
/// Only Instagram, and only because Instagram sometimes shows anonymous visitors a login
/// wall instead of the post. What the development container saw on 2026-10-07: a real
/// public post or reel came back with full OpenGraph (author, caption, counts, thumbnail),
/// while a profile redirected to the login page and a missing post returned a 636 KB script
/// shell with no metadata. Instagram is also known to wall anonymous traffic by rate and by
/// network, so the direct path is tried first and is often enough. Everything else takes
/// the direct path unchanged.
///
/// The proxy is tried **only after** the direct fetch has failed to produce anything useful,
/// so a link that works without one never reaches a third party. Each attempt is a URL
/// disclosed to somebody, so order matters here in a way it does not for an ordinary
/// fallback. Redirects from a proxy are refused (see [`Redirects::Refuse`]).
///
/// A card built this way carries [`CardSource::Proxy`], whose `caveat()` a client must
/// display. Returning a proxy-built card marked `Public` would be the specific lie
/// `docs/05-embeds.md` forbids.
pub fn unfurl_with_proxy(url: &str, policy: &instagram::ProxyPolicy) -> Result<Card, UnfurlError> {
    is_fetchable(url)?;
    let deadline = Deadline::start();
    let direct = direct(url, deadline);
    if let Ok(card) = &direct {
        if card.is_useful() {
            let mut card = card.clone();
            attach_thumbnail(&mut card, deadline);
            return Ok(card);
        }
    }

    // Not an Instagram post, or proxying is off: keep whatever the direct path said,
    // including its error. Falling through to a proxy for arbitrary URLs would send links to
    // a third party that the user never opted into sharing.
    let Some(link) = instagram::parse(url) else { return direct };
    if !policy.is_enabled() {
        return direct;
    }

    for candidate in instagram::proxy_urls(&link, policy) {
        if is_fetchable(&candidate).is_err() {
            continue;
        }
        if let Ok(mut card) = fetch_and_parse_within(&candidate, deadline, Redirects::Refuse) {
            if card.is_useful() {
                // The card describes the *original* link, not the proxy's URL. A recipient
                // evaluating where a message points must see where it really points — the
                // proxy is an implementation detail of how the preview was obtained, and
                // `source` is where that is disclosed.
                card.url = url.to_string();
                card.source = CardSource::Proxy;
                instagram::tidy(&mut card);
                // The proxy names its own copy of the image; fetching it tells that same
                // proxy nothing it was not just told.
                attach_thumbnail(&mut card, deadline);
                return Ok(card);
            }
        }
    }
    direct
}

/// Everything a sending client needs: the best card available for the first link in a
/// message, or `None` to send it bare.
///
/// For a recognised post on a platform (an Instagram reel, a TikTok, a YouTube video) with
/// no metadata available, the answer is a card carrying **only the URL** — a recipient's
/// client draws "Instagram reel · open link" from the URL's shape. Nothing is invented: a
/// card with a title nobody fetched would be a fabrication in the sender's name.
///
/// Never panics. A hostile page that tripped a bug in the parser would otherwise take the
/// message down with it, and a preview is never worth a message.
pub fn preview(url: &str, policy: &instagram::ProxyPolicy) -> Option<Card> {
    let attempt = std::panic::catch_unwind(|| unfurl_with_proxy(url, policy));
    settle(url, attempt.ok().and_then(Result::ok))
}

fn settle(url: &str, fetched: Option<Card>) -> Option<Card> {
    match fetched {
        Some(card) if card.is_useful() => Some(card.clamp()),
        _ if instagram::parse(url).is_some() || oembed::parse(url).is_some() => {
            Some(Card::bare(url))
        }
        _ => None,
    }
}

fn fetch_oembed(
    link: &oembed::OembedLink,
    url: &str,
    deadline: Deadline,
) -> Result<Card, UnfurlError> {
    let endpoint = link.endpoint();
    is_fetchable(&endpoint)?;
    let mut response = get(&endpoint, "application/json", deadline, Redirects::Follow)?;
    if !response.status().is_success() {
        return Err(UnfurlError::Fetch(format!("oEmbed answered {}", response.status())));
    }
    if !content_type(&response).contains("json") {
        return Err(UnfurlError::NotHtml);
    }
    let body = response
        .body_mut()
        .with_config()
        .limit(MAX_OEMBED)
        .read_to_string()
        .map_err(|e| UnfurlError::Fetch(e.to_string()))?;
    oembed::card_from_response(link, url, &body)
        .ok_or_else(|| UnfurlError::Fetch("oEmbed answer had nothing to show".into()))
}

/// The transport half of an OpenGraph fetch, with the address policy already applied.
///
/// Split out so tests can drive the HTTP and parsing path against a loopback server, which
/// [`is_fetchable`] refuses by design. Private, and the only public entry points apply the
/// check first — a caller cannot reach this to skip it.
#[cfg(test)]
pub(super) fn fetch_and_parse(url: &str) -> Result<Card, UnfurlError> {
    fetch_and_parse_within(url, Deadline::start(), Redirects::Follow)
}

fn fetch_and_parse_within(
    url: &str,
    deadline: Deadline,
    redirects: Redirects,
) -> Result<Card, UnfurlError> {
    let mut response = get(url, "text/html,application/xhtml+xml", deadline, redirects)?;
    let content_type = content_type(&response);
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

/// Fetch the card's image and shrink it into [`Card::thumbnail`]. Any failure leaves the
/// card without one, which is a perfectly good card.
fn attach_thumbnail(card: &mut Card, deadline: Deadline) {
    if card.thumbnail.is_some() {
        return;
    }
    let Some(image_url) = card.image_url.as_deref() else { return };
    if thumbnail_url_allowed(image_url).is_err() {
        return;
    }
    card.thumbnail = fetch_image(image_url, deadline)
        .ok()
        .and_then(|b| thumbnail::from_image_bytes(&b))
        .map(Box::new);
}

/// The policy for an image URL a page named.
///
/// The page chose this URL, so it is attacker-controlled even when the link was not: an
/// innocuous article can name `http://192.168.1.1/admin.png` as its image. **https only**,
/// because a thumbnail fetched in the clear can be swapped by anyone on the sender's
/// network and would then travel to every recipient under the sender's name; and the same
/// private-address refusal as any other fetch.
fn thumbnail_url_allowed(url: &str) -> Result<(), UnfurlError> {
    if !super::target::target(url).is_some_and(|t| t.https) {
        return Err(UnfurlError::NotHttp);
    }
    is_fetchable(url)
}

/// The image transport, policy already applied. Only `image/*`, at most [`MAX_IMAGE`].
fn fetch_image(url: &str, deadline: Deadline) -> Result<Vec<u8>, UnfurlError> {
    let mut response = get(url, "image/jpeg,image/png,image/webp", deadline, Redirects::Follow)?;
    if !response.status().is_success() {
        return Err(UnfurlError::Fetch(format!("image answered {}", response.status())));
    }
    // Checked before a byte of the body is read: a link to a 4 GB video named as an
    // "image" must not be downloaded to find out.
    if !content_type(&response).starts_with("image/") {
        return Err(UnfurlError::NotHtml);
    }
    response
        .body_mut()
        .with_config()
        .limit(MAX_IMAGE)
        .read_to_vec()
        .map_err(|e| UnfurlError::Fetch(e.to_string()))
}

/// Exposed for the thumbnail module's tests and nothing else.
#[cfg(test)]
pub(super) fn thumbnail_from(url: &str) -> Result<Option<Thumbnail>, UnfurlError> {
    Ok(thumbnail::from_image_bytes(&fetch_image(url, Deadline::start())?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    /// A one-shot server answering with exactly `head` (status line and headers, no blank
    /// line) and then `body`.
    fn serve(head: &str, body: Vec<u8>) -> String {
        let response = [
            format!("{head}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len())
                .into_bytes(),
            body,
        ]
        .concat();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf);
                let _ = stream.write_all(&response);
                let _ = stream.flush();
            }
        });
        format!("http://{addr}/x")
    }

    #[test]
    fn a_server_that_trickles_forever_cannot_hold_the_preview_past_its_deadline() {
        // Before the deadline existed this never returned: headers, then a byte every 200ms
        // for as long as the client would listen. Uses the real constant, not a test value,
        // because the constant is the thing being defended.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf);
                let _ = stream.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 999999\r\n\r\n<html><head>",
                );
                for _ in 0..200 {
                    std::thread::sleep(Duration::from_millis(200));
                    if stream.write_all(b" ").is_err() {
                        return;
                    }
                }
            }
        });
        let started = Instant::now();
        let result = fetch_and_parse(&format!("http://{addr}/slow"));
        let took = started.elapsed();
        assert!(result.is_err(), "a page that never finishes is not a card");
        assert!(
            took < FETCH_TIMEOUT + Duration::from_secs(2),
            "took {took:?}; the deadline is {FETCH_TIMEOUT:?}"
        );
    }

    #[test]
    fn a_proxy_that_redirects_is_not_followed() {
        // Probed: one Instagram proxy answered every request with a redirect to an
        // advertising network. Following it hands the user's IP to a party nobody chose.
        let url = serve("HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:9/ads", Vec::new());
        let result = fetch_and_parse_within(&url, Deadline::start(), Redirects::Refuse);
        assert!(result.is_err(), "a redirecting proxy must count as no answer: {result:?}");
    }

    #[test]
    fn a_thumbnail_is_only_fetched_over_https_from_a_public_address() {
        for refused in [
            "http://cdn.example.com/a.jpg",
            "https://127.0.0.1/a.jpg",
            "https://192.168.1.1/a.jpg",
            "https://2130706433/a.jpg",
            "https://[::ffff:127.0.0.1]/a.jpg",
            "https://localhost/a.jpg",
            "data:image/png;base64,AAAA",
            "javascript:alert(1)",
            "//cdn.example.com/a.jpg",
        ] {
            assert!(thumbnail_url_allowed(refused).is_err(), "must refuse {refused}");
        }
        assert!(thumbnail_url_allowed("https://i.ytimg.com/vi/dQw4w9WgXcQ/hqdefault.jpg").is_ok());
    }

    #[test]
    fn something_that_is_not_an_image_is_never_downloaded_as_one() {
        let url = serve("HTTP/1.1 200 OK\r\nContent-Type: text/html", b"<script>".to_vec());
        assert!(matches!(thumbnail_from(&url), Err(UnfurlError::NotHtml)));
        let url = serve("HTTP/1.1 200 OK\r\nContent-Type: video/mp4", vec![0; 64]);
        assert!(matches!(thumbnail_from(&url), Err(UnfurlError::NotHtml)));
    }

    #[test]
    fn an_oversized_image_is_abandoned_rather_than_read() {
        let url = serve(
            "HTTP/1.1 200 OK\r\nContent-Type: image/jpeg",
            vec![0xFF; MAX_IMAGE as usize + 10],
        );
        assert!(thumbnail_from(&url).is_err(), "over the download cap must be an error");
    }

    #[test]
    fn a_real_image_response_becomes_a_thumbnail() {
        let img = image::DynamicImage::ImageRgb8(image::RgbImage::from_pixel(
            900,
            1600,
            image::Rgb([200, 40, 90]),
        ));
        let mut png = std::io::Cursor::new(Vec::new());
        img.write_to(&mut png, image::ImageFormat::Png).unwrap();
        let url = serve("HTTP/1.1 200 OK\r\nContent-Type: image/png", png.into_inner());
        let thumb = thumbnail_from(&url).unwrap().expect("a thumbnail");
        assert!(thumb.is_portrait() && thumb.height <= thumbnail::MAX_HEIGHT);
    }

    #[test]
    fn a_platform_link_with_nothing_fetched_gets_a_card_carrying_only_its_url() {
        // The Instagram login-wall case, no proxy. Nothing may be invented — the
        // card is the URL and nothing else, and the recipient draws "reel" from its shape.
        let reel = "https://www.instagram.com/reel/C5nYxQyOZ6V/";
        let empty = Card { url: reel.into(), ..Card::default() };
        for fetched in [None, Some(empty)] {
            assert_eq!(settle(reel, fetched), Some(Card::bare(reel)));
        }
        // An ordinary link with nothing fetched is sent bare: chrome around nothing implies
        // a lookup found something.
        assert_eq!(settle("https://example.com/", None), None);
        // And the public entry point refuses a private address without fetching anything.
        assert_eq!(preview("http://127.0.0.1/", &Default::default()), None);
    }

    #[test]
    fn a_hostile_page_cannot_crash_the_preview() {
        // Found by probing: `<€€` in a page's head panicked the metadata parser on a byte
        // slice inside a multi-byte character. `preview` must survive whatever a page sends.
        let card = parse_metadata(
            "<html><head><€€ x><meta property='og:title' content='ok'></head>",
            "https://e.test/",
        );
        assert_eq!(card.title.as_deref(), Some("ok"));
    }
}
