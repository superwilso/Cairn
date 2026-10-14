//! Which sites a user has agreed to have their device contact for link previews.
//!
//! `docs/05-embeds.md` §1 requires the fetch to be **opt-in per platform**: linking X does not
//! imply linking Instagram, and a preview is never fetched for a platform the user has not
//! enabled. Every switch here is off by default.
//!
//! **Enforced per request, not per link.** The fetcher checks every hop — the link, each
//! redirect, the oEmbed endpoint, the thumbnail — against these switches. Checking only the
//! pasted link would leave two side doors: a shortener on an enabled site that redirects to
//! a disabled one, and an ordinary article whose preview image sits on a disabled
//! platform's CDN. Either would contact a platform the user said no to.
//!
//! Classification is by host, against a fixed list of each platform's own domains and image
//! CDNs. A platform that serves from a domain missing here is treated as "other websites" —
//! which errs towards asking under the more general switch, never towards contacting a
//! named platform the user turned off.

use serde::{Deserialize, Serialize};

use super::{target, UnfurlError};

/// A platform with its own switch. `Web` is everything that is not one of the others.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Site {
    Instagram,
    YouTube,
    TikTok,
    X,
    Reddit,
    Web,
}

/// Each platform's own domains, including the CDNs its preview images come from. A host
/// matches a domain when it is that domain or a subdomain of it.
const DOMAINS: &[(Site, &[&str])] = &[
    // fbcdn.net is Meta's CDN, which Instagram's images are served from.
    (Site::Instagram, &["instagram.com", "instagr.am", "cdninstagram.com", "fbcdn.net"]),
    (Site::YouTube, &["youtube.com", "youtu.be", "youtube-nocookie.com", "ytimg.com"]),
    (
        Site::TikTok,
        &["tiktok.com", "tiktokcdn.com", "tiktokcdn-us.com", "tiktokv.com", "ttwstatic.com"],
    ),
    (Site::X, &["x.com", "twitter.com", "t.co", "twimg.com"]),
    (Site::Reddit, &["reddit.com", "redd.it", "redditmedia.com", "redditstatic.com"]),
];

impl Site {
    /// Every site with a switch, in the order a settings screen lists them.
    pub const ALL: [Site; 6] =
        [Site::Instagram, Site::YouTube, Site::TikTok, Site::X, Site::Reddit, Site::Web];

    /// The site a host belongs to. Read the way a browser reads the host, so
    /// `youtube.com@evil.test` is `evil.test`, and a trailing dot changes nothing.
    pub fn of_host(host: &str) -> Site {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        for (site, domains) in DOMAINS {
            let hit = domains.iter().any(|d| {
                host == *d || host.strip_suffix(d).is_some_and(|rest| rest.ends_with('.'))
            });
            if hit {
                return *site;
            }
        }
        Site::Web
    }

    /// The site an http(s) URL goes to, or `None` for anything that is not one.
    pub fn of_url(url: &str) -> Option<Site> {
        let t = target::target(url)?;
        Some(Site::of_host(&t.host))
    }

    /// The name a settings screen shows.
    pub const fn label(self) -> &'static str {
        match self {
            Site::Instagram => "Instagram",
            Site::YouTube => "YouTube",
            Site::TikTok => "TikTok",
            Site::X => "X",
            Site::Reddit => "Reddit",
            Site::Web => "Other websites",
        }
    }
}

/// One switch per [`Site`]. **All off by default**: a device contacts nothing to build a
/// preview until its user has said, per platform, that it may.
///
/// `default` on every field, so a settings file written before a platform got its own
/// switch loads with that platform off rather than failing to load.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Sites {
    #[serde(default)]
    pub instagram: bool,
    #[serde(default)]
    pub youtube: bool,
    #[serde(default)]
    pub tiktok: bool,
    #[serde(default)]
    pub x: bool,
    #[serde(default)]
    pub reddit: bool,
    /// Everything that is not one of the named platforms, previewed from its OpenGraph tags.
    #[serde(default)]
    pub web: bool,
}

impl Sites {
    /// Every switch on. For tests, and for a user who turns each one on.
    pub const fn all() -> Self {
        Self { instagram: true, youtube: true, tiktok: true, x: true, reddit: true, web: true }
    }

    pub const fn allows(self, site: Site) -> bool {
        match site {
            Site::Instagram => self.instagram,
            Site::YouTube => self.youtube,
            Site::TikTok => self.tiktok,
            Site::X => self.x,
            Site::Reddit => self.reddit,
            Site::Web => self.web,
        }
    }

    /// Whether any switch is on — if none is, nothing is ever fetched.
    pub const fn any(self) -> bool {
        self.instagram || self.youtube || self.tiktok || self.x || self.reddit || self.web
    }

    /// Refuse a URL whose site is switched off. Called before every request.
    pub fn permits(self, url: &str) -> Result<(), UnfurlError> {
        let site = Site::of_url(url).ok_or(UnfurlError::NotHttp)?;
        if self.allows(site) {
            Ok(())
        } else {
            Err(UnfurlError::NotEnabled(site.label()))
        }
    }

    /// Parse a comma-separated list — `"youtube,web"`, or `"all"` — as a headless client's
    /// configuration. Unknown names are an error rather than ignored, so a typo cannot
    /// silently turn a platform on or leave the user believing one is on.
    pub fn parse_list(list: &str) -> Result<Self, String> {
        let mut sites = Sites::default();
        for name in list.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            match name.to_ascii_lowercase().as_str() {
                "all" => sites = Sites::all(),
                "instagram" => sites.instagram = true,
                "youtube" => sites.youtube = true,
                "tiktok" => sites.tiktok = true,
                "x" | "twitter" => sites.x = true,
                "reddit" => sites.reddit = true,
                "web" | "other" => sites.web = true,
                other => return Err(format!("unknown link-preview site {other:?}")),
            }
        }
        Ok(sites)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_switch_is_off_until_the_user_turns_it_on() {
        let sites = Sites::default();
        for site in Site::ALL {
            assert!(!sites.allows(site), "{site:?} must default to off");
        }
        assert!(!sites.any());
        // And a settings file from before per-platform switches loads as all off.
        let old: Sites = serde_json::from_str(r#"{"enabled":true}"#).unwrap();
        assert_eq!(old, Sites::default());
    }

    #[test]
    fn each_platforms_links_and_image_hosts_fall_under_its_own_switch() {
        for (url, site) in [
            ("https://www.instagram.com/reel/C5nYxQyOZ6V/", Site::Instagram),
            ("https://scontent-lhr8-1.cdninstagram.com/v/t51/x.jpg", Site::Instagram),
            ("https://youtu.be/dQw4w9WgXcQ", Site::YouTube),
            ("https://i.ytimg.com/vi/dQw4w9WgXcQ/hqdefault.jpg", Site::YouTube),
            ("https://www.tiktok.com/@a/video/1", Site::TikTok),
            ("https://twitter.com/jack/status/20", Site::X),
            ("https://pbs.twimg.com/media/x.jpg", Site::X),
            ("https://old.reddit.com/r/rust/comments/abc/", Site::Reddit),
            ("https://example.com/article", Site::Web),
        ] {
            assert_eq!(Site::of_url(url), Some(site), "{url}");
        }
    }

    #[test]
    fn a_lookalike_or_disguised_host_is_not_the_platform() {
        for url in [
            "https://notyoutube.com/watch",
            "https://youtube.com.evil.test/watch",
            "https://youtube.com@evil.test/watch",
            "https://evil.test/www.instagram.com/reel/x/",
        ] {
            assert_eq!(Site::of_url(url), Some(Site::Web), "{url} is not a named platform");
        }
    }

    #[test]
    fn a_disabled_site_is_refused_and_an_enabled_one_is_not() {
        let only_youtube = Sites { youtube: true, ..Sites::default() };
        assert!(only_youtube.permits("https://youtu.be/x").is_ok());
        assert!(matches!(
            only_youtube.permits("https://www.instagram.com/reel/x/"),
            Err(UnfurlError::NotEnabled("Instagram"))
        ));
        assert!(only_youtube.permits("https://example.com/").is_err());
    }

    #[test]
    fn a_typo_in_a_headless_list_is_an_error_not_a_silent_choice() {
        assert_eq!(Sites::parse_list("").unwrap(), Sites::default());
        assert_eq!(Sites::parse_list("all").unwrap(), Sites::all());
        let s = Sites::parse_list("youtube, web").unwrap();
        assert!(s.youtube && s.web && !s.instagram);
        assert!(Sites::parse_list("youtub").is_err());
    }
}
