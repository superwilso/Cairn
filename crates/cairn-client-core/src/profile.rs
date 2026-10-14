//! Profiles — display name, pronouns, about me, avatar, banner, colours, status and a
//! per-room nickname — carried inside the encrypted message stream.
//!
//! ## The shape, and why
//!
//! Discord keeps a profile on its server. Copying that would hand the instance exactly the
//! thing an E2EE room is meant to keep from it: a profile is chosen by people for the people
//! they talk to, and a name, a face and a bio are often more identifying than anything said
//! in the room. So the instance never sees one. A [`Profile`] is a record a client sends
//! *into each room* as an ordinary encrypted message
//! ([`crate::Conversation::send_profile`]); images are encrypted attachments uploaded to that
//! room, their keys inside the record. Recipients keep the latest record per member per room
//! ([`ProfileStore`]). The design and what it costs are in
//! `docs/adr/010-encrypted-profiles.md`.
//!
//! ## Whose profile it is
//!
//! **The record has no field saying.** It is filed under the envelope's sender, which
//! [`crate::Conversation::receive`] checks against the group's own roster before anything is
//! decrypted, so a member cannot publish a profile "for" somebody else and the instance cannot
//! relabel one.
//!
//! ## A name is a claim, never an identity
//!
//! Anyone can call themselves anything. So:
//!
//! - **Names are sanitised on both ends** ([`Profile::validate`]): bounded, one line, and no
//!   control, invisible or text-direction characters — a right-to-left override can make
//!   `alice` render from bytes that say `ecila`, and a zero-width space makes two names that
//!   look identical compare different.
//! - **A name cannot pass for an account id** — the short hex form a client shows for a
//!   member with no name. See [`looks_like_an_id`].
//! - **Collisions are flagged, not prevented** ([`labels`]). Two members whose names look
//!   alike — case, whitespace, and a table of common Latin/Cyrillic/Greek lookalikes folded
//!   away — are both marked `ambiguous`, and a client shows each one's id beside the name.
//!   This is a heuristic and says so: it is not Unicode TR39, and a determined lookalike can
//!   get past it. What does not depend on it: **security UI shows the account id, never the
//!   name** — safety numbers, the "verified" mark and membership notices are about keys, and
//!   a key has no display name.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use cairn_proto::{RoomId, UserId};

use crate::conversation::Attachment;

/// Longest display name or nickname, in characters.
pub const MAX_NAME_CHARS: usize = 32;
/// Longest pronouns field, in characters.
pub const MAX_PRONOUNS_CHARS: usize = 40;
/// Longest "about me", in characters. Discord's number, which people already write to.
pub const MAX_ABOUT_CHARS: usize = 190;
/// Most lines an "about me" may have, so a bio cannot push a profile card off the screen.
pub const MAX_ABOUT_LINES: usize = 8;
/// Longest custom status text, in characters.
pub const MAX_STATUS_CHARS: usize = 128;
/// Largest avatar or banner, in plaintext bytes.
///
/// Every member downloads every other member's images, in every room they share, so this is
/// multiplied by the room's size. A client downscales before sending; this is the ceiling it
/// works under, and the ceiling a recipient enforces on what it decrypts.
pub const MAX_PROFILE_IMAGE_BYTES: usize = 1024 * 1024;
/// Image types a profile may carry. Raster only, for the reason
/// `session::attachments` gives for refusing SVG inline.
pub const PROFILE_IMAGE_TYPES: &[&str] = &["image/png", "image/jpeg", "image/webp", "image/gif"];

/// Why a profile — one being set here, or one that arrived — was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProfileError {
    #[error("{field} is too long — the limit is {max} characters")]
    TooLong { field: &'static str, max: usize },
    #[error(
        "{field} contains a character that is not allowed: control, invisible and \
         text-direction characters are refused"
    )]
    ForbiddenCharacter { field: &'static str },
    #[error("{field} has nothing visible in it")]
    Blank { field: &'static str },
    #[error("{field} must be a single line")]
    MultiLine { field: &'static str },
    #[error("{field} cannot start or end with a space")]
    Untrimmed { field: &'static str },
    #[error(
        "{field} mixes Latin, Cyrillic or Greek letters, which is how lookalike names are built"
    )]
    MixedScript { field: &'static str },
    #[error("{field} looks like an account id, which is what members without a name are shown as")]
    LooksLikeId { field: &'static str },
    #[error("about me is limited to {MAX_ABOUT_LINES} lines")]
    TooManyLines,
    #[error("a status emoji is a single emoji")]
    BadEmoji,
    #[error("a status expiry must be a time, not {0}")]
    BadExpiry(i64),
    #[error("a profile colour must be written #rrggbb")]
    BadColour,
    #[error("profile images must be PNG, JPEG, WebP or GIF")]
    BadImageType,
    #[error("profile images are limited to {} KiB", MAX_PROFILE_IMAGE_BYTES / 1024)]
    ImageTooLarge,
}

/// A custom status: an emoji, some text, or both, optionally until a time.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Status {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub emoji: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// When it stops showing, on the *recipient's* clock. A sender cannot make a status
    /// outlive this by lying about the time, only by setting it again.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_ms: Option<i64>,
}

/// One member's profile, as sent into one room.
///
/// **Every field is chosen by the sender**, and every field is optional: an absent field is
/// "not set", and a client shows the account id where there is no name.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Profile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// A name for this room only. Sent only into the room it belongs to, so the other rooms
    /// never learn it — a nickname in a support group is nobody else's business.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nickname: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pronouns: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub about: Option<String>,
    /// An encrypted attachment in *this room's* blob store, its key in here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avatar: Option<Attachment>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub banner: Option<Attachment>,
    /// The banner gradient, top to bottom, as `0xRRGGBB`. Shown where there is no banner
    /// image, and as the card's accent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub colors: Option<[u32; 2]>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<Status>,
}

impl Profile {
    /// Check every field against the rules. Run by the sender before sending and by every
    /// recipient on receipt, which is the one that counts.
    pub fn validate(&self) -> Result<(), ProfileError> {
        if let Some(name) = &self.display_name {
            check_name("display name", name)?;
        }
        if let Some(name) = &self.nickname {
            check_name("nickname", name)?;
        }
        if let Some(p) = &self.pronouns {
            check_line("pronouns", p, MAX_PRONOUNS_CHARS)?;
        }
        if let Some(about) = &self.about {
            check_about(about)?;
        }
        for image in [&self.avatar, &self.banner].into_iter().flatten() {
            check_image(image.mime.as_deref(), image.size)?;
        }
        if let Some(colors) = &self.colors {
            if colors.iter().any(|c| *c > 0xFF_FFFF) {
                return Err(ProfileError::BadColour);
            }
        }
        if let Some(status) = &self.status {
            if let Some(text) = &status.text {
                check_line("status", text, MAX_STATUS_CHARS)?;
            }
            if let Some(emoji) = &status.emoji {
                if !crate::conversation::is_emoji_like(emoji) {
                    return Err(ProfileError::BadEmoji);
                }
            }
            if let Some(at) = status.expires_at_ms {
                if at <= 0 {
                    return Err(ProfileError::BadExpiry(at));
                }
            }
        }
        Ok(())
    }

    /// The name to show: the room nickname if there is one, else the display name.
    pub fn name(&self) -> Option<&str> {
        self.nickname.as_deref().or(self.display_name.as_deref())
    }
}

/// An image's claimed type and size, against the profile rules.
pub fn check_image(mime: Option<&str>, size: usize) -> Result<(), ProfileError> {
    let mime = mime.unwrap_or("").trim().to_ascii_lowercase();
    if !PROFILE_IMAGE_TYPES.contains(&mime.as_str()) {
        return Err(ProfileError::BadImageType);
    }
    if size == 0 || size > MAX_PROFILE_IMAGE_BYTES {
        return Err(ProfileError::ImageTooLarge);
    }
    Ok(())
}

/// Parse `#rrggbb` (the `#` optional) into `0xRRGGBB`.
pub fn parse_colour(s: &str) -> Result<u32, ProfileError> {
    let hex = s.trim().trim_start_matches('#');
    if hex.len() != 6 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(ProfileError::BadColour);
    }
    u32::from_str_radix(hex, 16).map_err(|_| ProfileError::BadColour)
}

pub fn format_colour(c: u32) -> String {
    format!("#{:06x}", c & 0xFF_FFFF)
}

// ---- text rules --------------------------------------------------------------

/// Characters that change how *other* text is laid out or compared without being seen:
/// explicit bidi controls, and the invisible formatting characters lookalike names are made
/// with. Refused in every field.
fn is_hidden(c: char) -> bool {
    matches!(c,
        // Bidi: embeddings, overrides, isolates and marks. An override is how `alice` is
        // drawn from bytes that read `ecila`.
        '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
        // Zero-width and invisible formatting.
        | '\u{00AD}' | '\u{034F}' | '\u{115F}' | '\u{1160}' | '\u{17B4}' | '\u{17B5}'
        | '\u{180B}'..='\u{180F}' | '\u{200B}' | '\u{200C}' | '\u{2060}'..='\u{2064}'
        | '\u{206A}'..='\u{206F}' | '\u{3164}' | '\u{FFA0}' | '\u{FEFF}'
        | '\u{FFF9}'..='\u{FFFC}' | '\u{E0000}'..='\u{E007F}'
        // Line and paragraph separators, which `char::is_control` does not catch.
        | '\u{2028}' | '\u{2029}'
    )
}

/// Combining marks, for bounding how many stack on one letter.
fn is_mark(c: char) -> bool {
    matches!(c,
        '\u{0300}'..='\u{036F}' | '\u{0483}'..='\u{0489}' | '\u{1AB0}'..='\u{1AFF}'
        | '\u{1DC0}'..='\u{1DFF}' | '\u{20D0}'..='\u{20FF}' | '\u{FE20}'..='\u{FE2F}')
}

fn is_private_use(c: char) -> bool {
    matches!(c, '\u{E000}'..='\u{F8FF}' | '\u{F0000}'..='\u{FFFFD}' | '\u{100000}'..='\u{10FFFD}')
}

/// Mathematical alphanumerics — 𝐀𝐥𝐢𝐜𝐞 — exist to look like letters they are not.
fn is_styled_letter(c: char) -> bool {
    matches!(c, '\u{1D400}'..='\u{1D7FF}')
}

/// Shared by every text field: no controls (bar newline where allowed), nothing hidden,
/// no private-use glyphs, and no more than two combining marks on one character.
fn check_chars(field: &'static str, s: &str, newlines: bool) -> Result<(), ProfileError> {
    let mut marks = 0;
    for c in s.chars() {
        if c == '\n' && newlines {
            marks = 0;
            continue;
        }
        if c.is_control() || is_hidden(c) || is_private_use(c) {
            return Err(ProfileError::ForbiddenCharacter { field });
        }
        if is_mark(c) {
            marks += 1;
            if marks > 2 {
                return Err(ProfileError::ForbiddenCharacter { field });
            }
        } else {
            marks = 0;
        }
    }
    Ok(())
}

/// A single line of free text: pronouns, a status.
fn check_line(field: &'static str, s: &str, max: usize) -> Result<(), ProfileError> {
    if s.chars().count() > max {
        return Err(ProfileError::TooLong { field, max });
    }
    if s.contains('\n') {
        return Err(ProfileError::MultiLine { field });
    }
    check_chars(field, s, false)?;
    if s.trim() != s {
        return Err(ProfileError::Untrimmed { field });
    }
    if s.trim().is_empty() {
        return Err(ProfileError::Blank { field });
    }
    Ok(())
}

fn check_about(s: &str) -> Result<(), ProfileError> {
    let field = "about me";
    if s.chars().count() > MAX_ABOUT_CHARS {
        return Err(ProfileError::TooLong { field, max: MAX_ABOUT_CHARS });
    }
    if s.lines().count() > MAX_ABOUT_LINES {
        return Err(ProfileError::TooManyLines);
    }
    check_chars(field, s, true)?;
    if s.trim().is_empty() {
        return Err(ProfileError::Blank { field });
    }
    Ok(())
}

/// A name — display name or nickname. Stricter than other text, because a name is what
/// people use to decide who said something.
fn check_name(field: &'static str, s: &str) -> Result<(), ProfileError> {
    check_line(field, s, MAX_NAME_CHARS)?;
    for c in s.chars() {
        // Only the ordinary space: an em space or a no-break space pads a name into looking
        // like another one, and nobody types them on purpose.
        if c.is_whitespace() && c != ' ' {
            return Err(ProfileError::ForbiddenCharacter { field });
        }
        if is_styled_letter(c) {
            return Err(ProfileError::ForbiddenCharacter { field });
        }
    }
    if s.contains("  ") {
        return Err(ProfileError::ForbiddenCharacter { field });
    }
    if !s.chars().any(|c| {
        !c.is_whitespace() && !is_mark(c) && !matches!(c, '\u{200D}' | '\u{FE0E}' | '\u{FE0F}')
    }) {
        return Err(ProfileError::Blank { field });
    }
    if mixes_scripts(s) {
        return Err(ProfileError::MixedScript { field });
    }
    if looks_like_an_id(s) {
        return Err(ProfileError::LooksLikeId { field });
    }
    Ok(())
}

#[derive(PartialEq, Eq, Clone, Copy)]
enum Script {
    Latin,
    Greek,
    Cyrillic,
}

fn script_of(c: char) -> Option<Script> {
    match c {
        'a'..='z' | 'A'..='Z' | '\u{00C0}'..='\u{024F}' => Some(Script::Latin),
        '\u{0370}'..='\u{03FF}' | '\u{1F00}'..='\u{1FFF}' => Some(Script::Greek),
        '\u{0400}'..='\u{052F}' => Some(Script::Cyrillic),
        _ => None,
    }
}

/// Whether a name uses letters from more than one of Latin, Greek and Cyrillic — the
/// alphabets that share glyphs. `Аlice` with a Cyrillic `А` is one of these. Mixing any of
/// them with another script (`Zoë 李`) is ordinary and allowed.
fn mixes_scripts(s: &str) -> bool {
    let mut seen: Option<Script> = None;
    for script in s.chars().filter_map(script_of) {
        match seen {
            None => seen = Some(script),
            Some(first) if first != script => return true,
            _ => {}
        }
    }
    false
}

/// Whether a name could be mistaken for an account id as a client shows one.
///
/// A member with no name is shown by the first hex digits of their id, so a name that is
/// itself a run of hex digits could stand in for somebody else's — `1a2b3c4d` is either a
/// name or an account and nothing on screen says which. Also anything carrying the `usr_`
/// prefix, and anything that parses as an id outright.
pub fn looks_like_an_id(name: &str) -> bool {
    let lower = name.to_lowercase();
    if lower.contains("usr_") || lower.parse::<UserId>().is_ok() {
        return true;
    }
    let hexish: String = lower.chars().filter(|c| !matches!(c, '-' | ' ' | '#')).collect();
    hexish.len() >= 4 && hexish.chars().all(|c| c.is_ascii_hexdigit())
}

// ---- telling names apart -------------------------------------------------------

/// A reduced form of a name for spotting lookalikes: lowercase, no spaces, separators or
/// combining marks, fullwidth folded to ASCII, common Cyrillic and Greek lookalikes folded
/// to the Latin letter they imitate, and `0/1/i/|` and `rn/vv` collapsed.
///
/// **A heuristic.** It catches the lookalikes people actually use, not every one Unicode
/// allows. Names that collide under it are flagged; names that do not are not thereby proven
/// different.
pub fn skeleton(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars().flat_map(char::to_lowercase) {
        if c.is_whitespace()
            || is_mark(c)
            || matches!(c, '\u{200D}' | '\u{FE0E}' | '\u{FE0F}' | '.' | '_' | '-' | '\'' | '·')
        {
            continue;
        }
        let c = match c {
            '\u{FF01}'..='\u{FF5E}' => {
                char::from_u32(c as u32 - 0xFEE0).unwrap_or(c).to_ascii_lowercase()
            }
            _ => c,
        };
        out.push(fold(c));
    }
    out.replace("rn", "m").replace("vv", "w")
}

fn fold(c: char) -> char {
    match c {
        // Cyrillic
        'а' => 'a',
        'в' => 'b',
        'е' | 'ё' | 'є' => 'e',
        'һ' | 'н' => 'h',
        'і' | 'ї' | 'ӏ' => 'l',
        'ј' => 'j',
        'к' => 'k',
        'м' => 'm',
        'о' => 'o',
        'р' => 'p',
        'ԛ' => 'q',
        'с' => 'c',
        'ѕ' => 's',
        'т' => 't',
        'у' => 'y',
        'х' => 'x',
        'ԁ' => 'd',
        'ԝ' => 'w',
        // Greek
        'α' => 'a',
        'β' => 'b',
        'ε' => 'e',
        'ζ' => 'z',
        'η' => 'n',
        'ι' => 'l',
        'κ' => 'k',
        'ν' => 'v',
        'ο' | 'σ' => 'o',
        'ρ' => 'p',
        'τ' => 't',
        'υ' => 'u',
        'χ' => 'x',
        'γ' => 'y',
        'ω' => 'w',
        // Latin and digits that pass for each other
        '0' => 'o',
        '1' | 'i' | '|' | '!' | 'ı' => 'l',
        _ => c,
    }
}

/// The first eight hex digits of an account id — how a client shows a member with no name.
pub fn short_id(user: &UserId) -> String {
    user.as_uuid().simple().to_string()[..8].to_string()
}

/// Twelve hex digits, shown beside a name that collides with another.
///
/// Longer than [`short_id`] because account ids are minted by clients, so anyone can grind
/// one whose first eight digits match somebody else's. Twelve makes that 2^48 work rather
/// than 2^32; neither is a substitute for the safety number, which is the actual check.
pub fn tag(user: &UserId) -> String {
    user.as_uuid().simple().to_string()[..12].to_string()
}

/// What to call one member, and whether that alone is enough to know who they are.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Label {
    pub text: String,
    /// Another member's name — or another member's id as shown — looks like this one. A
    /// client must show [`tag`] beside it.
    pub ambiguous: bool,
}

/// Label every member of a room. `name_of` gives each one's chosen name, if any.
///
/// Compared against every other member's *shown* label and against every other member's
/// short id — the second because ids appear on screen too, in membership notices and the
/// safety panel, and a name must not be able to pass for one there either.
pub fn labels<'a>(
    users: impl IntoIterator<Item = &'a UserId>,
    name_of: impl Fn(&UserId) -> Option<String>,
) -> HashMap<UserId, Label> {
    let users: Vec<UserId> = {
        let mut v: Vec<UserId> = users.into_iter().copied().collect();
        v.sort();
        v.dedup();
        v
    };
    let shown: Vec<(UserId, String, String)> = users
        .iter()
        .map(|u| {
            let text = name_of(u).unwrap_or_else(|| short_id(u));
            let skel = skeleton(&text);
            (*u, text, skel)
        })
        .collect();
    let ids: Vec<(UserId, String)> = users.iter().map(|u| (*u, skeleton(&short_id(u)))).collect();

    shown
        .iter()
        .map(|(u, text, skel)| {
            let ambiguous = shown.iter().any(|(v, _, other)| v != u && other == skel)
                || ids.iter().any(|(v, other)| v != u && other == skel);
            (*u, Label { text: text.clone(), ambiguous })
        })
        .collect()
}

// ---- views ----------------------------------------------------------------------

/// A profile image as a frontend sees it: something to ask for, never a key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageView {
    /// Changes whenever the image does, so a frontend can cache by it.
    pub id: String,
    pub mime: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusView {
    pub emoji: Option<String>,
    pub text: Option<String>,
    pub expires_at_ms: Option<i64>,
}

/// One member's profile in the open room, ready to draw.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileView {
    /// The full account id. **This, not the name, is who they are.**
    pub user: String,
    pub short_id: String,
    /// Shown beside `label` when `ambiguous`.
    pub tag: String,
    /// What to call them: room nickname, else display name, else `short_id`.
    pub label: String,
    /// Another member's name or id looks like this one's label.
    pub ambiguous: bool,
    pub display_name: Option<String>,
    pub nickname: Option<String>,
    pub pronouns: Option<String>,
    pub about: Option<String>,
    /// Omitted once expired, by this device's clock.
    pub status: Option<StatusView>,
    /// `#rrggbb`, top to bottom.
    pub colors: Option<[String; 2]>,
    pub avatar: Option<ImageView>,
    pub banner: Option<ImageView>,
    pub is_me: bool,
}

impl ProfileView {
    /// Build a view. `images` names the avatar and banner as a frontend should ask for them.
    pub fn of(
        user: &UserId,
        profile: Option<&Profile>,
        label: Option<&Label>,
        images: [Option<ImageView>; 2],
        is_me: bool,
        now_ms: i64,
    ) -> Self {
        let p = profile.cloned().unwrap_or_default();
        let [avatar, banner] = images;
        Self {
            user: user.to_string(),
            short_id: short_id(user),
            tag: tag(user),
            label: label.map_or_else(
                || p.name().map_or_else(|| short_id(user), str::to_owned),
                |l| l.text.clone(),
            ),
            ambiguous: label.is_some_and(|l| l.ambiguous),
            display_name: p.display_name,
            nickname: p.nickname,
            pronouns: p.pronouns,
            about: p.about,
            status: p
                .status
                .filter(|s| s.expires_at_ms.is_none_or(|at| at > now_ms))
                .filter(|s| s.emoji.is_some() || s.text.is_some())
                .map(|s| StatusView {
                    emoji: s.emoji,
                    text: s.text,
                    expires_at_ms: s.expires_at_ms,
                }),
            colors: p.colors.map(|[a, b]| [format_colour(a), format_colour(b)]),
            avatar,
            banner,
            is_me,
        }
    }
}

/// Which of a profile's two images.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImageSlot {
    Avatar,
    Banner,
}

// ---- storage ----------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum ProfileStoreError {
    #[error("profile store i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("stored profiles are corrupt: {0}")]
    Corrupt(#[from] serde_json::Error),
}

/// This account's own image, kept as plaintext so it can be sealed afresh for each room.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalImage {
    pub mime: String,
    pub size: usize,
}

/// This account's own profile, as set on this device.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Mine {
    /// Text fields only; images and nicknames are kept beside it.
    #[serde(default)]
    pub profile: Profile,
    #[serde(default)]
    pub nicknames: BTreeMap<RoomId, String>,
    #[serde(default)]
    pub avatar: Option<LocalImage>,
    #[serde(default)]
    pub banner: Option<LocalImage>,
    /// Bumped by every change. Zero means "never set", and nothing is sent.
    #[serde(default)]
    pub version: u64,
    /// Bumped only when an image changes, so re-sending text does not re-upload images.
    #[serde(default)]
    pub image_version: u64,
}

/// What was last sent into one room.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Sent {
    pub version: u64,
    pub image_version: u64,
    /// The sealed copies uploaded to this room, and the keys to them — reused when the
    /// profile is re-sent for a new member, so joining does not cost a re-upload.
    pub avatar: Option<Attachment>,
    pub banner: Option<Attachment>,
}

#[derive(Default, Serialize, Deserialize)]
struct File {
    #[serde(default)]
    mine: Mine,
    #[serde(default)]
    sent: BTreeMap<RoomId, Sent>,
    #[serde(default)]
    peers: BTreeMap<RoomId, BTreeMap<UserId, Profile>>,
}

/// Profiles under a client's state directory: this account's own, and the latest received
/// from each member of each room.
///
/// **Plaintext at `0600`**, beside the transcript and for the reason `crate::history` gives:
/// the group keys in the same directory already open far more. Like the transcript, it holds
/// attachment keys — here, to members' avatars.
pub struct ProfileStore {
    path: PathBuf,
    images: PathBuf,
    file: File,
}

impl std::fmt::Debug for ProfileStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProfileStore").field("path", &self.path).finish_non_exhaustive()
    }
}

impl ProfileStore {
    pub fn open(dir: impl AsRef<Path>) -> Result<Self, ProfileStoreError> {
        let dir = dir.as_ref();
        let path = dir.join("profiles.json");
        let images = dir.join("profile-images");
        std::fs::create_dir_all(&images)?;
        let file = match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => File::default(),
            Err(e) => return Err(e.into()),
        };
        Ok(Self { path, images, file })
    }

    fn save(&self) -> Result<(), ProfileStoreError> {
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec(&self.file)?)?;
        crate::history::restrict(&tmp).map_err(|e| match e {
            crate::history::HistoryError::Io(io) => ProfileStoreError::Io(io),
            crate::history::HistoryError::Corrupt(j) => ProfileStoreError::Corrupt(j),
        })?;
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }

    pub fn mine(&self) -> &Mine {
        &self.file.mine
    }

    /// Replace this account's text fields. Bumps the version, so every room is due.
    pub fn set_mine(&mut self, profile: Profile) -> Result<(), ProfileStoreError> {
        let mine = &mut self.file.mine;
        mine.profile = Profile {
            display_name: profile.display_name,
            pronouns: profile.pronouns,
            about: profile.about,
            colors: profile.colors,
            status: profile.status,
            ..Profile::default()
        };
        mine.version += 1;
        self.save()
    }

    pub fn set_nickname(
        &mut self,
        room: RoomId,
        nickname: Option<String>,
    ) -> Result<(), ProfileStoreError> {
        let mine = &mut self.file.mine;
        match nickname {
            Some(n) => mine.nicknames.insert(room, n),
            None => mine.nicknames.remove(&room),
        };
        mine.version += 1;
        self.save()
    }

    fn image_path(&self, slot: ImageSlot) -> PathBuf {
        self.images.join(match slot {
            ImageSlot::Avatar => "avatar",
            ImageSlot::Banner => "banner",
        })
    }

    /// Set or clear one of this account's images. The bytes are kept so each room gets its
    /// own sealed copy under its own key.
    pub fn set_image(
        &mut self,
        slot: ImageSlot,
        image: Option<(&[u8], &str)>,
    ) -> Result<(), ProfileStoreError> {
        let path = self.image_path(slot);
        let stored = match image {
            Some((bytes, mime)) => {
                std::fs::write(&path, bytes)?;
                crate::history::restrict(&path).map_err(|e| match e {
                    crate::history::HistoryError::Io(io) => ProfileStoreError::Io(io),
                    crate::history::HistoryError::Corrupt(j) => ProfileStoreError::Corrupt(j),
                })?;
                Some(LocalImage { mime: mime.to_string(), size: bytes.len() })
            }
            None => {
                let _ = std::fs::remove_file(&path);
                None
            }
        };
        let mine = &mut self.file.mine;
        match slot {
            ImageSlot::Avatar => mine.avatar = stored,
            ImageSlot::Banner => mine.banner = stored,
        }
        mine.version += 1;
        mine.image_version += 1;
        self.save()
    }

    /// This account's own image bytes.
    pub fn image(&self, slot: ImageSlot) -> Option<(Vec<u8>, String)> {
        let meta = match slot {
            ImageSlot::Avatar => self.file.mine.avatar.as_ref(),
            ImageSlot::Banner => self.file.mine.banner.as_ref(),
        }?;
        let bytes = std::fs::read(self.image_path(slot)).ok()?;
        Some((bytes, meta.mime.clone()))
    }

    /// The profile to send into `room`, minus images: the shared fields plus that room's
    /// nickname and nothing from any other room.
    pub fn outgoing(&self, room: &RoomId) -> Profile {
        let mine = &self.file.mine;
        Profile { nickname: mine.nicknames.get(room).cloned(), ..mine.profile.clone() }
    }

    /// Whether `room` has not yet been sent the current profile.
    pub fn due(&self, room: &RoomId) -> bool {
        let v = self.file.mine.version;
        v > 0 && self.file.sent.get(room).is_none_or(|s| s.version != v)
    }

    pub fn sent(&self, room: &RoomId) -> Option<&Sent> {
        self.file.sent.get(room)
    }

    pub fn record_sent(&mut self, room: RoomId, sent: Sent) -> Result<(), ProfileStoreError> {
        self.file.sent.insert(room, sent);
        self.save()
    }

    /// Forget what was sent to a room, so the next poll sends it again — for a new member,
    /// who cannot read anything sent before they joined.
    pub fn resend(&mut self, room: &RoomId) -> Result<(), ProfileStoreError> {
        if let Some(s) = self.file.sent.get_mut(room) {
            s.version = 0;
            self.save()?;
        }
        Ok(())
    }

    /// File a received profile under the member who sent it. Latest wins.
    pub fn receive(
        &mut self,
        room: RoomId,
        sender: UserId,
        profile: Profile,
    ) -> Result<(), ProfileStoreError> {
        self.file.peers.entry(room).or_default().insert(sender, profile);
        self.save()
    }

    pub fn peers(&self, room: &RoomId) -> Option<&BTreeMap<UserId, Profile>> {
        self.file.peers.get(room)
    }

    pub fn peer(&self, room: &RoomId, user: &UserId) -> Option<&Profile> {
        self.file.peers.get(room)?.get(user)
    }

    /// Drop everything about a room — this device was removed from it.
    pub fn forget(&mut self, room: &RoomId) -> Result<(), ProfileStoreError> {
        self.file.peers.remove(room);
        self.file.sent.remove(room);
        self.file.mine.nicknames.remove(room);
        self.save()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(n: &str) -> Profile {
        Profile { display_name: Some(n.into()), ..Profile::default() }
    }

    #[test]
    fn a_name_cannot_carry_a_text_direction_override() {
        // U+202E draws "alice" from bytes that say "ecila" — and, in a message line, can
        // reverse the text that follows the name too.
        for n in ["\u{202E}ecila", "al\u{2066}ice", "alice\u{200F}", "a\u{061C}lice"] {
            assert_eq!(
                name(n).validate(),
                Err(ProfileError::ForbiddenCharacter { field: "display name" }),
                "{n:?}"
            );
        }
    }

    #[test]
    fn a_name_cannot_hide_characters() {
        for n in ["ali\u{200B}ce", "\u{FEFF}alice", "alice\u{00AD}", "\u{3164}", "a\u{E000}"] {
            assert!(name(n).validate().is_err(), "{n:?} must be refused");
        }
        for n in ["ali\u{0000}ce", "ali\nce", "alice\u{2028}x", "a\tb"] {
            assert!(name(n).validate().is_err(), "{n:?} must be refused");
        }
    }

    #[test]
    fn a_name_is_bounded_and_trimmed() {
        assert!(name(&"x".repeat(MAX_NAME_CHARS)).validate().is_ok());
        assert_eq!(
            name(&"x".repeat(MAX_NAME_CHARS + 1)).validate(),
            Err(ProfileError::TooLong { field: "display name", max: MAX_NAME_CHARS })
        );
        assert!(name(" alice").validate().is_err());
        assert!(name("ali  ce").validate().is_err(), "double spaces pad one name into another");
        assert!(name("ali\u{2003}ce").validate().is_err(), "an em space is not a space");
        assert!(name(" ").validate().is_err());
        assert!(name("a\u{0301}\u{0301}\u{0301}").validate().is_err(), "no stacked marks");
        assert!(name("Zoë").validate().is_ok());
        assert!(name("José María").validate().is_ok());
    }

    #[test]
    fn a_name_cannot_pass_for_an_account_id() {
        let someone = UserId::new();
        for n in [
            short_id(&someone),
            someone.as_uuid().simple().to_string(),
            "usr_alice".into(),
            "dead beef".into(),
        ] {
            assert_eq!(
                name(&n).validate(),
                Err(ProfileError::LooksLikeId { field: "display name" }),
                "{n:?}"
            );
        }
        assert!(name("Ada").validate().is_ok(), "a short word made of hex letters is still a name");
        assert!(name("cafe bar").validate().is_ok());
    }

    #[test]
    fn a_name_cannot_mix_latin_with_a_lookalike_alphabet() {
        assert_eq!(
            name("\u{0410}lice").validate(),
            Err(ProfileError::MixedScript { field: "display name" }),
            "Cyrillic А with Latin lice"
        );
        assert!(name("Алиса").validate().is_ok(), "all-Cyrillic is a real name");
        assert!(name("Zoë 李").validate().is_ok());
        assert!(
            name("\u{1D400}lice").validate().is_err(),
            "styled letters exist to look like others"
        );
    }

    #[test]
    fn emoji_are_allowed_in_names() {
        assert!(name("Sam 👩\u{200D}💻").validate().is_ok());
        assert!(name("❤\u{FE0F} Kai").validate().is_ok());
    }

    #[test]
    fn about_me_allows_lines_but_not_too_many() {
        let p = Profile { about: Some("line one\nline two".into()), ..Profile::default() };
        assert!(p.validate().is_ok());
        let p = Profile { about: Some("x\n".repeat(MAX_ABOUT_LINES + 1)), ..Profile::default() };
        assert_eq!(p.validate(), Err(ProfileError::TooManyLines));
        let p = Profile { about: Some("x".repeat(MAX_ABOUT_CHARS + 1)), ..Profile::default() };
        assert!(p.validate().is_err());
        let p = Profile { about: Some("hi \u{202E}there".into()), ..Profile::default() };
        assert!(p.validate().is_err(), "a bio cannot reorder the card it sits in");
    }

    #[test]
    fn a_status_emoji_is_an_emoji() {
        let mut s = Status {
            emoji: Some("🎧".into()),
            text: Some("focusing".into()),
            expires_at_ms: Some(1),
        };
        assert!(Profile { status: Some(s.clone()), ..Profile::default() }.validate().is_ok());
        s.emoji = Some("lol".into());
        assert_eq!(
            Profile { status: Some(s), ..Profile::default() }.validate(),
            Err(ProfileError::BadEmoji)
        );
    }

    #[test]
    fn colours_parse_and_are_bounded() {
        assert_eq!(parse_colour("#5865f2"), Ok(0x5865F2));
        assert_eq!(parse_colour("5865F2"), Ok(0x5865F2));
        assert!(parse_colour("#5865f").is_err());
        assert!(parse_colour("red").is_err());
        let p = Profile { colors: Some([0x1000000, 0]), ..Profile::default() };
        assert_eq!(p.validate(), Err(ProfileError::BadColour));
    }

    #[test]
    fn lookalike_names_collide_under_the_skeleton() {
        assert_eq!(skeleton("Alice"), skeleton("alice"));
        assert_eq!(skeleton("Alice"), skeleton("AIice"), "capital I for l");
        assert_eq!(skeleton("Alice"), skeleton("Аlісе"), "Cyrillic");
        assert_eq!(skeleton("Alice"), skeleton("Ａｌｉｃｅ"), "fullwidth");
        assert_eq!(skeleton("Al ice"), skeleton("alice"));
        assert_eq!(skeleton("modern"), skeleton("rnodern"));
        assert_eq!(skeleton("B0B"), skeleton("bob"));
        assert_ne!(skeleton("alice"), skeleton("alicia"));
    }

    #[test]
    fn two_members_with_one_name_are_both_marked_ambiguous() {
        let (alice, mallory, carol) = (UserId::new(), UserId::new(), UserId::new());
        let names: HashMap<UserId, String> = [
            (alice, "Alice".to_string()),
            (mallory, "AIice".to_string()),
            (carol, "Carol".to_string()),
        ]
        .into();
        let labels = labels([&alice, &mallory, &carol], |u| names.get(u).cloned());
        assert!(
            labels[&alice].ambiguous,
            "the real one is flagged too: neither can be trusted by name"
        );
        assert!(labels[&mallory].ambiguous);
        assert!(!labels[&carol].ambiguous);
    }

    #[test]
    fn a_name_that_matches_another_members_short_id_is_ambiguous() {
        // Even though `validate` refuses hex names, labels are computed for profiles from
        // other clients too, so the check stands on its own.
        let (alice, mallory) = (UserId::new(), UserId::new());
        let fake = short_id(&alice);
        let labels = labels([&alice, &mallory], |u| (*u == mallory).then(|| fake.clone()));
        assert!(labels[&mallory].ambiguous);
        assert_eq!(labels[&alice].text, short_id(&alice), "no name: shown by id");
    }

    #[test]
    fn an_expired_status_is_not_shown() {
        let user = UserId::new();
        let p = Profile {
            status: Some(Status {
                emoji: None,
                text: Some("brb".into()),
                expires_at_ms: Some(1_000),
            }),
            ..Profile::default()
        };
        assert!(ProfileView::of(&user, Some(&p), None, [None, None], false, 999).status.is_some());
        assert!(ProfileView::of(&user, Some(&p), None, [None, None], false, 1_000)
            .status
            .is_none());
    }

    #[test]
    fn a_nickname_goes_only_to_its_own_room() {
        let dir = std::env::temp_dir().join(format!("cairn-profile-nick-{}", uuid::Uuid::new_v4()));
        let mut store = ProfileStore::open(&dir).unwrap();
        let (support, work) = (RoomId::new(), RoomId::new());
        store.set_mine(name("Sam")).unwrap();
        store.set_nickname(support, Some("S".into())).unwrap();
        assert_eq!(store.outgoing(&support).nickname.as_deref(), Some("S"));
        assert_eq!(store.outgoing(&work).nickname, None, "another room must never learn it");
        assert_eq!(store.outgoing(&work).display_name.as_deref(), Some("Sam"));

        // And it survives a restart.
        let store = ProfileStore::open(&dir).unwrap();
        assert_eq!(store.outgoing(&support).nickname.as_deref(), Some("S"));
    }
}
