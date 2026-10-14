//! A room's custom emoji, stickers and soundboard clips — distributed as a set, up front,
//! inside the encrypted stream, and rendered from this device's own cache.
//!
//! ## The leak this shape exists to avoid
//!
//! The obvious design — a message says `:blobsad:`, the client fetches
//! `/emojis/blobsad.webp` to draw it — tells the instance **which emoji was used and when**,
//! from the fetch, even though it cannot read the message (`docs/13-customisation.md` §3).
//! A rare emoji is close to a fingerprint, and a reaction narrows it further.
//!
//! So fetching is decoupled from rendering:
//!
//! - A room's set is a [`CustomSet`] record carried **inside an ordinary MLS-encrypted
//!   message**, like a profile (ADR-010). Each image or clip is an encrypted attachment in
//!   the room's blob store, sealed under its own single-use key, the key inside the record.
//! - When a new set is accepted, **every asset in it** that this device does not already hold
//!   is downloaded at once ([`missing`]) — not on first use. A lazily fetched new emoji would
//!   reintroduce exactly the leak.
//! - Drawing an emoji, a sticker or playing a clip reads this device's cache and nothing
//!   else. There is no code path from rendering to the network.
//!
//! What the instance learns: that a message of some size was sent, that blobs were uploaded,
//! and that each member downloaded those blobs shortly after — i.e. "the set changed". Not
//! which names, not which images, and nothing at the moment one is used.
//!
//! ## Who may change the set
//!
//! The instance cannot read the record, so it cannot enforce anything about it; every
//! recipient does, on receipt. A set is accepted only from a sender the **instance's member
//! list** names as `owner` or `moderator` ([`may_edit`]). That role list is the instance's
//! word — roles are instance state, not part of the encrypted group — so **a malicious
//! instance can grant a member the right to change the set**. It still cannot write a set
//! itself: the record is inside MLS ciphertext, and its sender is checked against the
//! group's roster before it is decrypted. See `docs/13-customisation.md` §3a.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use cairn_proto::{BlobId, RoomId, UserId};

use crate::conversation::Attachment;

/// Most custom emoji in one room.
pub const MAX_EMOJI: usize = 100;
/// Most stickers in one room.
pub const MAX_STICKERS: usize = 40;
/// Most soundboard clips in one room.
pub const MAX_SOUNDS: usize = 24;
/// Largest emoji image, plaintext bytes.
pub const MAX_EMOJI_BYTES: usize = 256 * 1024;
/// Largest sticker image, plaintext bytes.
pub const MAX_STICKER_BYTES: usize = 512 * 1024;
/// Largest soundboard clip, plaintext bytes.
pub const MAX_SOUND_BYTES: usize = 512 * 1024;
/// Longest soundboard clip. Checked here for WAV and Ogg; every client also stops playback
/// at this length whatever the file says, which is the check that cannot be talked around.
pub const MAX_SOUND_MS: u64 = 5_000;
/// The whole set, in plaintext bytes. **Every member downloads all of it**, so this is the
/// cost of joining a room, multiplied by its membership.
pub const MAX_SET_BYTES: usize = 16 * 1024 * 1024;
/// Shortest and longest name, in characters.
pub const NAME_CHARS: std::ops::RangeInclusive<usize> = 2..=32;

/// Image types an emoji or sticker may be. Raster only — no SVG, for the reason
/// `session::attachments` gives.
pub const IMAGE_TYPES: &[&str] = &["image/png", "image/gif", "image/webp"];
/// Audio types a clip may be. Opus travels in Ogg.
pub const SOUND_TYPES: &[&str] = &["audio/ogg", "audio/mpeg", "audio/wav"];

/// What an item is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Emoji,
    Sticker,
    Sound,
}

impl Kind {
    pub const fn max_bytes(self) -> usize {
        match self {
            Self::Emoji => MAX_EMOJI_BYTES,
            Self::Sticker => MAX_STICKER_BYTES,
            Self::Sound => MAX_SOUND_BYTES,
        }
    }

    pub const fn max_items(self) -> usize {
        match self {
            Self::Emoji => MAX_EMOJI,
            Self::Sticker => MAX_STICKERS,
            Self::Sound => MAX_SOUNDS,
        }
    }

    pub const fn types(self) -> &'static [&'static str] {
        match self {
            Self::Emoji | Self::Sticker => IMAGE_TYPES,
            Self::Sound => SOUND_TYPES,
        }
    }

    const fn noun(self) -> &'static str {
        match self {
            Self::Emoji => "emoji",
            Self::Sticker => "stickers",
            Self::Sound => "sounds",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CustomError {
    #[error(
        "a name is 2 to 32 characters of lowercase letters, digits and underscores, \
         like :party_parrot:"
    )]
    BadName,
    #[error("this room already has one called :{0}:")]
    Taken(String),
    #[error("this room has no {0} called that")]
    NoSuchItem(&'static str),
    #[error("a room can hold at most {max} {noun}")]
    TooMany { noun: &'static str, max: usize },
    #[error("that file is {size} bytes; {noun} are limited to {} KiB", max / 1024)]
    TooLarge { noun: &'static str, size: usize, max: usize },
    #[error("the room's whole set is limited to {} MiB, because every member downloads all of it", MAX_SET_BYTES / (1024 * 1024))]
    SetTooLarge,
    #[error("that file is empty")]
    Empty,
    #[error("emoji and stickers must be PNG, GIF or WebP; sounds must be Ogg/Opus, MP3 or WAV")]
    BadType,
    #[error("sounds are limited to {} seconds", MAX_SOUND_MS / 1000)]
    TooLong,
    #[error("only the room's owner and moderators can change its emoji, stickers and sounds")]
    NotPermitted,
}

/// One emoji, sticker or clip, and the key to its bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Item {
    pub kind: Kind,
    /// Without colons. See [`valid_name`].
    pub name: String,
    /// The sealed bytes in the room's blob store, with the key. `asset.mime` is the type
    /// sniffed from the bytes on the uploader's device, and re-checked on download here.
    pub asset: Attachment,
}

/// A room's whole set. Replaces the previous one entirely; there are no per-item updates,
/// because a per-item update is the lazily fetched emoji the module note rules out.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CustomSet {
    pub items: Vec<Item>,
}

impl CustomSet {
    /// Every limit, checked by the sender before sending and by every recipient on receipt.
    /// One bad item drops the whole record: a set is one decision by one admin.
    pub fn validate(&self) -> Result<(), CustomError> {
        let mut total = 0usize;
        let mut seen = std::collections::BTreeSet::new();
        for kind in [Kind::Emoji, Kind::Sticker, Kind::Sound] {
            let n = self.items.iter().filter(|i| i.kind == kind).count();
            if n > kind.max_items() {
                return Err(CustomError::TooMany { noun: kind.noun(), max: kind.max_items() });
            }
        }
        for item in &self.items {
            if !valid_name(&item.name) {
                return Err(CustomError::BadName);
            }
            if !seen.insert((item.kind, item.name.as_str())) {
                return Err(CustomError::Taken(item.name.clone()));
            }
            let mime = item.asset.mime.as_deref().unwrap_or("");
            if !item.kind.types().contains(&mime) {
                return Err(CustomError::BadType);
            }
            if item.asset.size == 0 {
                return Err(CustomError::Empty);
            }
            if item.asset.size > item.kind.max_bytes() {
                return Err(CustomError::TooLarge {
                    noun: item.kind.noun(),
                    size: item.asset.size,
                    max: item.kind.max_bytes(),
                });
            }
            total = total.saturating_add(item.asset.size);
        }
        if total > MAX_SET_BYTES {
            return Err(CustomError::SetTooLarge);
        }
        Ok(())
    }

    pub fn find(&self, kind: Kind, name: &str) -> Option<&Item> {
        self.items.iter().find(|i| i.kind == kind && i.name == name)
    }

    pub fn bytes(&self) -> usize {
        self.items.iter().map(|i| i.asset.size).sum()
    }
}

/// `[a-z0-9_]`, 2–32 characters. ASCII only so `:name:` can never be a lookalike of another
/// name, and lowercase so one name has one spelling.
pub fn valid_name(name: &str) -> bool {
    NAME_CHARS.contains(&name.len())
        && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// Turn what someone typed or a filename into a name, or say why it cannot be one.
/// `Party Parrot!.gif` becomes `party_parrot`.
pub fn sanitize_name(raw: &str) -> Result<String, CustomError> {
    let raw = raw.trim().trim_matches(':');
    let stem = match raw.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() && ext.len() <= 4 => stem,
        _ => raw,
    };
    let mut out = String::new();
    for c in stem.chars() {
        let c = c.to_ascii_lowercase();
        if c.is_ascii_lowercase() || c.is_ascii_digit() {
            out.push(c);
        } else if !out.ends_with('_') {
            out.push('_');
        }
    }
    let out: String = out.trim_matches('_').chars().take(*NAME_CHARS.end()).collect();
    let out = out.trim_end_matches('_').to_string();
    if valid_name(&out) {
        Ok(out)
    } else {
        Err(CustomError::BadName)
    }
}

/// Whether the instance's word for a role lets its holder change a room's set.
pub fn may_edit(role: &str) -> bool {
    matches!(role, "owner" | "moderator")
}

/// The type the bytes actually are, from their first bytes — never from a filename or a
/// sender's claim. `None` for anything that is not one of the allowed types.
pub fn sniff(bytes: &[u8]) -> Option<&'static str> {
    let starts = |sig: &[u8]| bytes.len() >= sig.len() && &bytes[..sig.len()] == sig;
    let riff = |form: &[u8; 4]| starts(b"RIFF") && bytes.len() >= 12 && &bytes[8..12] == form;
    if starts(b"\x89PNG\r\n\x1a\n") {
        Some("image/png")
    } else if starts(b"GIF87a") || starts(b"GIF89a") {
        Some("image/gif")
    } else if riff(b"WEBP") {
        Some("image/webp")
    } else if riff(b"WAVE") {
        Some("audio/wav")
    } else if starts(b"OggS") {
        Some("audio/ogg")
    } else if starts(b"ID3") || (bytes.len() >= 2 && bytes[0] == 0xFF && bytes[1] & 0xE0 == 0xE0) {
        Some("audio/mpeg")
    } else {
        None
    }
}

/// Check bytes for an item of `kind`, returning their real type.
///
/// The same check runs before upload and after every download: the uploader's claim of a
/// type is theirs to make, and this device only ever hands a webview bytes whose type it
/// established itself.
pub fn check_asset(kind: Kind, bytes: &[u8]) -> Result<&'static str, CustomError> {
    if bytes.is_empty() {
        return Err(CustomError::Empty);
    }
    if bytes.len() > kind.max_bytes() {
        return Err(CustomError::TooLarge {
            noun: kind.noun(),
            size: bytes.len(),
            max: kind.max_bytes(),
        });
    }
    let mime = sniff(bytes).filter(|m| kind.types().contains(m)).ok_or(CustomError::BadType)?;
    if kind == Kind::Sound && duration_ms(mime, bytes).is_some_and(|ms| ms > MAX_SOUND_MS) {
        return Err(CustomError::TooLong);
    }
    Ok(mime)
}

/// A clip's length, where the container states it cheaply: WAV from its header, Ogg from
/// the last page's granule position. `None` for MP3, whose length needs a decoder — the UI
/// measures it before upload, and playback stops at [`MAX_SOUND_MS`] regardless.
pub fn duration_ms(mime: &str, bytes: &[u8]) -> Option<u64> {
    match mime {
        "audio/wav" => wav_duration_ms(bytes),
        "audio/ogg" => ogg_duration_ms(bytes),
        _ => None,
    }
}

fn u32_le(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

fn wav_duration_ms(b: &[u8]) -> Option<u64> {
    let mut at = 12;
    let mut byte_rate = None;
    while at + 8 <= b.len() {
        let id = &b[at..at + 4];
        let len = u32_le(b, at + 4)? as usize;
        if id == b"fmt " {
            byte_rate = u32_le(b, at + 16);
        } else if id == b"data" {
            let rate = u64::from(byte_rate.filter(|r| *r > 0)?);
            // A streaming writer leaves the data length as 0xFFFFFFFF; measure what is there.
            let len = len.min(b.len().saturating_sub(at + 8)) as u64;
            return Some(len * 1000 / rate);
        }
        at = at.checked_add(8 + len + (len & 1))?;
    }
    None
}

fn ogg_duration_ms(b: &[u8]) -> Option<u64> {
    let find = |needle: &[u8]| b.windows(needle.len()).position(|w| w == needle);
    let rate = if find(b"OpusHead").is_some() {
        48_000u64
    } else {
        let at = find(b"\x01vorbis")?;
        u64::from(u32_le(b, at + 12)?)
    };
    if rate == 0 {
        return None;
    }
    // The last page header's absolute granule position is the stream's length in samples.
    let last = b.windows(4).rposition(|w| w == b"OggS")?;
    let granule = i64::from_le_bytes(b.get(last + 6..last + 14)?.try_into().ok()?);
    u64::try_from(granule).ok().map(|g| g * 1000 / rate)
}

// ---- storage ---------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum CustomStoreError {
    #[error("custom emoji storage i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("stored custom emoji are corrupt: {0}")]
    Corrupt(#[from] serde_json::Error),
}

impl From<crate::history::HistoryError> for CustomStoreError {
    fn from(e: crate::history::HistoryError) -> Self {
        match e {
            crate::history::HistoryError::Io(io) => Self::Io(io),
            crate::history::HistoryError::Corrupt(j) => Self::Corrupt(j),
        }
    }
}

/// A set, and where it came from.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Accepted {
    pub set: CustomSet,
    /// The admin whose message carried it — the envelope's sender, never a field inside.
    pub from: UserId,
    /// The instance's sequence number for that message, so a set held back for a role check
    /// cannot overwrite a later one when it is finally accepted. For this device's own set,
    /// one past everything it had seen when it sent it.
    pub seq: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct RoomCustom {
    #[serde(default)]
    current: Option<Accepted>,
    /// Sets from senders whose role was not known to allow it when they arrived — kept until
    /// roles are next read, so an admin promoted a moment ago is not ignored, then applied or
    /// dropped. See [`CustomStore::release`].
    #[serde(default)]
    held: BTreeMap<UserId, Accepted>,
    /// This device should send `current` into the room — someone joined, who cannot read
    /// anything sent before they did.
    #[serde(default)]
    due: bool,
}

#[derive(Default, Serialize, Deserialize)]
struct File {
    #[serde(default)]
    rooms: BTreeMap<RoomId, RoomCustom>,
}

/// Each room's accepted set, plus a cache of the decrypted assets.
///
/// **Plaintext at `0600`**, beside the transcript, for the reason `crate::history` gives;
/// it holds attachment keys as the transcript does.
pub struct CustomStore {
    path: PathBuf,
    cache: PathBuf,
    file: File,
}

impl std::fmt::Debug for CustomStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CustomStore").field("path", &self.path).finish_non_exhaustive()
    }
}

impl CustomStore {
    pub fn open(dir: impl AsRef<Path>) -> Result<Self, CustomStoreError> {
        let dir = dir.as_ref();
        let path = dir.join("custom.json");
        let cache = dir.join("custom-assets");
        std::fs::create_dir_all(&cache)?;
        let file = match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => File::default(),
            Err(e) => return Err(e.into()),
        };
        Ok(Self { path, cache, file })
    }

    fn save(&self) -> Result<(), CustomStoreError> {
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec(&self.file)?)?;
        crate::history::restrict(&tmp)?;
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }

    pub fn current(&self, room: &RoomId) -> Option<&Accepted> {
        self.file.rooms.get(room)?.current.as_ref()
    }

    /// Install a set. Later-sequenced wins; an earlier one (a held set accepted late) is
    /// dropped. Returns whether `current` changed.
    pub fn accept(&mut self, room: RoomId, accepted: Accepted) -> Result<bool, CustomStoreError> {
        let entry = self.file.rooms.entry(room).or_default();
        entry.held.remove(&accepted.from);
        if entry.current.as_ref().is_some_and(|c| c.seq > accepted.seq) {
            self.save()?;
            return Ok(false);
        }
        entry.current = Some(accepted);
        self.save()?;
        self.collect()?;
        Ok(true)
    }

    /// Keep a set whose sender's role is not yet known to allow it. Latest per sender.
    pub fn hold(&mut self, room: RoomId, accepted: Accepted) -> Result<(), CustomStoreError> {
        self.file.rooms.entry(room).or_default().held.insert(accepted.from, accepted);
        self.save()
    }

    /// Check held sets against roles just read from the instance — once. A sender permitted
    /// now has their set applied (unless a later one is in force); a sender still not
    /// permitted has it **dropped**, so a set sent by a plain member cannot spring into force
    /// weeks later because they were promoted for some other reason. Returns whether
    /// `current` changed.
    pub fn release(
        &mut self,
        room: RoomId,
        permitted: impl Fn(&UserId) -> bool,
    ) -> Result<bool, CustomStoreError> {
        let Some(entry) = self.file.rooms.get_mut(&room) else { return Ok(false) };
        if entry.held.is_empty() {
            return Ok(false);
        }
        let held = std::mem::take(&mut entry.held);
        let mut ready: Vec<Accepted> = held.into_values().filter(|a| permitted(&a.from)).collect();
        self.save()?;
        let mut changed = false;
        ready.sort_by_key(|a| a.seq);
        for a in ready {
            changed |= self.accept(room, a)?;
        }
        Ok(changed)
    }

    pub fn mark_due(&mut self, room: &RoomId) -> Result<(), CustomStoreError> {
        if let Some(entry) = self.file.rooms.get_mut(room) {
            if entry.current.is_some() && !entry.due {
                entry.due = true;
                self.save()?;
            }
        }
        Ok(())
    }

    pub fn due(&self, room: &RoomId) -> bool {
        self.file.rooms.get(room).is_some_and(|r| r.due && r.current.is_some())
    }

    pub fn clear_due(&mut self, room: &RoomId) -> Result<(), CustomStoreError> {
        if let Some(entry) = self.file.rooms.get_mut(room) {
            entry.due = false;
            self.save()?;
        }
        Ok(())
    }

    /// Drop everything about a room — this device was removed from it.
    pub fn forget(&mut self, room: &RoomId) -> Result<(), CustomStoreError> {
        self.file.rooms.remove(room);
        self.save()?;
        self.collect()
    }

    fn cached_path(&self, blob: &BlobId) -> PathBuf {
        self.cache.join(blob.to_string())
    }

    /// The directory a [`missing`] download writes into.
    pub fn cache_dir(&self) -> &Path {
        &self.cache
    }

    pub fn is_cached(&self, blob: &BlobId) -> bool {
        self.cached_path(blob).is_file()
    }

    /// Bytes from the cache, and **only** from the cache. Never a network call: this is
    /// what drawing an emoji costs.
    pub fn cached(&self, blob: &BlobId) -> Option<Vec<u8>> {
        std::fs::read(self.cached_path(blob)).ok()
    }

    /// Put bytes this device already holds — its own upload — straight into the cache.
    pub fn put(&self, blob: &BlobId, bytes: &[u8]) -> Result<(), CustomStoreError> {
        write_cached(&self.cache, blob, bytes)
    }

    /// Delete cached assets no room's set refers to any more.
    fn collect(&self) -> Result<(), CustomStoreError> {
        let live: std::collections::HashSet<String> = self
            .file
            .rooms
            .values()
            .flat_map(|r| r.current.iter().chain(r.held.values()))
            .flat_map(|a| a.set.items.iter().map(|i| i.asset.blob.to_string()))
            .collect();
        for entry in std::fs::read_dir(&self.cache)?.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if !live.contains(&name) {
                let _ = std::fs::remove_file(entry.path());
            }
        }
        Ok(())
    }
}

pub(crate) fn write_cached(
    dir: &Path,
    blob: &BlobId,
    bytes: &[u8],
) -> Result<(), CustomStoreError> {
    let path = dir.join(blob.to_string());
    let tmp = dir.join(format!("{blob}.tmp"));
    std::fs::write(&tmp, bytes)?;
    crate::history::restrict(&tmp)?;
    std::fs::rename(&tmp, &path)?;
    Ok(())
}

/// The assets of `set` this device does not hold yet. All of them are fetched when the set
/// is accepted, whether or not anyone has used them — see the module note.
pub fn missing(store: &CustomStore, set: &CustomSet) -> Vec<Item> {
    set.items.iter().filter(|i| !store.is_cached(&i.asset.blob)).cloned().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const PNG: &[u8] = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR";

    fn item(kind: Kind, name: &str, mime: &str, size: usize) -> Item {
        let (key, _) = cairn_crypto::attachment::seal(b"x");
        Item {
            kind,
            name: name.into(),
            asset: Attachment {
                blob: BlobId::new(),
                key,
                name: name.into(),
                size,
                mime: Some(mime.into()),
            },
        }
    }

    #[test]
    fn a_name_is_lowercase_ascii_so_it_cannot_be_a_lookalike() {
        for good in ["ok", "party_parrot", "a1", &"x".repeat(32)] {
            assert!(valid_name(good), "{good}");
        }
        for bad in ["a", "Party", "pаrty", "a-b", "a b", ":ok:", "", &"x".repeat(33), "ok\u{200b}"]
        {
            assert!(!valid_name(bad), "{bad:?}");
        }
        assert_eq!(sanitize_name("Party Parrot!.gif").unwrap(), "party_parrot");
        assert_eq!(sanitize_name(":blob_sad:").unwrap(), "blob_sad");
        assert_eq!(sanitize_name("  --Hi--  ").unwrap(), "hi");
        assert!(sanitize_name("é").is_err());
        assert!(sanitize_name("!!!").is_err());
    }

    #[test]
    fn a_set_over_any_limit_is_refused_whole() {
        let ok = CustomSet { items: vec![item(Kind::Emoji, "ok", "image/png", 10)] };
        assert!(ok.validate().is_ok());
        let cases = [
            item(Kind::Emoji, "big", "image/png", MAX_EMOJI_BYTES + 1),
            item(Kind::Emoji, "svg", "image/svg+xml", 10),
            item(Kind::Sound, "img", "image/png", 10),
            item(Kind::Emoji, "Bad", "image/png", 10),
            item(Kind::Emoji, "ok", "image/png", 10), // duplicate name
        ];
        for bad in cases {
            let mut set = ok.clone();
            set.items.push(bad);
            assert!(set.validate().is_err());
        }
        let many = CustomSet {
            items: (0..=MAX_SOUNDS)
                .map(|n| item(Kind::Sound, &format!("s{n}"), "audio/ogg", 10))
                .collect(),
        };
        assert!(matches!(many.validate(), Err(CustomError::TooMany { .. })));
        // An emoji and a sticker may share a name: `:wave:` and the wave sticker.
        let shared = CustomSet {
            items: vec![
                item(Kind::Emoji, "wave", "image/png", 1),
                item(Kind::Sticker, "wave", "image/png", 1),
            ],
        };
        assert!(shared.validate().is_ok());
    }

    #[test]
    fn the_type_comes_from_the_bytes_not_the_claim() {
        assert_eq!(check_asset(Kind::Emoji, PNG), Ok("image/png"));
        assert_eq!(check_asset(Kind::Emoji, b"<svg onload=x>"), Err(CustomError::BadType));
        assert_eq!(check_asset(Kind::Emoji, b"OggS\0\0"), Err(CustomError::BadType));
        assert_eq!(check_asset(Kind::Sound, PNG), Err(CustomError::BadType));
        assert_eq!(check_asset(Kind::Sound, b"ID3\x04"), Ok("audio/mpeg"));
        assert_eq!(check_asset(Kind::Emoji, b""), Err(CustomError::Empty));
    }

    fn wav(seconds: u32) -> Vec<u8> {
        let rate = 8_000u32;
        let data = rate * seconds;
        let mut b = Vec::new();
        b.extend_from_slice(b"RIFF");
        b.extend_from_slice(&(36 + data).to_le_bytes());
        b.extend_from_slice(b"WAVEfmt ");
        b.extend_from_slice(&16u32.to_le_bytes());
        b.extend_from_slice(&1u16.to_le_bytes()); // PCM
        b.extend_from_slice(&1u16.to_le_bytes()); // mono
        b.extend_from_slice(&rate.to_le_bytes());
        b.extend_from_slice(&rate.to_le_bytes()); // byte rate, 8-bit mono
        b.extend_from_slice(&1u16.to_le_bytes());
        b.extend_from_slice(&8u16.to_le_bytes());
        b.extend_from_slice(b"data");
        b.extend_from_slice(&data.to_le_bytes());
        b.resize(b.len() + data as usize, 128);
        b
    }

    #[test]
    fn a_clip_longer_than_five_seconds_is_refused() {
        assert_eq!(check_asset(Kind::Sound, &wav(2)), Ok("audio/wav"));
        assert_eq!(duration_ms("audio/wav", &wav(2)), Some(2_000));
        assert_eq!(check_asset(Kind::Sound, &wav(6)), Err(CustomError::TooLong));
    }

    #[test]
    fn an_ogg_opus_clip_is_measured_from_its_last_page() {
        let page = |granule: i64| {
            let mut p = b"OggS\0\0".to_vec();
            p.extend_from_slice(&granule.to_le_bytes());
            p.extend_from_slice(&[0u8; 14]);
            p
        };
        let mut ogg = page(0);
        ogg.extend_from_slice(b"OpusHead\x01\x01");
        ogg.extend(page(48_000 * 3));
        assert_eq!(duration_ms("audio/ogg", &ogg), Some(3_000));
        let mut long = page(0);
        long.extend_from_slice(b"OpusHead");
        long.extend(page(48_000 * 9));
        assert_eq!(check_asset(Kind::Sound, &long), Err(CustomError::TooLong));
    }

    #[test]
    fn a_held_set_never_overwrites_a_later_one() {
        let dir = std::env::temp_dir().join(format!("cairn-custom-{}", uuid::Uuid::new_v4()));
        let mut store = CustomStore::open(&dir).unwrap();
        let room = RoomId::new();
        let (a, b) = (UserId::new(), UserId::new());
        let set = |name: &str| CustomSet { items: vec![item(Kind::Emoji, name, "image/png", 1)] };
        store.hold(room, Accepted { set: set("early"), from: b, seq: 5 }).unwrap();
        store.accept(room, Accepted { set: set("later"), from: a, seq: 9 }).unwrap();
        assert!(!store.release(room, |u| *u == b).unwrap());
        assert_eq!(store.current(&room).unwrap().set.items[0].name, "later");
        // A sender not permitted when roles are next read has their set dropped — it does
        // not wait around for a promotion that would bring it into force later.
        store.hold(room, Accepted { set: set("nope"), from: b, seq: 12 }).unwrap();
        assert!(!store.release(room, |_| false).unwrap());
        assert!(!store.release(room, |_| true).unwrap(), "already dropped");
        assert_eq!(store.current(&room).unwrap().set.items[0].name, "later");
        let _ = std::fs::remove_dir_all(dir);
    }
}
