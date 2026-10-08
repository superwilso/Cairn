//! Files, photos and voice notes, for a frontend that must never hold a key.
//!
//! ## The shape
//!
//! Sending is **seal → upload → send**: the bytes are sealed under a fresh key on this
//! device, the ciphertext goes to the room's blob store, and the key travels inside the
//! encrypted message that refers to it ([`Conversation::send_with_attachment`]). Receiving
//! is the reverse, and the key never leaves Rust: a frontend gets an [`AttachmentView`] —
//! an id, a name, a size, a type — and asks for the plaintext *by id*.
//!
//! That last part is the boundary worth stating. A frontend cannot hand this module a key,
//! and cannot name an arbitrary blob: [`Session::prepare_download`] only fetches attachments
//! this session has itself seen inside an encrypted message in the open room. The UI can
//! ask for "the photo in that message", never for "blob X with key Y".
//!
//! ## Why the three steps are separate methods
//!
//! The desktop shell keeps the [`Session`] behind a mutex, because MLS state must not be
//! mutated from two places at once. Uploading 25 MiB over a home connection takes as long
//! as it takes, and holding that lock for the duration would stop polling — no messages, no
//! call signalling — until it finished. So sealing and sending (which touch MLS state) are
//! short calls on the session, and the transfer in between runs on a clone of the network
//! client ([`PendingUpload::upload`], [`PendingDownload::fetch`]) with no lock held.
//! [`Session::send_file`] and [`Session::fetch_attachment`] compose them for callers that do
//! not care.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use cairn_crypto::attachment::AttachmentKey;
use cairn_proto::{BlobId, RoomId};

use super::{now_ms, view, MessageView, Session, SessionError};
use crate::client::Client;
use crate::conversation::Attachment;
use crate::history::Entry as HistoryEntry;
use crate::transport::HttpTransport;

/// What sealing adds to a file: a 24-byte XChaCha20 nonce in front, a 16-byte Poly1305 tag
/// behind. Asserted against [`cairn_crypto::attachment::seal`] in the tests below, so it
/// cannot drift from the real thing silently.
pub const SEAL_OVERHEAD: usize = 24 + 16;

/// The largest file this client will try to send.
///
/// The instance's ceiling (`cairn_server::state::MAX_BLOB_BYTES`, 25 MiB) applies to what
/// it *stores*, which is ciphertext — so the plaintext limit is that minus the seal. A
/// client that checked the plaintext against 25 MiB would accept a file of exactly 25 MiB,
/// upload it, and have the instance refuse it 40 bytes over.
///
/// **A courtesy, not the rule.** The instance enforces its own limit whatever a client
/// believes, and an operator's instance may differ from this build's. Checking here means a
/// person is told before waiting on an upload that was always going to fail.
pub const MAX_ATTACHMENT_BYTES: usize = 25 * 1024 * 1024 - SEAL_OVERHEAD;

/// How a frontend should present an attachment.
///
/// Decided here rather than in the UI because the input is a sender's *claim*: `kind` is
/// what this client is prepared to act on, not what the sender said.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttachmentKind {
    /// A raster format a webview decodes as an image and nothing else. Shown inline.
    Image,
    /// An audio format a webview plays. Shown as a player — this is what a voice note is.
    Audio,
    /// Everything else, including every type nobody named. Offered as a download.
    File,
}

/// An attachment as a frontend sees it. **No key** — fetch the bytes by `id`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttachmentView {
    /// The blob id. Not secret: the instance minted it and stores the ciphertext under it.
    pub id: String,
    /// The sender's claimed filename. A label to show, never a path.
    pub name: String,
    /// The sender's claimed plaintext size, for display before the bytes arrive.
    pub size: usize,
    /// The claimed media type, normalised: anything unreadable becomes
    /// `application/octet-stream`.
    pub mime: String,
    pub kind: AttachmentKind,
}

impl AttachmentView {
    pub(super) fn of(attachment: &Attachment) -> Self {
        let mime = normalize_mime(attachment.mime.as_deref());
        Self {
            id: attachment.blob.to_string(),
            name: attachment.name.clone(),
            size: attachment.size,
            kind: kind_of(&mime),
            mime,
        }
    }
}

/// Raster image types a webview will only ever *decode*.
///
/// SVG is deliberately absent. An `<img>` does not run an SVG's scripts, so this is not
/// closing a hole that is open today — it is declining to make "the sender said image"
/// sufficient for a format that is a document with a scripting model. A sender who wants an
/// SVG seen can send it; it arrives as a file.
const INLINE_IMAGES: &[&str] = &["image/png", "image/jpeg", "image/gif", "image/webp"];

/// Audio types a webview's `<audio>` element plays. `audio/webm` and `audio/ogg` are what
/// `MediaRecorder` produces in Chromium-based webviews; `audio/mp4` is WebKit's.
const PLAYABLE_AUDIO: &[&str] = &[
    "audio/webm",
    "audio/ogg",
    "audio/mp4",
    "audio/mpeg",
    "audio/aac",
    "audio/wav",
    "audio/x-wav",
];

/// A sender's media type, reduced to something safe to hand a `Blob` constructor.
///
/// It is printable ASCII of a sane length with a `/` in it, or it is
/// `application/octet-stream`. Parameters (`;codecs=opus`) are kept, because a recorder's
/// type needs them to play back.
pub fn normalize_mime(claimed: Option<&str>) -> String {
    const UNKNOWN: &str = "application/octet-stream";
    let Some(raw) = claimed else { return UNKNOWN.into() };
    let mime = raw.trim().to_ascii_lowercase();
    let printable = mime.bytes().all(|b| b.is_ascii_graphic() || b == b' ');
    let (base, _) = mime.split_once(';').unwrap_or((&mime, ""));
    let shaped = base.split_once('/').is_some_and(|(t, s)| !t.is_empty() && !s.trim().is_empty());
    if printable && shaped && mime.len() <= 127 {
        mime
    } else {
        UNKNOWN.into()
    }
}

/// How to present a (normalised) media type. Only the base type counts.
pub fn kind_of(mime: &str) -> AttachmentKind {
    let base = mime.split(';').next().unwrap_or("").trim();
    if INLINE_IMAGES.contains(&base) {
        AttachmentKind::Image
    } else if PLAYABLE_AUDIO.contains(&base) {
        AttachmentKind::Audio
    } else {
        AttachmentKind::File
    }
}

/// A sender's filename, made safe to create inside a directory of this device's choosing.
///
/// The name arrived inside a message and was chosen by whoever sent it, so it is treated as
/// hostile: only its last path component survives, separators and characters Windows
/// refuses are replaced, leading dots go (no hidden files, no `..`), it is bounded in
/// length, and a reserved Windows device name gets a prefix. What comes out may still be
/// ugly; it cannot point anywhere but the directory it is joined to.
pub fn safe_file_name(claimed: &str) -> String {
    let last = claimed.rsplit(['/', '\\']).next().unwrap_or("");
    let mut cleaned: String = last
        .chars()
        .map(|c| if c.is_control() || "<>:\"/\\|?*".contains(c) { '_' } else { c })
        .collect();
    cleaned = cleaned.trim_start_matches(['.', ' ']).trim_end_matches(['.', ' ']).to_string();

    // Bounded by characters, cut on a boundary, keeping the extension where there is room.
    const MAX: usize = 120;
    if cleaned.chars().count() > MAX {
        let ext: String = match cleaned.rsplit_once('.') {
            Some((_, e)) if !e.is_empty() && e.chars().count() <= 10 => format!(".{e}"),
            _ => String::new(),
        };
        let stem: String = cleaned.chars().take(MAX - ext.chars().count()).collect();
        cleaned = format!("{stem}{ext}");
    }

    const RESERVED: &[&str] = &[
        "con", "prn", "aux", "nul", "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8",
        "com9", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
    ];
    let stem = cleaned.split('.').next().unwrap_or("").to_ascii_lowercase();
    if RESERVED.contains(&stem.as_str()) {
        cleaned = format!("_{cleaned}");
    }
    if cleaned.is_empty() {
        "attachment".into()
    } else {
        cleaned
    }
}

/// A file sealed on this device and not yet uploaded. Holds the key; never crosses to a UI.
pub struct PendingUpload {
    client: Client<HttpTransport>,
    room: RoomId,
    key: AttachmentKey,
    sealed: Vec<u8>,
    name: String,
    mime: String,
    size: usize,
}

/// Ciphertext the instance has accepted, waiting for the message that refers to it.
pub struct UploadedAttachment {
    room: RoomId,
    attachment: Attachment,
}

impl PendingUpload {
    /// Upload the ciphertext. Needs no lock on the session; see the module note.
    pub fn upload(self) -> Result<UploadedAttachment, SessionError> {
        let blob = self.client.upload_attachment(self.room, &self.sealed)?;
        Ok(UploadedAttachment {
            room: self.room,
            attachment: Attachment {
                blob,
                key: self.key,
                name: self.name,
                size: self.size,
                mime: Some(self.mime),
            },
        })
    }
}

/// An attachment this session knows the key to, about to be fetched.
pub struct PendingDownload {
    client: Client<HttpTransport>,
    attachment: Attachment,
}

impl PendingDownload {
    /// Download and open. Fails — rather than returning anything — if the instance served
    /// bytes that do not authenticate under the key from the message.
    pub fn fetch(&self) -> Result<Vec<u8>, SessionError> {
        let sealed = self.client.download_attachment(self.attachment.blob)?;
        Ok(cairn_crypto::attachment::open(&self.attachment.key, &sealed)?)
    }

    /// Fetch, then write into `dir` under a sanitised version of the sender's name.
    ///
    /// Never overwrites: a name already taken gets ` (1)`, ` (2)` … and the file is
    /// created with `create_new`, so a file — or a symlink — that appears between the
    /// check and the write is refused rather than followed or clobbered.
    pub fn save_into(&self, dir: &Path) -> Result<PathBuf, SessionError> {
        let bytes = self.fetch()?;
        std::fs::create_dir_all(dir).map_err(SessionError::Save)?;
        let name = safe_file_name(&self.attachment.name);
        let (stem, ext) = match name.rsplit_once('.') {
            Some((s, e)) if !s.is_empty() => (s.to_string(), format!(".{e}")),
            _ => (name.clone(), String::new()),
        };
        for n in 0..1000 {
            let candidate =
                if n == 0 { dir.join(&name) } else { dir.join(format!("{stem} ({n}){ext}")) };
            match std::fs::OpenOptions::new().write(true).create_new(true).open(&candidate) {
                Ok(mut file) => {
                    use std::io::Write as _;
                    file.write_all(&bytes).map_err(SessionError::Save)?;
                    return Ok(candidate);
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(SessionError::Save(e)),
            }
        }
        Err(SessionError::Save(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "a thousand files by that name already exist",
        )))
    }
}

impl Session {
    /// Seal a file for the open room. Fast, and touches nothing on the network.
    ///
    /// Refuses an empty file and one over [`MAX_ATTACHMENT_BYTES`] here, before anything is
    /// uploaded — the instance refuses both anyway, but only after the person has waited.
    pub fn prepare_upload(
        &self,
        name: &str,
        mime: &str,
        bytes: &[u8],
    ) -> Result<PendingUpload, SessionError> {
        let open = self.open.as_ref().ok_or(SessionError::NoRoomOpen)?;
        // Checked before uploading, not just before sending: otherwise a member waiting to
        // be admitted could park ciphertext in a room they cannot yet speak in.
        if open.convo.group_id().is_none() {
            return Err(SessionError::NoGroupYet);
        }
        if bytes.is_empty() {
            return Err(SessionError::EmptyAttachment);
        }
        if bytes.len() > MAX_ATTACHMENT_BYTES {
            return Err(SessionError::AttachmentTooLarge {
                size: bytes.len(),
                max: MAX_ATTACHMENT_BYTES,
            });
        }
        let (key, sealed) = cairn_crypto::attachment::seal(bytes);
        Ok(PendingUpload {
            client: self.client.clone(),
            room: open.convo.room(),
            key,
            sealed,
            name: if name.trim().is_empty() { "attachment".into() } else { name.to_string() },
            mime: normalize_mime(Some(mime)),
            size: bytes.len(),
        })
    }

    /// Send the message that carries an uploaded attachment's key, and remember it.
    ///
    /// Returns the message as the sender should see it, because MLS will not decrypt this
    /// device's own message back to it — a frontend waiting for the poll would wait forever.
    pub fn send_uploaded(
        &mut self,
        uploaded: UploadedAttachment,
    ) -> Result<MessageView, SessionError> {
        let open = self.open.as_mut().ok_or(SessionError::NoRoomOpen)?;
        // The person may have switched rooms while the upload ran. Sending into whichever
        // room is open *now* would post their file somewhere they did not choose.
        if open.convo.room() != uploaded.room {
            return Err(SessionError::RoomChangedDuringUpload);
        }
        if open.convo.group_id().is_none() {
            return Err(SessionError::NoGroupYet);
        }
        let attachment = uploaded.attachment;
        // The body is the filename: a client that predates attachments — or this one, with
        // the descriptor stripped — still shows *something* sensible.
        let body = attachment.name.clone().into_bytes();
        let at = now_ms();
        let outbound = open.convo.send_with_attachment(&body, attachment.clone(), at)?;
        self.client.send(open.convo.room(), &outbound.envelope)?;

        let entry = HistoryEntry {
            sender: self.client.user(),
            sent_at_ms: at,
            body,
            attachment_name: Some(attachment.name.clone()),
            attachment: Some(attachment.clone()),
            id: Some(outbound.commitment.to_hex()),
            reply_to: None,
            reaction: None,
        };
        self.history.append(open.convo.room(), &entry)?;
        // Into the thread too, so the sender can be replied to or reacted to about it.
        open.thread.record(&entry);
        self.attachments.insert(attachment.blob, attachment);
        Ok(view(&entry, &open.thread, false))
    }

    /// Seal, upload and send in one call, holding `&mut self` throughout. For callers that
    /// do not share the session across threads; the desktop shell uses the three steps.
    pub fn send_file(
        &mut self,
        name: &str,
        mime: &str,
        bytes: &[u8],
    ) -> Result<MessageView, SessionError> {
        let pending = self.prepare_upload(name, mime, bytes)?;
        let uploaded = pending.upload()?;
        self.send_uploaded(uploaded)
    }

    /// Look up an attachment by the id a frontend was shown.
    ///
    /// Only attachments this session saw inside an encrypted message in the **open room**
    /// resolve. That is what keeps a frontend from asking for arbitrary blobs: the key comes
    /// from the message, the id only selects which message.
    pub fn prepare_download(&self, id: &str) -> Result<PendingDownload, SessionError> {
        let blob: BlobId = id.parse().map_err(|_| SessionError::UnknownAttachment)?;
        let attachment = self.attachments.get(&blob).ok_or(SessionError::UnknownAttachment)?;
        Ok(PendingDownload { client: self.client.clone(), attachment: attachment.clone() })
    }

    /// Download and open an attachment from the open room.
    pub fn fetch_attachment(&self, id: &str) -> Result<Vec<u8>, SessionError> {
        self.prepare_download(id)?.fetch()
    }

    /// Download, open, and save an attachment from the open room into `dir`.
    pub fn save_attachment(&self, id: &str, dir: &Path) -> Result<PathBuf, SessionError> {
        self.prepare_download(id)?.save_into(dir)
    }
}

/// The open room's known attachments, keyed by blob.
pub(super) type Known = HashMap<BlobId, Attachment>;

/// Replace what is known with exactly the attachments in `entries` — the open room's live
/// transcript. Run on open and after every timer sweep, so a key leaves memory when the
/// message that carried it leaves the disk.
pub(super) fn remember(known: &mut Known, entries: &[HistoryEntry]) {
    known.clear();
    for a in entries.iter().filter_map(|e| e.attachment.as_ref()) {
        known.insert(a.blob, a.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_seal_overhead_matches_what_sealing_actually_adds() {
        // If the crypto crate ever changes its framing, the client's ceiling must move with
        // it — or a file just under the client's limit is refused by the instance.
        for len in [1usize, 100, 65_537] {
            let (_key, sealed) = cairn_crypto::attachment::seal(&vec![0u8; len]);
            assert_eq!(sealed.len(), len + SEAL_OVERHEAD);
        }
    }

    #[test]
    fn the_transport_will_read_a_blob_at_the_ceiling() {
        // The transport's response cap and the attachment ceiling are set in different
        // files; this is what stops them drifting back into "uploads but never downloads".
        let largest_blob = (MAX_ATTACHMENT_BYTES + SEAL_OVERHEAD) as u64;
        assert!(crate::transport::MAX_RESPONSE_BYTES > largest_blob);
    }

    #[test]
    fn only_raster_images_are_shown_inline() {
        assert_eq!(kind_of("image/png"), AttachmentKind::Image);
        assert_eq!(kind_of("image/jpeg"), AttachmentKind::Image);
        // The sender's word that something is an image is not enough for a format with a
        // scripting model.
        assert_eq!(kind_of("image/svg+xml"), AttachmentKind::File);
        assert_eq!(kind_of("text/html"), AttachmentKind::File);
        assert_eq!(kind_of("application/octet-stream"), AttachmentKind::File);
    }

    #[test]
    fn a_recorded_voice_note_is_playable_audio() {
        // What MediaRecorder actually reports, parameters and all.
        assert_eq!(kind_of(&normalize_mime(Some("audio/webm;codecs=opus"))), AttachmentKind::Audio);
        assert_eq!(kind_of(&normalize_mime(Some("audio/ogg; codecs=opus"))), AttachmentKind::Audio);
        assert_eq!(kind_of(&normalize_mime(Some("audio/mp4"))), AttachmentKind::Audio);
    }

    #[test]
    fn a_hostile_media_type_becomes_an_untyped_file() {
        let long = "a/".repeat(100);
        for claimed in ["", "png", "image/", "/png", "image/png\r\nx: y", long.as_str()] {
            let mime = normalize_mime(Some(claimed));
            assert_eq!(mime, "application/octet-stream", "{claimed:?} must not survive");
            assert_eq!(kind_of(&mime), AttachmentKind::File);
        }
        assert_eq!(normalize_mime(None), "application/octet-stream");
        assert_eq!(normalize_mime(Some(" Image/PNG ")), "image/png");
    }

    #[test]
    fn a_senders_filename_cannot_escape_the_download_directory() {
        assert_eq!(safe_file_name("../../.ssh/authorized_keys"), "authorized_keys");
        assert_eq!(safe_file_name("..\\..\\Windows\\win.ini"), "win.ini");
        assert_eq!(safe_file_name("/etc/passwd"), "passwd");
        assert_eq!(safe_file_name(".."), "attachment");
        assert_eq!(safe_file_name(".bashrc"), "bashrc");
        assert_eq!(safe_file_name(""), "attachment");
        assert_eq!(safe_file_name("a:b*c?.txt"), "a_b_c_.txt");
        assert_eq!(safe_file_name("line\nbreak.txt"), "line_break.txt");
        assert_eq!(safe_file_name("CON.txt"), "_CON.txt");
        assert_eq!(safe_file_name("photo.jpg"), "photo.jpg");
    }

    #[test]
    fn a_long_filename_is_cut_on_a_character_boundary_and_keeps_its_extension() {
        let long = format!("{}.png", "é".repeat(300));
        let safe = safe_file_name(&long);
        assert!(safe.ends_with(".png"));
        assert!(safe.chars().count() <= 120);
    }
}
