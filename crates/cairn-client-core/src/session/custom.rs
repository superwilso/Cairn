//! A room's custom emoji, stickers and soundboard, for a frontend that must never hold a key
//! and must never cause a network request by drawing something.
//!
//! The record, its rules and its storage are [`crate::custom`]. This is the plumbing:
//!
//! - **Who may change the set** is checked here, on receipt, against roles the instance
//!   listed for the room — read when the room opens and then on the same slow clock as the
//!   room's timer, never because a set arrived. A set from a sender not (yet) known to be an
//!   owner or moderator is held, not applied, and checked once more when roles are next read
//!   — then applied or dropped. Reading roles *because* a set arrived would tell the instance
//!   which message was one. The cost: a demotion takes up to that clock (ten seconds) to
//!   reach a device that has the room open.
//! - **Fetching is a separate step from rendering.** [`Session::prepare_custom_sync`] names
//!   every asset of the open room's set this device lacks; [`CustomSync::run`] downloads them
//!   all, with no lock on the session; [`Session::custom_asset`] reads the cache and only the
//!   cache. A frontend asks for an asset by the id the set view gave it, and only for assets
//!   in the open room's current set.
//! - **Sent lazily, like a profile.** A set goes into the room when an owner or moderator
//!   changes it, and again — by every owner or moderator device that holds it — after
//!   somebody joins, since a new member cannot read anything sent before the welcome.

use std::collections::HashMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use cairn_proto::{BlobId, RoomId, UserId};

use super::attachments::PendingDownload;
use super::{now_ms, view, MessageView, OpenRoom, Session, SessionError};
use crate::client::Client;
use crate::conversation::Attachment;
use crate::custom::{self, Accepted, CustomError, CustomSet, Item, Kind};
use crate::history::Entry as HistoryEntry;
use crate::transport::HttpTransport;

/// One item as a frontend sees it. **No key.** `id` selects it for [`Session::custom_asset`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomItemView {
    pub kind: Kind,
    pub name: String,
    pub id: String,
    /// Sniffed from the bytes on the uploader's device and re-checked on this one before the
    /// bytes were cached. Safe to hand a `Blob` constructor.
    pub mime: String,
    pub size: usize,
    /// Whether this device holds the bytes. A frontend draws `:name:` as text until it does —
    /// it never fetches anything itself.
    pub ready: bool,
}

/// The open room's set.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomSetView {
    pub items: Vec<CustomItemView>,
    /// Whether the instance lists this account as an owner or moderator here. A courtesy for
    /// drawing the Customise panel: every recipient makes the real check.
    pub can_edit: bool,
    /// Who sent the set in force, by id. `None` when the room has none.
    pub author: Option<String>,
    /// Plaintext bytes every member downloads for this set.
    pub bytes: usize,
}

/// The limits, so a frontend can refuse a file before reading it and say the number.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomLimits {
    pub emoji: usize,
    pub stickers: usize,
    pub sounds: usize,
    pub emoji_bytes: usize,
    pub sticker_bytes: usize,
    pub sound_bytes: usize,
    pub sound_ms: u64,
    pub set_bytes: usize,
    pub image_types: Vec<String>,
    pub sound_types: Vec<String>,
}

pub fn custom_limits() -> CustomLimits {
    let owned = |t: &[&str]| t.iter().map(|s| (*s).to_string()).collect();
    CustomLimits {
        emoji: custom::MAX_EMOJI,
        stickers: custom::MAX_STICKERS,
        sounds: custom::MAX_SOUNDS,
        emoji_bytes: custom::MAX_EMOJI_BYTES,
        sticker_bytes: custom::MAX_STICKER_BYTES,
        sound_bytes: custom::MAX_SOUND_BYTES,
        sound_ms: custom::MAX_SOUND_MS,
        set_bytes: custom::MAX_SET_BYTES,
        image_types: owned(custom::IMAGE_TYPES),
        sound_types: owned(custom::SOUND_TYPES),
    }
}

/// An image or clip checked and sealed on this device, not yet uploaded. Holds the key.
pub struct PendingCustomUpload {
    client: Client<HttpTransport>,
    room: RoomId,
    kind: Kind,
    name: String,
    mime: &'static str,
    plaintext: Vec<u8>,
    key: cairn_crypto::attachment::AttachmentKey,
    sealed: Vec<u8>,
}

/// Ciphertext the instance accepted, waiting to be added to the set.
pub struct UploadedCustom {
    room: RoomId,
    item: Item,
    plaintext: Vec<u8>,
}

impl PendingCustomUpload {
    /// Upload the ciphertext. Needs no lock on the session.
    pub fn upload(self) -> Result<UploadedCustom, SessionError> {
        let blob = self.client.upload_attachment(self.room, &self.sealed)?;
        Ok(UploadedCustom {
            room: self.room,
            item: Item {
                kind: self.kind,
                name: self.name.clone(),
                asset: Attachment {
                    blob,
                    key: self.key,
                    name: self.name,
                    size: self.plaintext.len(),
                    mime: Some(self.mime.to_string()),
                },
            },
            plaintext: self.plaintext,
        })
    }
}

/// Every asset of a set this device lacks, about to be downloaded. Holds keys.
pub struct CustomSync {
    client: Client<HttpTransport>,
    dir: PathBuf,
    items: Vec<Item>,
}

impl CustomSync {
    /// How many assets are missing.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Download and cache them all. Needs no lock on the session.
    ///
    /// Each one is opened under its key, then checked again here — size, and a type sniffed
    /// from the bytes that must match the set's — before it is written. One that fails is
    /// skipped, not fatal: it stays un-ready and is drawn as its `:name:`. Returns how many
    /// were cached.
    pub fn run(self) -> usize {
        let mut cached = 0;
        for item in self.items {
            let download = PendingDownload::new(self.client.clone(), item.asset.clone());
            let Ok(bytes) = download.fetch() else { continue };
            let Ok(mime) = custom::check_asset(item.kind, &bytes) else { continue };
            if item.asset.mime.as_deref() != Some(mime) {
                continue;
            }
            if custom::write_cached(&self.dir, &item.asset.blob, &bytes).is_ok() {
                cached += 1;
            }
        }
        cached
    }
}

impl Session {
    /// The open room's set, as a frontend draws it.
    pub fn custom_set(&self) -> Result<CustomSetView, SessionError> {
        let open = self.open.as_ref().ok_or(SessionError::NoRoomOpen)?;
        Ok(self.custom_view(open))
    }

    pub(super) fn custom_view(&self, open: &OpenRoom) -> CustomSetView {
        let current = self.custom.current(&open.convo.room());
        let items = current
            .map(|a| {
                a.set
                    .items
                    .iter()
                    .map(|i| CustomItemView {
                        kind: i.kind,
                        name: i.name.clone(),
                        id: i.asset.blob.to_string(),
                        mime: i.asset.mime.clone().unwrap_or_default(),
                        size: i.asset.size,
                        ready: self.custom.is_cached(&i.asset.blob),
                    })
                    .collect()
            })
            .unwrap_or_default();
        CustomSetView {
            items,
            can_edit: self.permitted(open, &self.client.user()),
            author: current.map(|a| a.from.to_string()),
            bytes: current.map_or(0, |a| a.set.bytes()),
        }
    }

    /// Whether the instance's last-read roles let `user` change the open room's set.
    fn permitted(&self, open: &OpenRoom, user: &UserId) -> bool {
        open.roles.as_ref().and_then(|r| r.get(user)).is_some_and(|role| custom::may_edit(role))
    }

    /// Check, name and seal an image or clip for the open room's set.
    ///
    /// `name` is sanitised (`Party Parrot!` → `party_parrot`); the type is sniffed from the
    /// bytes, never taken from a filename. Refused here — before anything is uploaded — for a
    /// member the instance does not list as an owner or moderator, a name already in use,
    /// and any limit the set would break. Recipients apply the same rules regardless.
    pub fn prepare_custom_upload(
        &self,
        kind: Kind,
        name: &str,
        bytes: &[u8],
    ) -> Result<PendingCustomUpload, SessionError> {
        let open = self.open.as_ref().ok_or(SessionError::NoRoomOpen)?;
        if open.convo.group_id().is_none() {
            return Err(SessionError::NoGroupYet);
        }
        if !self.permitted(open, &self.client.user()) {
            return Err(CustomError::NotPermitted.into());
        }
        let name = custom::sanitize_name(name)?;
        let mime = custom::check_asset(kind, bytes)?;
        let mut set =
            self.custom.current(&open.convo.room()).map(|a| a.set.clone()).unwrap_or_default();
        if set.find(kind, &name).is_some() {
            return Err(CustomError::Taken(name).into());
        }
        // Validate the set as it would be, with a stand-in for the asset not yet uploaded.
        let (key, sealed) = cairn_crypto::attachment::seal(bytes);
        set.items.push(Item {
            kind,
            name: name.clone(),
            asset: Attachment {
                blob: BlobId::new(),
                key: key.clone(),
                name: name.clone(),
                size: bytes.len(),
                mime: Some(mime.to_string()),
            },
        });
        set.validate()?;
        Ok(PendingCustomUpload {
            client: self.client.clone(),
            room: open.convo.room(),
            kind,
            name,
            mime,
            plaintext: bytes.to_vec(),
            key,
            sealed,
        })
    }

    /// Add an uploaded item to the open room's set and send the new set into the room.
    pub fn commit_custom(
        &mut self,
        uploaded: UploadedCustom,
    ) -> Result<CustomSetView, SessionError> {
        let open = self.open.as_ref().ok_or(SessionError::NoRoomOpen)?;
        if open.convo.room() != uploaded.room {
            return Err(SessionError::RoomChangedDuringUpload);
        }
        let mut set =
            self.custom.current(&uploaded.room).map(|a| a.set.clone()).unwrap_or_default();
        // Checked again: another admin's set may have arrived while this one uploaded.
        if set.find(uploaded.item.kind, &uploaded.item.name).is_some() {
            return Err(CustomError::Taken(uploaded.item.name).into());
        }
        let blob = uploaded.item.asset.blob;
        set.items.push(uploaded.item);
        self.custom.put(&blob, &uploaded.plaintext)?;
        self.publish_custom(set)
    }

    /// Check, upload and add in one call. For callers that do not share the session.
    pub fn add_custom(
        &mut self,
        kind: Kind,
        name: &str,
        bytes: &[u8],
    ) -> Result<CustomSetView, SessionError> {
        let uploaded = self.prepare_custom_upload(kind, name, bytes)?.upload()?;
        self.commit_custom(uploaded)
    }

    /// Remove one item from the open room's set, and send the smaller set.
    pub fn remove_custom(&mut self, kind: Kind, name: &str) -> Result<CustomSetView, SessionError> {
        let open = self.open.as_ref().ok_or(SessionError::NoRoomOpen)?;
        if !self.permitted(open, &self.client.user()) {
            return Err(CustomError::NotPermitted.into());
        }
        let mut set =
            self.custom.current(&open.convo.room()).map(|a| a.set.clone()).unwrap_or_default();
        let before = set.items.len();
        set.items.retain(|i| !(i.kind == kind && i.name == name));
        if set.items.len() == before {
            return Err(CustomError::NoSuchItem(match kind {
                Kind::Emoji => "emoji",
                Kind::Sticker => "sticker",
                Kind::Sound => "sound",
            })
            .into());
        }
        self.publish_custom(set)
    }

    /// Send `set` into the open room and make it this device's current one.
    fn publish_custom(&mut self, set: CustomSet) -> Result<CustomSetView, SessionError> {
        set.validate()?;
        let me = self.client.user();
        let open = self.open.as_mut().ok_or(SessionError::NoRoomOpen)?;
        if open.convo.group_id().is_none() {
            return Err(SessionError::NoGroupYet);
        }
        let outbound = open.convo.send_custom_set(set.clone(), now_ms())?;
        self.client.send(open.convo.room(), &outbound.envelope)?;
        let room = open.convo.room();
        // After everything this device has seen, so a set held from before cannot replace it.
        let seq = open.cursor.saturating_add(1);
        self.custom.accept(room, Accepted { set, from: me, seq })?;
        let open = self.open.as_ref().ok_or(SessionError::NoRoomOpen)?;
        Ok(self.custom_view(open))
    }

    /// Bytes of one item in the open room's set, **from this device's cache only**.
    ///
    /// This is the whole rendering path, and it has no network call in it: an emoji not yet
    /// downloaded is refused, and the frontend draws its name instead. Only items in the open
    /// room's current set resolve, so a frontend cannot use this to read arbitrary files.
    pub fn custom_asset(&self, id: &str) -> Result<Vec<u8>, SessionError> {
        let open = self.open.as_ref().ok_or(SessionError::NoRoomOpen)?;
        let blob: BlobId = id.parse().map_err(|_| SessionError::UnknownCustomAsset)?;
        let current =
            self.custom.current(&open.convo.room()).ok_or(SessionError::UnknownCustomAsset)?;
        if !current.set.items.iter().any(|i| i.asset.blob == blob) {
            return Err(SessionError::UnknownCustomAsset);
        }
        self.custom.cached(&blob).ok_or(SessionError::UnknownCustomAsset)
    }

    /// Everything in the open room's set this device has not downloaded yet.
    pub fn prepare_custom_sync(&self) -> Result<CustomSync, SessionError> {
        let open = self.open.as_ref().ok_or(SessionError::NoRoomOpen)?;
        let items = self
            .custom
            .current(&open.convo.room())
            .map(|a| custom::missing(&self.custom, &a.set))
            .unwrap_or_default();
        Ok(CustomSync {
            client: self.client.clone(),
            dir: self.custom.cache_dir().to_path_buf(),
            items,
        })
    }

    /// Download the open room's whole set now. For callers that do not share the session.
    pub fn sync_custom(&self) -> Result<usize, SessionError> {
        Ok(self.prepare_custom_sync()?.run())
    }

    /// Send one of the open room's stickers.
    pub fn send_sticker(&mut self, name: &str) -> Result<MessageView, SessionError> {
        let open = self.open.as_mut().ok_or(SessionError::NoRoomOpen)?;
        if open.convo.group_id().is_none() {
            return Err(SessionError::NoGroupYet);
        }
        let room = open.convo.room();
        if self.custom.current(&room).and_then(|a| a.set.find(Kind::Sticker, name)).is_none() {
            return Err(CustomError::NoSuchItem("sticker").into());
        }
        let at = now_ms();
        let outbound = open.convo.send_sticker(name, at)?;
        self.client.send(room, &outbound.envelope)?;
        let entry = HistoryEntry {
            sender: self.client.user(),
            sent_at_ms: at,
            body: format!(":{name}:").into_bytes(),
            attachment_name: None,
            attachment: None,
            id: Some(outbound.commitment.to_hex()),
            reply_to: None,
            reaction: None,
            card: None,
            sticker: Some(name.to_owned()),
            edit: None,
            deleted: false,
        };
        self.history.append(room, &entry)?;
        open.thread.record(&entry);
        Ok(view(&entry, &open.thread, &open.labels, false, self.client.user()))
    }

    /// A set arrived from `sender` at the instance's sequence `seq`. Applied if the room's
    /// roles, as last read, let them change it; held otherwise. Returns whether the room's
    /// set changed.
    pub(super) fn receive_custom(
        &mut self,
        open: &OpenRoom,
        sender: UserId,
        seq: u64,
        set: CustomSet,
    ) -> bool {
        let room = open.convo.room();
        let accepted = Accepted { set, from: sender, seq };
        if self.permitted(open, &sender) {
            self.custom.accept(room, accepted).unwrap_or(false)
        } else {
            let _ = self.custom.hold(room, accepted);
            false
        }
    }

    /// Read the open room's roles from the instance, and apply any set that was held for
    /// want of them. Returns whether the room's set changed.
    pub(super) fn refresh_roles(&mut self, open: &mut OpenRoom) -> bool {
        let Ok(listed) = self.client.room_members(open.convo.room()) else { return false };
        open.roles_checked_ms = now_ms();
        self.apply_roles(open, &listed)
    }

    /// Take a member list just read — by polling or by [`Session::members`] — as the room's
    /// roles.
    pub(super) fn apply_roles(&mut self, open: &mut OpenRoom, listed: &[(UserId, String)]) -> bool {
        let roles: HashMap<UserId, String> = listed.iter().cloned().collect();
        let room = open.convo.room();
        let changed = self
            .custom
            .release(room, |u| roles.get(u).is_some_and(|r| custom::may_edit(r)))
            .unwrap_or(false);
        open.roles = Some(roles);
        changed
    }

    /// Re-send the open room's set if somebody joined since it was last sent, and this
    /// account may send it. Returns whether anything was sent.
    pub(super) fn flush_custom(&mut self, open: &mut OpenRoom) -> Result<bool, SessionError> {
        let room = open.convo.room();
        if open.convo.group_id().is_none() || !self.custom.due(&room) {
            return Ok(false);
        }
        if !self.permitted(open, &self.client.user()) {
            // Not ours to send. Somebody who may will.
            self.custom.clear_due(&room)?;
            return Ok(false);
        }
        let Some(current) = self.custom.current(&room) else { return Ok(false) };
        let outbound = open.convo.send_custom_set(current.set.clone(), now_ms())?;
        self.client.send(room, &outbound.envelope)?;
        self.custom.clear_due(&room)?;
        Ok(true)
    }
}
