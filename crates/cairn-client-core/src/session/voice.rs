//! Voice channels: the room-attached call that goes through the instance's SFU.
//!
//! Everything a frontend must not decide is decided here: whether the call is end-to-end
//! encrypted right now, which key seals this device's frames, which keys open everyone
//! else's. The webview gets the answers as data — `voice_state` and `voice_keys` — and
//! applies them. See `docs/adr/012-sfu-voice-channels.md`.

use std::collections::HashMap;

use base64::Engine as _;
use serde::Serialize;

use cairn_proto::{DeviceId, DeviceIdentity, UserId};

use super::{Session, SessionError};
use crate::call::{CallSignal, SignalKind, VOICE_CHANNEL, VOICE_E2EE, VOICE_TRANSPORT_ONLY};
use crate::client::VoiceSlot;

/// This device's seat, while it holds one.
#[derive(Debug, Clone)]
pub(super) struct Seat {
    room: cairn_proto::RoomId,
    session: String,
    e2ee: bool,
}

/// What each device in the open room has announced about its media, from MLS-authenticated
/// signals only. `true` is end to end.
pub(super) type Modes = HashMap<(UserId, DeviceId), bool>;

/// The answer to joining.
#[derive(Debug, Clone, Serialize)]
pub struct VoiceJoined {
    pub session: String,
    pub answer: String,
}

/// How a voice call is protected *right now*. Derived from the call, not from the room —
/// §5's "its own badge".
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VoiceProtection {
    /// Every connected participant seals frames. The SFU forwards ciphertext.
    E2ee,
    /// Somebody connected announced they cannot seal frames, so nobody does. The SFU can
    /// hear the call. The room's own tier is unchanged.
    TransportOnly,
    /// The room is transport-encrypted by its tier (T3), so its voice channel is too.
    TransportRoom,
}

#[derive(Debug, Clone, Serialize)]
pub struct VoiceParticipantView {
    pub user: String,
    pub device: String,
    pub joined_at_ms: i64,
    pub me: bool,
    /// Whether this device is a leaf of the room's MLS group. One that is not cannot hold a
    /// key — the instance listed somebody the group does not contain, and the UI says so.
    pub in_group: bool,
    /// `"e2ee"`, `"transport_only"`, or `"unknown"` when nothing authenticated has said.
    pub media: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct VoiceStateView {
    /// False when the instance runs no SFU: no voice channel to show.
    pub available: bool,
    pub joined: bool,
    pub session: Option<String>,
    pub protection: VoiceProtection,
    /// Who caused a transport-only fallback, by account.
    pub fallback_by: Vec<String>,
    pub participants: Vec<VoiceParticipantView>,
    /// The SFU's claim about this device's receive slots. Used to place audio in transport
    /// mode only; sealed frames are attributed by the key they open under.
    pub slots: Vec<VoiceSlot>,
}

/// One sender's key for the current epoch.
#[derive(Debug, Clone, Serialize)]
pub struct VoiceKeyView {
    pub leaf: u32,
    pub user: String,
    pub device: String,
    /// Base64 of the raw AES-128 key, for a one-time import as a non-extractable CryptoKey.
    pub key: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct VoiceKeysView {
    /// Low 32 bits of the MLS epoch — what a frame's trailer carries.
    pub epoch: u32,
    /// This device's leaf: what its own frames are sealed as.
    pub me_leaf: u32,
    pub keys: Vec<VoiceKeyView>,
}

impl Session {
    /// Join the open room's voice channel with this device's SDP offer.
    ///
    /// `e2ee_capable` is the webview's honest answer to "can you transform frames?". It is
    /// announced to the room inside the encrypted body; a `false` makes the call
    /// transport-only for everyone until this device leaves, and everyone is told.
    pub fn voice_join(
        &mut self,
        offer: &str,
        e2ee_capable: bool,
    ) -> Result<VoiceJoined, SessionError> {
        let open = self.open.as_ref().ok_or(SessionError::NoRoomOpen)?;
        let room = open.convo.room();
        if self.voice.is_some() {
            let _ = self.voice_leave();
        }
        let (session, answer) = self.client.voice_join(room, offer)?;
        self.voice = Some(Seat { room, session: session.clone(), e2ee: e2ee_capable });
        self.announce_voice_media()?;
        Ok(VoiceJoined { session, answer })
    }

    /// Leave the voice channel. A no-op when not in it.
    pub fn voice_leave(&mut self) -> Result<(), SessionError> {
        let Some(seat) = self.voice.take() else { return Ok(()) };
        self.client.voice_leave(seat.room, &seat.session)?;
        Ok(())
    }

    /// Tell the room what this device's media is. Encrypted, so the instance cannot forge
    /// one; repeated when a newcomer announces, because what was said before they joined is
    /// not readable to them.
    fn announce_voice_media(&mut self) -> Result<(), SessionError> {
        let Some(seat) = &self.voice else { return Ok(()) };
        let payload = if seat.e2ee { VOICE_E2EE } else { VOICE_TRANSPORT_ONLY };
        let open = self.open.as_mut().ok_or(SessionError::NoRoomOpen)?;
        if open.convo.group_id().is_none() {
            return Ok(());
        }
        let signal = CallSignal {
            call: VOICE_CHANNEL.to_string(),
            kind: SignalKind::VoiceMedia,
            to: None,
            payload: payload.to_string(),
        };
        let outbound = open.convo.send_signal(signal, super::now_ms())?;
        self.client.send(open.convo.room(), &outbound.envelope)?;
        Ok(())
    }

    /// Record an announcement that arrived in the open room. Returns whether it was news,
    /// in which case this device answers with its own so the newcomer learns it.
    pub(super) fn voice_media_heard(
        &mut self,
        user: UserId,
        device: DeviceId,
        payload: &str,
    ) -> bool {
        let e2ee = match payload {
            VOICE_E2EE => true,
            VOICE_TRANSPORT_ONLY => false,
            _ => return false,
        };
        let before = self.voice_modes.insert((user, device), e2ee);
        let news = before != Some(e2ee);
        if news && self.voice.is_some() {
            let _ = self.announce_voice_media();
        }
        news
    }

    /// The open room's voice channel as this device should show and run it.
    pub fn voice_state(&mut self) -> Result<VoiceStateView, SessionError> {
        let room = self.open.as_ref().ok_or(SessionError::NoRoomOpen)?.convo.room();
        let seat = self.voice.as_ref().filter(|s| s.room == room).cloned();
        let roster = match self.client.voice_roster(room, seat.as_ref().map(|s| s.session.as_str()))
        {
            // No longer a member of the room: removed, so out of its voice channel too. The
            // SFU has already dropped the connection; this is the client finding out.
            Err(crate::client::ClientError::Transport(
                crate::transport::TransportError::Status { status: 403, .. },
            )) => {
                self.voice = None;
                None
            }
            other => other?,
        };
        let seat = self.voice.as_ref().filter(|s| s.room == room).cloned();
        let open = self.open.as_ref().ok_or(SessionError::NoRoomOpen)?;
        let has_group = open.convo.group_id().is_some();
        let group: Vec<Vec<u8>> = open.convo.members().into_iter().map(|m| m.identity).collect();
        let me = (self.client.user(), self.client.device());

        let Some(roster) = roster else {
            return Ok(VoiceStateView {
                available: false,
                joined: false,
                session: None,
                protection: if has_group {
                    VoiceProtection::E2ee
                } else {
                    VoiceProtection::TransportRoom
                },
                fallback_by: Vec::new(),
                participants: Vec::new(),
                slots: Vec::new(),
            });
        };

        let mut participants = Vec::new();
        let mut fallback_by = Vec::new();
        for p in &roster.participants {
            let (Ok(user), Ok(device)) = (p.user.parse::<UserId>(), p.device.parse::<DeviceId>())
            else {
                continue;
            };
            let is_me = (user, device) == me;
            let mode = if is_me {
                seat.as_ref().map(|s| s.e2ee)
            } else {
                self.voice_modes.get(&(user, device)).copied()
            };
            if mode == Some(false) && !fallback_by.contains(&p.user) {
                fallback_by.push(p.user.clone());
            }
            let credential = DeviceIdentity::new(user, device).to_credential();
            participants.push(VoiceParticipantView {
                user: p.user.clone(),
                device: p.device.clone(),
                joined_at_ms: p.joined_at_ms,
                me: is_me,
                in_group: group.contains(&credential),
                media: match mode {
                    Some(true) => VOICE_E2EE,
                    Some(false) => VOICE_TRANSPORT_ONLY,
                    None => "unknown",
                },
            });
        }
        let protection = protection_of(has_group, !fallback_by.is_empty());
        Ok(VoiceStateView {
            available: true,
            joined: seat.is_some(),
            session: seat.map(|s| s.session),
            protection,
            fallback_by,
            participants,
            slots: roster.slots,
        })
    }

    /// Every group member's media key for the current epoch, and this device's leaf.
    ///
    /// The one place raw media keys cross to the frontend. Refused outside an encrypted
    /// room, where there is nothing to derive them from.
    pub fn voice_keys(&self) -> Result<VoiceKeysView, SessionError> {
        let open = self.open.as_ref().ok_or(SessionError::NoRoomOpen)?;
        let group = open.convo.group().ok_or(SessionError::NoGroupYet)?;
        let room = open.convo.room();
        let room_bytes = room.as_uuid().as_bytes().to_vec();
        let mut keys = Vec::new();
        for m in group.members() {
            let Ok(id) = DeviceIdentity::parse(&m.identity) else { continue };
            let key = group.media_key(&room_bytes, &m.identity)?;
            keys.push(VoiceKeyView {
                leaf: m.index,
                user: id.user().to_string(),
                device: id.device().to_string(),
                key: base64::engine::general_purpose::STANDARD.encode(key.as_bytes()),
            });
        }
        Ok(VoiceKeysView { epoch: group.epoch() as u32, me_leaf: group.own_member()?.index, keys })
    }
}

/// The rule, separate so it can be tested without a network: transport by tier if the room
/// has no group; transport-only while any *authenticated* announcement from a connected
/// participant says so; otherwise end to end. Nothing the instance says alone can move it
/// off end to end.
fn protection_of(has_group: bool, someone_announced_transport_only: bool) -> VoiceProtection {
    if !has_group {
        VoiceProtection::TransportRoom
    } else if someone_announced_transport_only {
        VoiceProtection::TransportOnly
    } else {
        VoiceProtection::E2ee
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_an_announcement_moves_a_voice_call_off_end_to_end() {
        assert_eq!(protection_of(true, false), VoiceProtection::E2ee);
        assert_eq!(protection_of(true, true), VoiceProtection::TransportOnly);
        assert_eq!(protection_of(false, false), VoiceProtection::TransportRoom);
    }
}
