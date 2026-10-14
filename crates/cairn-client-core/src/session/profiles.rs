//! Profiles, for a frontend that must never hold a key or decide who someone is.
//!
//! The record, its rules and its storage are [`crate::profile`]. This is the plumbing:
//!
//! - **Sending is lazy, per room, from `poll`.** A profile goes into a room the next time
//!   this device polls it after the profile changed, after somebody joined, or after this
//!   device itself joined — by then the group is at its current epoch, so the new member can
//!   read it. The cost, stated: **a room this device never opens never hears about a change.**
//!   The desktop client only polls the open room, so the alternative — loading every other
//!   room's group to send into it blind — would send at a stale epoch into rooms whose
//!   commits this device had not yet processed.
//! - **Images are sealed per room.** Each room gets its own copy under its own single-use key,
//!   uploaded once and reused when the profile is re-sent for a new member. A room's blob
//!   store only serves its own members, so one upload could not serve two rooms anyway.
//! - **A frontend asks for an image by member and slot**, and only for members whose profile
//!   this device holds in the open room — the same rule as message attachments.

use std::collections::HashMap;

use cairn_proto::{DeviceIdentity, RoomId, UserId};
use serde::{Deserialize, Serialize};

use super::attachments::PendingDownload;
use super::{now_ms, OpenRoom, Session, SessionError};
use crate::conversation::{Attachment, Conversation};
use crate::profile::{
    self, check_image, parse_colour, ImageSlot, ImageView, Label, Profile, ProfileStore,
    ProfileView, Sent, Status, MAX_ABOUT_CHARS, MAX_ABOUT_LINES, MAX_NAME_CHARS,
    MAX_PROFILE_IMAGE_BYTES, MAX_PRONOUNS_CHARS, MAX_STATUS_CHARS, PROFILE_IMAGE_TYPES,
};

/// What a frontend sends to change the shared part of a profile. Every field replaces the
/// current one; an empty or absent field clears it.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ProfileEdit {
    pub display_name: Option<String>,
    pub pronouns: Option<String>,
    pub about: Option<String>,
    /// `#rrggbb`, top to bottom.
    pub colors: Option<[String; 2]>,
    pub status_emoji: Option<String>,
    pub status_text: Option<String>,
    pub status_expires_at_ms: Option<i64>,
}

/// The limits, so a frontend can count characters against numbers that live here.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileLimits {
    pub name_chars: usize,
    pub pronouns_chars: usize,
    pub about_chars: usize,
    pub about_lines: usize,
    pub status_chars: usize,
    pub image_bytes: usize,
    pub image_types: Vec<String>,
}

pub fn profile_limits() -> ProfileLimits {
    ProfileLimits {
        name_chars: MAX_NAME_CHARS,
        pronouns_chars: MAX_PRONOUNS_CHARS,
        about_chars: MAX_ABOUT_CHARS,
        about_lines: MAX_ABOUT_LINES,
        status_chars: MAX_STATUS_CHARS,
        image_bytes: MAX_PROFILE_IMAGE_BYTES,
        image_types: PROFILE_IMAGE_TYPES.iter().map(|s| (*s).to_string()).collect(),
    }
}

/// A profile image about to be read: this account's own from disk, or a member's from the
/// room's blob store. Holds the key in the second case; never crosses to a UI.
pub enum PendingProfileImage {
    Local(Vec<u8>),
    Remote(PendingDownload),
}

impl PendingProfileImage {
    /// The plaintext. A member's image is refused if it decrypts to more than the profile
    /// ceiling, whatever size their record claimed: the claim was theirs to make.
    pub fn fetch(self) -> Result<Vec<u8>, SessionError> {
        match self {
            Self::Local(bytes) => Ok(bytes),
            Self::Remote(download) => {
                let bytes = download.fetch()?;
                if bytes.len() > MAX_PROFILE_IMAGE_BYTES {
                    return Err(SessionError::Profile(profile::ProfileError::ImageTooLarge));
                }
                Ok(bytes)
            }
        }
    }
}

/// Trim, and treat blank as absent.
fn clean(s: Option<String>) -> Option<String> {
    s.map(|s| s.replace("\r\n", "\n").trim().to_string()).filter(|s| !s.is_empty())
}

impl Session {
    /// Change this account's name, pronouns, about me, colours and status.
    ///
    /// Checked here with the rules every recipient applies, so a refusal is a sentence now
    /// rather than a profile that silently never appears anywhere else. Sent into the open
    /// room at once; other rooms get it the next time they are opened.
    pub fn set_profile(&mut self, edit: ProfileEdit) -> Result<ProfileView, SessionError> {
        let colors = match edit.colors {
            Some([a, b]) => Some([parse_colour(&a)?, parse_colour(&b)?]),
            None => None,
        };
        let status = Status {
            emoji: clean(edit.status_emoji),
            text: clean(edit.status_text),
            expires_at_ms: edit.status_expires_at_ms,
        };
        let profile = Profile {
            display_name: clean(edit.display_name),
            pronouns: clean(edit.pronouns),
            about: clean(edit.about),
            colors,
            status: (status.emoji.is_some() || status.text.is_some()).then_some(status),
            ..Profile::default()
        };
        profile.validate()?;
        self.profiles.set_mine(profile)?;
        self.after_profile_change();
        Ok(self.my_profile())
    }

    /// Set (`Some((bytes, type))`) or clear (`None`) this account's avatar or banner.
    pub fn set_profile_image(
        &mut self,
        slot: ImageSlot,
        image: Option<(&[u8], &str)>,
    ) -> Result<ProfileView, SessionError> {
        let image = match image {
            Some((bytes, mime)) => {
                let mime = super::normalize_mime(Some(mime));
                let base = mime.split(';').next().unwrap_or("").trim().to_string();
                check_image(Some(&base), bytes.len())?;
                Some((bytes, base))
            }
            None => None,
        };
        self.profiles.set_image(slot, image.as_ref().map(|(b, m)| (*b, m.as_str())))?;
        self.after_profile_change();
        Ok(self.my_profile())
    }

    /// Set or clear this account's nickname in the open room. Only that room is told.
    pub fn set_nickname(&mut self, nickname: Option<&str>) -> Result<ProfileView, SessionError> {
        let room = self.open.as_ref().ok_or(SessionError::NoRoomOpen)?.convo.room();
        let nickname = clean(nickname.map(str::to_owned));
        Profile { nickname: nickname.clone(), ..Profile::default() }.validate()?;
        self.profiles.set_nickname(room, nickname)?;
        self.after_profile_change();
        Ok(self.my_profile())
    }

    /// Relabel the open room and send the new profile into it, best-effort: if the send
    /// fails the room stays due and the next poll tries again.
    fn after_profile_change(&mut self) {
        if let Some(mut open) = self.open.take() {
            let _ = self.flush_profile(&mut open);
            self.relabel(&mut open);
            self.open = Some(open);
        }
    }

    /// This account's profile as the open room sees it — with that room's nickname, if any.
    pub fn my_profile(&self) -> ProfileView {
        let me = self.client.user();
        match &self.open {
            Some(open) => self.view_of(open, &me),
            None => ProfileView::of(
                &me,
                Some(&self.profiles.mine().profile),
                None,
                self.own_images(),
                true,
                now_ms(),
            ),
        }
    }

    /// Every profile this device knows in the open room: members of the group, members the
    /// instance listed, and anyone whose profile arrived here, each labelled against the rest.
    pub fn profiles(&self) -> Result<Vec<ProfileView>, SessionError> {
        let open = self.open.as_ref().ok_or(SessionError::NoRoomOpen)?;
        let mut users: Vec<&UserId> = open.labels.keys().collect();
        users.sort();
        Ok(users.into_iter().map(|u| self.view_of(open, u)).collect())
    }

    /// Get ready to read one member's avatar or banner in the open room.
    pub fn prepare_profile_image(
        &self,
        user: &str,
        slot: ImageSlot,
    ) -> Result<PendingProfileImage, SessionError> {
        let user: UserId = user.parse().map_err(|_| SessionError::BadId(user.to_string()))?;
        if user == self.client.user() {
            return self
                .profiles
                .image(slot)
                .map(|(bytes, _)| PendingProfileImage::Local(bytes))
                .ok_or(SessionError::UnknownProfileImage);
        }
        let open = self.open.as_ref().ok_or(SessionError::NoRoomOpen)?;
        let profile = self
            .profiles
            .peer(&open.convo.room(), &user)
            .ok_or(SessionError::UnknownProfileImage)?;
        let image = match slot {
            ImageSlot::Avatar => profile.avatar.as_ref(),
            ImageSlot::Banner => profile.banner.as_ref(),
        }
        .ok_or(SessionError::UnknownProfileImage)?;
        Ok(PendingProfileImage::Remote(PendingDownload::new(self.client.clone(), image.clone())))
    }

    /// Download and open one member's image. For callers that do not share the session.
    pub fn fetch_profile_image(
        &self,
        user: &str,
        slot: ImageSlot,
    ) -> Result<Vec<u8>, SessionError> {
        self.prepare_profile_image(user, slot)?.fetch()
    }

    pub(super) fn view_of(&self, open: &OpenRoom, user: &UserId) -> ProfileView {
        let room = open.convo.room();
        let me = self.client.user();
        if *user == me {
            let mine = self.profiles.outgoing(&room);
            return ProfileView::of(
                user,
                Some(&mine),
                open.labels.get(user),
                self.own_images(),
                true,
                now_ms(),
            );
        }
        let profile = self.profiles.peer(&room, user);
        let image = |a: Option<&Attachment>| {
            a.map(|a| ImageView {
                id: a.blob.to_string(),
                mime: a.mime.clone().unwrap_or_default(),
            })
        };
        let images = [
            image(profile.and_then(|p| p.avatar.as_ref())),
            image(profile.and_then(|p| p.banner.as_ref())),
        ];
        ProfileView::of(user, profile, open.labels.get(user), images, false, now_ms())
    }

    fn own_images(&self) -> [Option<ImageView>; 2] {
        let mine = self.profiles.mine();
        let v = mine.image_version;
        [
            mine.avatar
                .as_ref()
                .map(|i| ImageView { id: format!("own-avatar-{v}"), mime: i.mime.clone() }),
            mine.banner
                .as_ref()
                .map(|i| ImageView { id: format!("own-banner-{v}"), mime: i.mime.clone() }),
        ]
    }

    /// Recompute every label in the open room.
    pub(super) fn relabel(&self, open: &mut OpenRoom) {
        open.labels = labels_for(&self.profiles, self.client.user(), &open.convo, &open.listed);
    }

    /// Send this account's profile into the open room if it has not had the current one.
    ///
    /// Returns whether anything was sent. Uploads images first when this room has not had
    /// this version of them; the record then carries the keys.
    pub(super) fn flush_profile(&mut self, open: &mut OpenRoom) -> Result<bool, SessionError> {
        let room = open.convo.room();
        if open.convo.group_id().is_none() || !self.profiles.due(&room) {
            return Ok(false);
        }
        let mine = self.profiles.mine().clone();
        let prev = self.profiles.sent(&room).cloned().unwrap_or_default();
        let (avatar, banner) = if prev.image_version == mine.image_version {
            (prev.avatar, prev.banner)
        } else {
            (self.upload_own(room, ImageSlot::Avatar)?, self.upload_own(room, ImageSlot::Banner)?)
        };
        let profile = Profile {
            avatar: avatar.clone(),
            banner: banner.clone(),
            ..self.profiles.outgoing(&room)
        };
        profile.validate()?;
        let outbound = open.convo.send_profile(profile, now_ms())?;
        self.client.send(room, &outbound.envelope)?;
        self.profiles.record_sent(
            room,
            Sent { version: mine.version, image_version: mine.image_version, avatar, banner },
        )?;
        Ok(true)
    }

    fn upload_own(
        &self,
        room: RoomId,
        slot: ImageSlot,
    ) -> Result<Option<Attachment>, SessionError> {
        let Some((bytes, mime)) = self.profiles.image(slot) else { return Ok(None) };
        let (key, sealed) = cairn_crypto::attachment::seal(&bytes);
        let blob = self.client.upload_attachment(room, &sealed)?;
        let name = match slot {
            ImageSlot::Avatar => "avatar",
            ImageSlot::Banner => "banner",
        };
        Ok(Some(Attachment { blob, key, name: name.into(), size: bytes.len(), mime: Some(mime) }))
    }
}

/// Who is in a room, as far as this device can tell, labelled against each other.
///
/// The group's roster, the accounts the instance last listed, anyone whose profile this
/// device holds for the room (members who have since left still have messages on screen),
/// and this account.
pub(super) fn labels_for(
    profiles: &ProfileStore,
    me: UserId,
    convo: &Conversation,
    listed: &[UserId],
) -> HashMap<UserId, Label> {
    let room = convo.room();
    let mut users: Vec<UserId> = convo
        .members()
        .iter()
        .filter_map(|m| DeviceIdentity::parse(&m.identity).ok().map(|id| id.user()))
        .collect();
    users.extend_from_slice(listed);
    if let Some(peers) = profiles.peers(&room) {
        users.extend(peers.keys().copied());
    }
    users.push(me);
    let mine = profiles.outgoing(&room);
    profile::labels(users.iter(), |u| {
        if *u == me {
            mine.name().map(str::to_owned)
        } else {
            profiles.peer(&room, u).and_then(|p| p.name().map(str::to_owned))
        }
    })
}
