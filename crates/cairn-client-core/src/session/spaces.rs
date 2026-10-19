//! Spaces for a frontend: plain strings in, plain data out.
//!
//! Every permission a frontend shows comes from the instance's view of the space, already
//! decided: `can_send`, `manageable`, the viewer's own permission names. This file converts
//! them to strings and does nothing to them, so a UI cannot come to disagree with the
//! instance about who may do what — and a UI that tried to decide would be enforcing nothing,
//! since the instance re-checks every request regardless.
//!
//! The parts that are *this device's* to decide are the cryptographic ones: a channel's group
//! is founded here, its tier is checked against the published rule here, and admitting or
//! removing people from its encrypted group is an explicit action here, never something the
//! instance's list does on its own.

use serde::Serialize;

use cairn_proto::{DeviceIdentity, Permissions, RoleId, RoomId, SpaceId, UserId};

use super::{now_ms, Session, SessionError};
use crate::spaces::{checked_channel_seal, SpaceView};

/// A space, as a list entry.
#[derive(Debug, Clone, Serialize)]
pub struct SpaceListing {
    pub id: String,
    pub name: String,
}

/// A space as a frontend draws it. Every flag here is the instance's answer.
#[derive(Debug, Clone, Serialize)]
pub struct SpaceDisplay {
    pub id: String,
    pub name: String,
    pub owner: String,
    pub i_am_owner: bool,
    /// The viewer's space-wide permissions, by name.
    pub my_permissions: Vec<&'static str>,
    pub everyone: Vec<&'static str>,
    pub everyone_manageable: bool,
    pub roles: Vec<RoleDisplay>,
    pub members: Vec<SpaceMemberDisplay>,
    pub channels: Vec<ChannelDisplay>,
    /// Said once, so a frontend can show it beside the member list rather than invent it.
    pub visibility_note: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct RoleDisplay {
    pub id: String,
    pub name: String,
    pub permissions: Vec<&'static str>,
    pub position: u32,
    pub manageable: bool,
    pub assignable: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct SpaceMemberDisplay {
    pub user: String,
    pub roles: Vec<String>,
    pub owner: bool,
    pub manageable: bool,
    pub roles_editable: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ChannelDisplay {
    pub id: String,
    pub name: String,
    /// From the seal this device derived and recorded — checked against the rule, and
    /// refused by the local index if it ever changes.
    pub tier: &'static str,
    pub e2ee: bool,
    pub can_send: bool,
    /// Whether this device holds the channel's encrypted group.
    pub joined: bool,
    pub overrides: Option<Vec<OverrideDisplay>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct OverrideDisplay {
    /// A role id, or `None` for `@everyone`.
    pub role: Option<String>,
    pub allow: Vec<&'static str>,
    pub deny: Vec<&'static str>,
}

/// What the instance sees of a space, in the words a frontend shows. ADR-011.
const VISIBILITY_NOTE: &str = "Your instance can see this space's name, its channels and \
    roles, and who is in it. In an end-to-end encrypted channel it cannot read the messages.";

/// Members a new space admits. Below `T2_MAX_MEMBERS`, so its channels can be encrypted.
pub const DEFAULT_SPACE_CEILING: u32 = 500;

fn space_id(s: &str) -> Result<SpaceId, SessionError> {
    s.parse().map_err(|_| SessionError::BadId(s.to_string()))
}

fn room_id(s: &str) -> Result<RoomId, SessionError> {
    s.parse().map_err(|_| SessionError::BadId(s.to_string()))
}

fn user_id(s: &str) -> Result<UserId, SessionError> {
    s.parse().map_err(|_| SessionError::BadId(s.to_string()))
}

fn role_id(s: &str) -> Result<RoleId, SessionError> {
    s.parse().map_err(|_| SessionError::BadId(s.to_string()))
}

fn permissions(names: &[String]) -> Result<Permissions, SessionError> {
    Permissions::from_names(names.iter().map(String::as_str))
        .ok_or_else(|| SessionError::BadId(names.join(",")))
}

impl Session {
    /// The spaces this account is in.
    pub fn spaces(&self) -> Result<Vec<SpaceListing>, SessionError> {
        Ok(self
            .client
            .spaces()?
            .into_iter()
            .map(|s| SpaceListing { id: s.id.to_string(), name: s.name })
            .collect())
    }

    /// Create a space this account owns.
    ///
    /// Refuses a ceiling above `T2_MAX_MEMBERS`, as [`Session::create_group`] does: a space
    /// that large can only hold public channels, and asking for a big *private* space and
    /// getting a readable one is the silent downgrade the tier model forbids.
    pub fn create_space(
        &mut self,
        name: &str,
        ceiling: Option<u32>,
    ) -> Result<String, SessionError> {
        let ceiling = ceiling.unwrap_or(DEFAULT_SPACE_CEILING);
        if ceiling > cairn_proto::tier::T2_MAX_MEMBERS {
            return Err(SessionError::Shape(cairn_proto::ShapeError::DirectRoomTooLarge));
        }
        Ok(self.client.create_space(name, ceiling)?.to_string())
    }

    /// A space, with its channels recorded on this device so they can be opened.
    ///
    /// Each listed channel's tier is checked against the rule for this space's ceiling and
    /// then recorded; the index refuses a channel it already holds at a different tier.
    pub fn space(&mut self, space: &str) -> Result<SpaceDisplay, SessionError> {
        let view = self.client.describe_space(space_id(space)?)?;
        let mut channels = Vec::with_capacity(view.channels.len());
        for c in &view.channels {
            let seal = checked_channel_seal(&view, c)?;
            self.index.record_channel(c.room, &seal, view.id)?;
            channels.push(ChannelDisplay {
                id: c.room.to_string(),
                name: c.name.clone(),
                tier: seal.tier().label(),
                e2ee: seal.tier().is_e2ee(),
                can_send: c.my_permissions.contains(Permissions::SEND),
                joined: self.index.group_id(&c.room)?.is_some(),
                overrides: c.overrides.as_ref().map(|list| {
                    list.iter()
                        .map(|o| OverrideDisplay {
                            role: o.role.map(|r| r.to_string()),
                            allow: o.allow.names(),
                            deny: o.deny.names(),
                        })
                        .collect()
                }),
            });
        }
        Ok(display(&view, self.client.user(), channels))
    }

    /// Create an end-to-end encrypted channel and found its group on this device.
    ///
    /// Private channels only. A public channel is T3, which this client does not yet send to;
    /// [`crate::Client::create_channel`] can make one for a client that does.
    pub fn create_channel(&mut self, space: &str, name: &str) -> Result<String, SessionError> {
        let space = space_id(space)?;
        let ceiling = self.client.describe_space(space)?.member_ceiling;
        let (room, seal) = self.client.create_channel(space, ceiling, name, false)?;
        let opened = self.start_group(room, seal)?;
        self.index.record_channel(room, &seal, space)?;
        Ok(opened)
    }

    pub fn rename_channel(
        &self,
        space: &str,
        channel: &str,
        name: &str,
    ) -> Result<(), SessionError> {
        Ok(self.client.rename_channel(space_id(space)?, room_id(channel)?, name)?)
    }

    pub fn delete_channel(&self, space: &str, channel: &str) -> Result<(), SessionError> {
        Ok(self.client.delete_channel(space_id(space)?, room_id(channel)?)?)
    }

    /// Set a channel override for a role, or `@everyone` when `role` is `None`.
    pub fn set_channel_override(
        &self,
        space: &str,
        channel: &str,
        role: Option<&str>,
        allow: &[String],
        deny: &[String],
    ) -> Result<(), SessionError> {
        let role = role.map(role_id).transpose()?;
        Ok(self.client.set_override(
            space_id(space)?,
            room_id(channel)?,
            role,
            permissions(allow)?,
            permissions(deny)?,
        )?)
    }

    pub fn create_role(
        &self,
        space: &str,
        name: &str,
        grants: &[String],
        position: u32,
    ) -> Result<String, SessionError> {
        Ok(self
            .client
            .create_role(space_id(space)?, name, permissions(grants)?, position)?
            .to_string())
    }

    pub fn assign_role(&self, space: &str, user: &str, role: &str) -> Result<(), SessionError> {
        Ok(self.client.assign_role(space_id(space)?, user_id(user)?, role_id(role)?)?)
    }

    pub fn unassign_role(&self, space: &str, user: &str, role: &str) -> Result<(), SessionError> {
        Ok(self.client.unassign_role(space_id(space)?, user_id(user)?, role_id(role)?)?)
    }

    /// Remove someone from the space. The instance stops serving them every channel at once;
    /// their device still holds each encrypted channel's group until a member runs
    /// [`Session::remove_departed`] there.
    pub fn kick(&self, space: &str, user: &str) -> Result<(), SessionError> {
        Ok(self.client.kick(space_id(space)?, user_id(user)?)?)
    }

    pub fn leave_space(&self, space: &str) -> Result<(), SessionError> {
        Ok(self.client.kick(space_id(space)?, self.client.user())?)
    }

    pub fn create_space_invite(
        &self,
        space: &str,
        uses: u32,
        hours: i64,
    ) -> Result<String, SessionError> {
        let expires = (hours > 0).then(|| now_ms() + hours * 3_600_000);
        Ok(self.client.create_space_invite(space_id(space)?, uses, expires)?)
    }

    /// Join a space. Like a room invite, it grants no keys: each encrypted channel's group
    /// must still admit this device before anything in it is readable.
    pub fn redeem_space_invite(&self, token: &str) -> Result<String, SessionError> {
        Ok(self.client.redeem_space_invite(token)?.to_string())
    }

    /// Remove from the open room's encrypted group every account the instance no longer
    /// lists — a kicked member, someone whose role no longer reaches this channel.
    ///
    /// The cryptographic half of a kick. Until it runs, a removed device still holds the
    /// group's keys: the instance has stopped serving it ciphertext, which protects against
    /// everyone but the instance. After it, MLS's post-compromise security means the removed
    /// device cannot read what follows even if it is handed the ciphertext.
    ///
    /// **An action, never automatic**, like [`Session::admit_waiting`] and for the mirrored
    /// reason: the list is the instance's word. A malicious instance could use it to make
    /// this client eject people — which costs them nothing they could not already do by
    /// refusing to deliver, but should still be something a person chose.
    pub fn remove_departed(&mut self) -> Result<Vec<String>, SessionError> {
        let open = self.open.as_ref().ok_or(SessionError::NoRoomOpen)?;
        if open.convo.group_id().is_none() {
            return Err(SessionError::NoGroupYet);
        }
        let room = open.convo.room();
        let listed: Vec<UserId> =
            self.client.room_members(room)?.into_iter().map(|(u, _)| u).collect();
        let me = self.client.user();
        let departed: Vec<(u32, UserId)> = open
            .convo
            .members()
            .iter()
            .filter_map(|m| {
                let id = DeviceIdentity::parse(&m.identity).ok()?;
                (id.user() != me && !listed.contains(&id.user())).then(|| (m.index, id.user()))
            })
            .collect();

        let open = self.open.as_mut().ok_or(SessionError::NoRoomOpen)?;
        let mut removed: Vec<String> = Vec::new();
        for (index, user) in departed {
            let group = open.convo.group_mut().ok_or(SessionError::NoGroupYet)?;
            let output = group.remove_member(index)?;
            let commit = output.commit.to_bytes().map_err(|_| SessionError::NoGroupYet)?;
            let wrapped = open.convo.wrap_handshake(&commit, now_ms())?;
            self.client.send(room, &wrapped)?;
            let user = user.to_string();
            if !removed.contains(&user) {
                removed.push(user);
            }
        }
        self.index.record(room, &open.seal, open.convo.group_id())?;
        Ok(removed)
    }
}

fn display(view: &SpaceView, me: UserId, channels: Vec<ChannelDisplay>) -> SpaceDisplay {
    SpaceDisplay {
        id: view.id.to_string(),
        name: view.name.clone(),
        owner: view.owner.to_string(),
        i_am_owner: view.owner == me,
        my_permissions: view.my_permissions.names(),
        everyone: view.everyone.names(),
        everyone_manageable: view.everyone_manageable,
        roles: view
            .roles
            .iter()
            .map(|r| RoleDisplay {
                id: r.id.to_string(),
                name: r.name.clone(),
                permissions: r.permissions.names(),
                position: r.position,
                manageable: r.manageable,
                assignable: r.assignable,
            })
            .collect(),
        members: view
            .members
            .iter()
            .map(|m| SpaceMemberDisplay {
                user: m.user.to_string(),
                roles: m.roles.iter().map(ToString::to_string).collect(),
                owner: m.owner,
                manageable: m.manageable,
                roles_editable: m.roles_editable,
            })
            .collect(),
        channels,
        visibility_note: VISIBILITY_NOTE,
    }
}
