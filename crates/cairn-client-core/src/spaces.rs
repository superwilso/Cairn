//! Spaces, channels and roles: the client's half.
//!
//! **The instance decides every permission.** This module asks, signs, and checks what comes
//! back for consistency; it does not compute who may do what. A space's view arrives with the
//! viewer's permissions and a `manageable` flag on every role and member already worked out
//! by `cairn-server`'s `state.rs`, and a frontend renders those flags. A client that computed
//! the hierarchy itself would hold a second copy of the rule — the one nobody tests, and the
//! one a modified client ignores anyway (`docs/01-threat-model.md` §7).
//!
//! What a client *can* check is the tier, because the rule for it is published: a channel's
//! shape is the space's sealed ceiling plus whether the channel is public, and
//! [`cairn_proto::derive_tier`] is a pure function of that. See ADR-011.

use serde::{Deserialize, Serialize};

use cairn_proto::{
    space_action, Permissions, ResourceRef, RoleId, RoomId, RoomSeal, RoomShape, SpaceId, UserId,
};

use crate::client::{Client, ClientError};
use crate::transport::Transport;

/// A space as the instance described it to this account.
#[derive(Debug, Clone, Deserialize)]
pub struct SpaceView {
    pub id: SpaceId,
    pub name: String,
    pub owner: UserId,
    pub member_ceiling: u32,
    pub my_permissions: Permissions,
    pub everyone: Permissions,
    pub everyone_manageable: bool,
    pub roles: Vec<RoleView>,
    pub members: Vec<SpaceMemberView>,
    pub channels: Vec<ChannelView>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RoleView {
    pub id: RoleId,
    pub name: String,
    pub permissions: Permissions,
    pub position: u32,
    pub manageable: bool,
    #[serde(default)]
    pub assignable: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SpaceMemberView {
    pub user: UserId,
    pub roles: Vec<RoleId>,
    pub owner: bool,
    pub manageable: bool,
    #[serde(default)]
    pub roles_editable: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ChannelView {
    pub room: RoomId,
    pub name: String,
    pub tier: String,
    pub e2ee: bool,
    pub my_permissions: Permissions,
    #[serde(default)]
    pub overrides: Option<Vec<OverrideView>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverrideView {
    pub role: Option<RoleId>,
    pub allow: Permissions,
    pub deny: Permissions,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SpaceSummary {
    pub id: SpaceId,
    pub name: String,
}

/// The seal a channel of this space must have, derived here from the published rule.
///
/// A channel's shape is never direct, takes the space's ceiling, and is discoverable only if
/// it was created public. For a channel this device created, `public` is what it asked for.
/// For one it did not, `public` can only be the instance's word — the space view says whether
/// a channel is encrypted, and nothing else on this device knows. What this still catches is
/// an instance contradicting the rule: claiming a channel is end-to-end encrypted in a space
/// whose ceiling makes that impossible, or claiming T1 for something that is not a DM.
pub fn channel_seal(member_ceiling: u32, public: bool) -> Result<RoomSeal, ClientError> {
    Ok(RoomSeal::new(RoomShape {
        is_direct: false,
        is_publicly_discoverable: public,
        member_ceiling,
    })?)
}

/// Check one listed channel against the rule, returning the seal to record for it.
pub fn checked_channel_seal(
    space: &SpaceView,
    channel: &ChannelView,
) -> Result<RoomSeal, ClientError> {
    let seal = channel_seal(space.member_ceiling, !channel.e2ee)?;
    agree(&seal, &channel.tier, channel.e2ee)?;
    Ok(seal)
}

fn agree(seal: &RoomSeal, tier: &str, e2ee: bool) -> Result<(), ClientError> {
    if tier != seal.tier().label() || e2ee != seal.tier().is_e2ee() {
        return Err(ClientError::TierDisagreement {
            local: seal.tier().label(),
            server: tier.to_string(),
        });
    }
    Ok(())
}

#[derive(Deserialize)]
struct CreatedSpace {
    space: SpaceId,
}

#[derive(Deserialize)]
struct CreatedChannel {
    room: RoomId,
    tier: String,
    e2ee: bool,
}

#[derive(Deserialize)]
struct CreatedRole {
    role: RoleId,
}

#[derive(Deserialize)]
struct Minted {
    token: String,
}

#[derive(Deserialize)]
struct Redeemed {
    space: SpaceId,
}

/// `@everyone` or a role, as the instance's paths spell them.
fn role_segment(role: Option<RoleId>) -> String {
    match role {
        None => "everyone".to_string(),
        Some(r) => r.as_uuid().to_string(),
    }
}

fn role_uuid(role: Option<RoleId>) -> uuid::Uuid {
    role.map(|r| *r.as_uuid()).unwrap_or_else(uuid::Uuid::nil)
}

impl<T: Transport> Client<T> {
    fn space_auth(
        &self,
        space: SpaceId,
        verb: &str,
        targets: &[&uuid::Uuid],
    ) -> Result<Vec<(&'static str, String)>, ClientError> {
        self.auth(&space_action(verb, targets), Some(ResourceRef::Space(space)))
    }

    /// Create a space this account owns. The ceiling is sealed and decides every channel's
    /// tier: above `T2_MAX_MEMBERS`, nothing in the space can be end-to-end encrypted.
    pub fn create_space(&self, name: &str, member_ceiling: u32) -> Result<SpaceId, ClientError> {
        let body =
            serde_json::json!({ "name": name, "member_ceiling": member_ceiling }).to_string();
        let r = self.call("POST", "/v1/spaces", &self.auth("space.create", None)?, Some(&body))?;
        Ok(serde_json::from_slice::<CreatedSpace>(&r.body)?.space)
    }

    pub fn spaces(&self) -> Result<Vec<SpaceSummary>, ClientError> {
        let r = self.call("GET", "/v1/spaces", &self.auth("space.list", None)?, None)?;
        Ok(serde_json::from_slice(&r.body)?)
    }

    pub fn describe_space(&self, space: SpaceId) -> Result<SpaceView, ClientError> {
        let r = self.call(
            "GET",
            &format!("/v1/spaces/{}", space.as_uuid()),
            &self.space_auth(space, "describe", &[])?,
            None,
        )?;
        Ok(serde_json::from_slice(&r.body)?)
    }

    /// Create a channel, refusing it if the instance sealed a different tier than the rule
    /// gives for what was asked. As [`Client::create_room`] does, and for the same reason: a
    /// badge that disagrees with what the client does is worse than no channel.
    pub fn create_channel(
        &self,
        space: SpaceId,
        member_ceiling: u32,
        name: &str,
        public: bool,
    ) -> Result<(RoomId, RoomSeal), ClientError> {
        let seal = channel_seal(member_ceiling, public)?;
        let body = serde_json::json!({ "name": name, "public": public }).to_string();
        let r = self.call(
            "POST",
            &format!("/v1/spaces/{}/channels", space.as_uuid()),
            &self.space_auth(space, "create_channel", &[])?,
            Some(&body),
        )?;
        let created: CreatedChannel = serde_json::from_slice(&r.body)?;
        agree(&seal, &created.tier, created.e2ee)?;
        Ok((created.room, seal))
    }

    pub fn rename_channel(
        &self,
        space: SpaceId,
        room: RoomId,
        name: &str,
    ) -> Result<(), ClientError> {
        let body = serde_json::json!({ "name": name }).to_string();
        self.call(
            "PATCH",
            &format!("/v1/spaces/{}/channels/{}", space.as_uuid(), room.as_uuid()),
            &self.space_auth(space, "rename_channel", &[room.as_uuid()])?,
            Some(&body),
        )?;
        Ok(())
    }

    pub fn delete_channel(&self, space: SpaceId, room: RoomId) -> Result<(), ClientError> {
        self.call(
            "DELETE",
            &format!("/v1/spaces/{}/channels/{}", space.as_uuid(), room.as_uuid()),
            &self.space_auth(space, "delete_channel", &[room.as_uuid()])?,
            None,
        )?;
        Ok(())
    }

    /// Set one channel override; both sets empty clears it.
    pub fn set_override(
        &self,
        space: SpaceId,
        room: RoomId,
        role: Option<RoleId>,
        allow: Permissions,
        deny: Permissions,
    ) -> Result<(), ClientError> {
        let body = serde_json::json!({ "allow": allow.bits(), "deny": deny.bits() }).to_string();
        let t = role_uuid(role);
        self.call(
            "PUT",
            &format!(
                "/v1/spaces/{}/channels/{}/overrides/{}",
                space.as_uuid(),
                room.as_uuid(),
                role_segment(role)
            ),
            &self.space_auth(space, "set_override", &[room.as_uuid(), &t])?,
            Some(&body),
        )?;
        Ok(())
    }

    pub fn create_role(
        &self,
        space: SpaceId,
        name: &str,
        permissions: Permissions,
        position: u32,
    ) -> Result<RoleId, ClientError> {
        let body = serde_json::json!({
            "name": name, "permissions": permissions.bits(), "position": position
        })
        .to_string();
        let r = self.call(
            "POST",
            &format!("/v1/spaces/{}/roles", space.as_uuid()),
            &self.space_auth(space, "create_role", &[])?,
            Some(&body),
        )?;
        Ok(serde_json::from_slice::<CreatedRole>(&r.body)?.role)
    }

    /// Edit a role, or `@everyone` when `role` is `None`.
    pub fn edit_role(
        &self,
        space: SpaceId,
        role: Option<RoleId>,
        name: Option<&str>,
        permissions: Option<Permissions>,
        position: Option<u32>,
    ) -> Result<(), ClientError> {
        let mut body = serde_json::Map::new();
        if let Some(n) = name {
            body.insert("name".into(), n.into());
        }
        if let Some(p) = permissions {
            body.insert("permissions".into(), p.bits().into());
        }
        if let Some(p) = position {
            body.insert("position".into(), p.into());
        }
        let t = role_uuid(role);
        self.call(
            "PATCH",
            &format!("/v1/spaces/{}/roles/{}", space.as_uuid(), role_segment(role)),
            &self.space_auth(space, "edit_role", &[&t])?,
            Some(&serde_json::Value::Object(body).to_string()),
        )?;
        Ok(())
    }

    pub fn delete_role(&self, space: SpaceId, role: RoleId) -> Result<(), ClientError> {
        self.call(
            "DELETE",
            &format!("/v1/spaces/{}/roles/{}", space.as_uuid(), role.as_uuid()),
            &self.space_auth(space, "delete_role", &[role.as_uuid()])?,
            None,
        )?;
        Ok(())
    }

    pub fn assign_role(
        &self,
        space: SpaceId,
        user: UserId,
        role: RoleId,
    ) -> Result<(), ClientError> {
        self.call(
            "PUT",
            &format!(
                "/v1/spaces/{}/members/{}/roles/{}",
                space.as_uuid(),
                user.as_uuid(),
                role.as_uuid()
            ),
            &self.space_auth(space, "assign_role", &[user.as_uuid(), role.as_uuid()])?,
            None,
        )?;
        Ok(())
    }

    pub fn unassign_role(
        &self,
        space: SpaceId,
        user: UserId,
        role: RoleId,
    ) -> Result<(), ClientError> {
        self.call(
            "DELETE",
            &format!(
                "/v1/spaces/{}/members/{}/roles/{}",
                space.as_uuid(),
                user.as_uuid(),
                role.as_uuid()
            ),
            &self.space_auth(space, "unassign_role", &[user.as_uuid(), role.as_uuid()])?,
            None,
        )?;
        Ok(())
    }

    /// Kick `user`, or leave when `user` is this account.
    pub fn kick(&self, space: SpaceId, user: UserId) -> Result<(), ClientError> {
        self.call(
            "DELETE",
            &format!("/v1/spaces/{}/members/{}", space.as_uuid(), user.as_uuid()),
            &self.space_auth(space, "kick", &[user.as_uuid()])?,
            None,
        )?;
        Ok(())
    }

    pub fn unbar(&self, space: SpaceId, user: UserId) -> Result<(), ClientError> {
        self.call(
            "DELETE",
            &format!("/v1/spaces/{}/bars/{}", space.as_uuid(), user.as_uuid()),
            &self.space_auth(space, "unbar", &[user.as_uuid()])?,
            None,
        )?;
        Ok(())
    }

    pub fn create_space_invite(
        &self,
        space: SpaceId,
        uses: u32,
        expires_at_ms: Option<i64>,
    ) -> Result<String, ClientError> {
        let body = serde_json::json!({ "uses": uses, "expires_at_ms": expires_at_ms }).to_string();
        let r = self.call(
            "POST",
            &format!("/v1/spaces/{}/invites", space.as_uuid()),
            &self.space_auth(space, "create_invite", &[])?,
            Some(&body),
        )?;
        Ok(serde_json::from_slice::<Minted>(&r.body)?.token)
    }

    pub fn redeem_space_invite(&self, token: &str) -> Result<SpaceId, ClientError> {
        let body = serde_json::json!({ "token": token }).to_string();
        let r = self.call(
            "POST",
            "/v1/space-invites/redeem",
            &self.auth("space.redeem_invite", None)?,
            Some(&body),
        )?;
        Ok(serde_json::from_slice::<Redeemed>(&r.body)?.space)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cairn_proto::Tier;

    fn view(ceiling: u32, tier: &str, e2ee: bool) -> (SpaceView, ChannelView) {
        let channel = ChannelView {
            room: RoomId::new(),
            name: "general".into(),
            tier: tier.into(),
            e2ee,
            my_permissions: Permissions::DEFAULT_EVERYONE,
            overrides: None,
        };
        let space = SpaceView {
            id: SpaceId::new(),
            name: "s".into(),
            owner: UserId::new(),
            member_ceiling: ceiling,
            my_permissions: Permissions::DEFAULT_EVERYONE,
            everyone: Permissions::DEFAULT_EVERYONE,
            everyone_manageable: false,
            roles: Vec::new(),
            members: Vec::new(),
            channels: vec![channel.clone()],
        };
        (space, channel)
    }

    #[test]
    fn an_instance_cannot_claim_encryption_the_spaces_ceiling_rules_out() {
        // A space of 50,000 cannot have an end-to-end encrypted channel. An instance saying
        // otherwise is refused, rather than the client drawing a T2 badge over a room whose
        // shape makes it public.
        let (space, channel) = view(50_000, "T2", true);
        assert!(matches!(
            checked_channel_seal(&space, &channel),
            Err(ClientError::TierDisagreement { .. })
        ));
    }

    #[test]
    fn a_channel_cannot_be_listed_as_a_dm() {
        let (space, channel) = view(50, "T1", true);
        assert!(checked_channel_seal(&space, &channel).is_err());
    }

    #[test]
    fn a_consistent_listing_yields_the_rules_seal() {
        let (space, channel) = view(50, "T2", true);
        assert_eq!(checked_channel_seal(&space, &channel).unwrap().tier(), Tier::PrivateCommunity);
        let (space, channel) = view(50, "T3", false);
        assert_eq!(checked_channel_seal(&space, &channel).unwrap().tier(), Tier::PublicCommunity);
    }
}
