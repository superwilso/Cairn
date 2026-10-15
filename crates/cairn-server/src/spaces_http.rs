//! HTTP surface for spaces, channels and roles.
//!
//! Translation only, like [`crate::http`]: authenticate, parse, call one method on
//! [`crate::state::Instance`], map the answer. Every rule — who may create a channel, which
//! roles an actor may hand out, what a kick does — is in `state.rs`, where it is tested
//! without a socket. A rule added here would be untested and bypassable by any other route to
//! the same method.
//!
//! Each request is signed over the space *and* the path's other targets
//! ([`cairn_proto::space_action`]), so a captured "assign R to Bob" cannot be replayed as
//! "assign R to Mallory". Mutation bodies refuse unknown fields: a client sending `tier`
//! with a rename is told no, rather than having the field silently dropped while it believes
//! something changed.

use axum::extract::{FromRef, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{delete, get, patch, post, put};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use cairn_proto::{space_action, Permissions, RoleId, RoomId, SpaceId, UserId};

use crate::http::{now_ms, signed_actor};
use crate::state::{ServerError, SharedInstance, SpaceSummary, SpaceView};

/// The routes, to be merged into the instance's router.
pub(crate) fn routes<S>() -> Router<S>
where
    SharedInstance: FromRef<S>,
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        .route("/v1/spaces", post(create_space).get(list_spaces))
        .route("/v1/spaces/{space}", get(describe_space))
        .route("/v1/spaces/{space}/channels", post(create_channel))
        .route("/v1/spaces/{space}/channels/{room}", patch(rename_channel).delete(delete_channel))
        .route(
            "/v1/spaces/{space}/channels/{room}/overrides/{target}",
            put(set_override).delete(clear_override),
        )
        .route("/v1/spaces/{space}/roles", post(create_role))
        .route("/v1/spaces/{space}/roles/{target}", patch(edit_role).delete(delete_role))
        .route("/v1/spaces/{space}/members/{user}", delete(kick))
        .route(
            "/v1/spaces/{space}/members/{user}/roles/{role}",
            put(assign_role).delete(unassign_role),
        )
        .route("/v1/spaces/{space}/bars/{user}", delete(unbar))
        .route("/v1/spaces/{space}/invites", post(create_invite))
        // Not under `/v1/spaces/…`: the redeemer is not yet in any space, and the token is
        // the only thing that names one.
        .route("/v1/space-invites/redeem", post(redeem_invite))
}

/// `everyone` or a role id, as a path segment.
fn role_target(segment: &str) -> Result<Option<RoleId>, ServerError> {
    if segment == "everyone" {
        return Ok(None);
    }
    segment.parse::<RoleId>().map(Some).map_err(|_| ServerError::NoSuchRole)
}

/// The uuid signed for a role target. `@everyone` is the nil uuid, which no role can have.
fn target_uuid(role: Option<RoleId>) -> uuid::Uuid {
    role.map(|r| *r.as_uuid()).unwrap_or_else(uuid::Uuid::nil)
}

fn bits(raw: u32) -> Result<Permissions, ServerError> {
    Permissions::from_bits(raw).ok_or(ServerError::UnknownPermission)
}

fn actor_for(
    instance: &SharedInstance,
    headers: &HeaderMap,
    space: SpaceId,
    verb: &str,
    targets: &[&uuid::Uuid],
) -> Result<UserId, ServerError> {
    signed_actor(instance, headers, &space_action(verb, targets), Some(space.into()))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateSpaceRequest {
    name: String,
    member_ceiling: u32,
}

#[derive(Serialize)]
struct CreatedSpace {
    space: SpaceId,
}

async fn create_space(
    State(instance): State<SharedInstance>,
    headers: HeaderMap,
    Json(req): Json<CreateSpaceRequest>,
) -> Result<(StatusCode, Json<CreatedSpace>), ServerError> {
    let actor = signed_actor(&instance, &headers, "space.create", None)?;
    let space = instance.create_space(actor, &req.name, req.member_ceiling)?;
    Ok((StatusCode::CREATED, Json(CreatedSpace { space })))
}

async fn list_spaces(
    State(instance): State<SharedInstance>,
    headers: HeaderMap,
) -> Result<Json<Vec<SpaceSummary>>, ServerError> {
    let actor = signed_actor(&instance, &headers, "space.list", None)?;
    Ok(Json(instance.spaces_of(actor)))
}

async fn describe_space(
    State(instance): State<SharedInstance>,
    Path(space): Path<SpaceId>,
    headers: HeaderMap,
) -> Result<Json<SpaceView>, ServerError> {
    let actor = actor_for(&instance, &headers, space, "describe", &[])?;
    Ok(Json(instance.describe_space(space, actor)?))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateChannelRequest {
    name: String,
    /// Publicly discoverable, so T3 and readable by the instance. Off unless asked for.
    #[serde(default)]
    public: bool,
}

#[derive(Serialize)]
struct CreatedChannel {
    room: RoomId,
    tier: &'static str,
    e2ee: bool,
}

async fn create_channel(
    State(instance): State<SharedInstance>,
    Path(space): Path<SpaceId>,
    headers: HeaderMap,
    Json(req): Json<CreateChannelRequest>,
) -> Result<(StatusCode, Json<CreatedChannel>), ServerError> {
    let actor = actor_for(&instance, &headers, space, "create_channel", &[])?;
    let (room, seal) = instance.create_channel(space, actor, &req.name, req.public)?;
    Ok((
        StatusCode::CREATED,
        Json(CreatedChannel { room, tier: seal.tier().label(), e2ee: seal.tier().is_e2ee() }),
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RenameChannelRequest {
    name: String,
}

async fn rename_channel(
    State(instance): State<SharedInstance>,
    Path((space, room)): Path<(SpaceId, RoomId)>,
    headers: HeaderMap,
    Json(req): Json<RenameChannelRequest>,
) -> Result<StatusCode, ServerError> {
    let actor = actor_for(&instance, &headers, space, "rename_channel", &[room.as_uuid()])?;
    instance.rename_channel(space, actor, room, &req.name)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn delete_channel(
    State(instance): State<SharedInstance>,
    Path((space, room)): Path<(SpaceId, RoomId)>,
    headers: HeaderMap,
) -> Result<StatusCode, ServerError> {
    let actor = actor_for(&instance, &headers, space, "delete_channel", &[room.as_uuid()])?;
    instance.delete_channel(space, actor, room)?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OverrideRequest {
    #[serde(default)]
    allow: u32,
    #[serde(default)]
    deny: u32,
}

async fn set_override(
    State(instance): State<SharedInstance>,
    Path((space, room, target)): Path<(SpaceId, RoomId, String)>,
    headers: HeaderMap,
    Json(req): Json<OverrideRequest>,
) -> Result<StatusCode, ServerError> {
    let role = role_target(&target)?;
    let t = target_uuid(role);
    let actor = actor_for(&instance, &headers, space, "set_override", &[room.as_uuid(), &t])?;
    instance.set_channel_override(space, actor, room, role, bits(req.allow)?, bits(req.deny)?)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn clear_override(
    State(instance): State<SharedInstance>,
    Path((space, room, target)): Path<(SpaceId, RoomId, String)>,
    headers: HeaderMap,
) -> Result<StatusCode, ServerError> {
    let role = role_target(&target)?;
    let t = target_uuid(role);
    let actor = actor_for(&instance, &headers, space, "clear_override", &[room.as_uuid(), &t])?;
    instance.set_channel_override(
        space,
        actor,
        room,
        role,
        Permissions::NONE,
        Permissions::NONE,
    )?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateRoleRequest {
    name: String,
    permissions: u32,
    position: u32,
}

#[derive(Serialize)]
struct CreatedRole {
    role: RoleId,
}

async fn create_role(
    State(instance): State<SharedInstance>,
    Path(space): Path<SpaceId>,
    headers: HeaderMap,
    Json(req): Json<CreateRoleRequest>,
) -> Result<(StatusCode, Json<CreatedRole>), ServerError> {
    let actor = actor_for(&instance, &headers, space, "create_role", &[])?;
    let role =
        instance.create_role(space, actor, &req.name, bits(req.permissions)?, req.position)?;
    Ok((StatusCode::CREATED, Json(CreatedRole { role })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EditRoleRequest {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    permissions: Option<u32>,
    #[serde(default)]
    position: Option<u32>,
}

async fn edit_role(
    State(instance): State<SharedInstance>,
    Path((space, target)): Path<(SpaceId, String)>,
    headers: HeaderMap,
    Json(req): Json<EditRoleRequest>,
) -> Result<StatusCode, ServerError> {
    let role = role_target(&target)?;
    let t = target_uuid(role);
    let actor = actor_for(&instance, &headers, space, "edit_role", &[&t])?;
    let permissions = req.permissions.map(bits).transpose()?;
    instance.edit_role(space, actor, role, req.name.as_deref(), permissions, req.position)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn delete_role(
    State(instance): State<SharedInstance>,
    Path((space, role)): Path<(SpaceId, RoleId)>,
    headers: HeaderMap,
) -> Result<StatusCode, ServerError> {
    let actor = actor_for(&instance, &headers, space, "delete_role", &[role.as_uuid()])?;
    instance.delete_role(space, actor, role)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn assign_role(
    State(instance): State<SharedInstance>,
    Path((space, user, role)): Path<(SpaceId, UserId, RoleId)>,
    headers: HeaderMap,
) -> Result<StatusCode, ServerError> {
    let actor =
        actor_for(&instance, &headers, space, "assign_role", &[user.as_uuid(), role.as_uuid()])?;
    instance.assign_role(space, actor, user, role)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn unassign_role(
    State(instance): State<SharedInstance>,
    Path((space, user, role)): Path<(SpaceId, UserId, RoleId)>,
    headers: HeaderMap,
) -> Result<StatusCode, ServerError> {
    let actor =
        actor_for(&instance, &headers, space, "unassign_role", &[user.as_uuid(), role.as_uuid()])?;
    instance.unassign_role(space, actor, user, role)?;
    Ok(StatusCode::NO_CONTENT)
}

/// Kick a member, or leave when the path names the caller.
async fn kick(
    State(instance): State<SharedInstance>,
    Path((space, user)): Path<(SpaceId, UserId)>,
    headers: HeaderMap,
) -> Result<StatusCode, ServerError> {
    let actor = actor_for(&instance, &headers, space, "kick", &[user.as_uuid()])?;
    instance.kick_from_space(space, actor, user)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn unbar(
    State(instance): State<SharedInstance>,
    Path((space, user)): Path<(SpaceId, UserId)>,
    headers: HeaderMap,
) -> Result<StatusCode, ServerError> {
    let actor = actor_for(&instance, &headers, space, "unbar", &[user.as_uuid()])?;
    instance.unbar_from_space(space, actor, user)?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateInviteRequest {
    uses: u32,
    #[serde(default)]
    expires_at_ms: Option<i64>,
}

#[derive(Serialize)]
struct MintedInvite {
    /// Returned **once**; only a hash is stored.
    token: String,
}

async fn create_invite(
    State(instance): State<SharedInstance>,
    Path(space): Path<SpaceId>,
    headers: HeaderMap,
    Json(req): Json<CreateInviteRequest>,
) -> Result<(StatusCode, Json<MintedInvite>), ServerError> {
    let actor = actor_for(&instance, &headers, space, "create_invite", &[])?;
    let token = instance.create_space_invite(space, actor, req.uses, req.expires_at_ms)?;
    Ok((StatusCode::CREATED, Json(MintedInvite { token })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RedeemRequest {
    token: String,
}

#[derive(Serialize)]
struct Redeemed {
    space: SpaceId,
}

/// The token is in the body, not the path: a path lands in access logs, and this is a
/// credential.
async fn redeem_invite(
    State(instance): State<SharedInstance>,
    headers: HeaderMap,
    Json(req): Json<RedeemRequest>,
) -> Result<Json<Redeemed>, ServerError> {
    let actor = signed_actor(&instance, &headers, "space.redeem_invite", None)?;
    let space = instance.redeem_space_invite(actor, &req.token, now_ms())?;
    Ok(Json(Redeemed { space }))
}
