//! HTTP surface.
//!
//! A thin translation layer over [`crate::state::Instance`]. All rules live in `state`;
//! this module only maps them onto status codes.
//!
//! This is a development API, not the eventual wire protocol — see
//! `docs/03-protocol-evaluation.md`. It exists so the vertical slice is exercisable
//! end to end.

use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::HeaderMap;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use cairn_crypto::TranscriptReport;
use cairn_proto::{Envelope, RoomId, RoomShape};

use crate::state::{ServerError, SharedInstance};

pub fn router(instance: SharedInstance) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/v1/accounts", post(claim_account))
        .route("/v1/devices", post(link_device))
        .route("/v1/rooms", post(create_room))
        .route("/v1/rooms/{room}", get(describe_room))
        .route("/v1/rooms/{room}/messages", post(send_message).get(fetch_messages))
        .route("/v1/rooms/{room}/members", post(add_room_member))
        .route("/v1/rooms/{room}/members/{target}", delete(remove_room_member).put(set_room_role))
        .route("/v1/rooms/{room}/join", post(join_room))
        .route("/v1/devices/{device}/key-packages", post(publish_key_packages))
        .route("/v1/users/{user}/key-packages", post(claim_key_packages))
        // The framework's default body limit is 2 MiB, which sat in front of the instance's
        // own ceiling and rejected a 5 MiB upload before `store_blob` ever ran — so
        // `MAX_BLOB_BYTES` was decorative and an operator raising it would have seen no
        // effect. Found by a test that uploaded a large-but-permitted attachment; the
        // undersized-rejection half alone would have passed against the broken behaviour.
        //
        // Set just above the instance's ceiling, so anything an operator would call
        // "too large" is refused by `state.rs` with the reason, while a genuinely enormous
        // body is still cut off before it is buffered.
        .route(
            "/v1/rooms/{room}/blobs",
            post(upload_blob)
                .layer(DefaultBodyLimit::max(crate::state::MAX_BLOB_BYTES + 64 * 1024)),
        )
        .route("/v1/blobs/{blob}", get(download_blob))
        .route("/v1/reports", post(submit_report))
        .with_state(instance)
}

impl IntoResponse for ServerError {
    fn into_response(self) -> Response {
        let status = match self {
            ServerError::NoSuchRoom => StatusCode::NOT_FOUND,
            ServerError::Rejected(_) | ServerError::Shape(_) | ServerError::BadCommitment => {
                StatusCode::BAD_REQUEST
            }
            // A storage failure is ours, not the caller's, and it means the write may not
            // be durable — so it must not be reported as success.
            ServerError::Storage(_) => StatusCode::INTERNAL_SERVER_ERROR,
            // Authentication failures are all 401 and all carry their own message. They
            // are deliberately not collapsed into one opaque error: an honest client with
            // an unregistered device needs to know that, and none of these distinctions
            // help an attacker, who already knows which part of the request they forged.
            ServerError::Unsigned
            | ServerError::UnknownDevice
            | ServerError::BadSignature
            | ServerError::DeviceUserMismatch => StatusCode::UNAUTHORIZED,
            ServerError::DeviceAlreadyRegistered | ServerError::AccountAlreadyClaimed => {
                StatusCode::CONFLICT
            }
            ServerError::NoSuchAccount => StatusCode::NOT_FOUND,
            ServerError::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            ServerError::NoSuchBlob => StatusCode::NOT_FOUND,
            // 413 rather than 400: the request was well-formed, the instance just will not
            // hold something this big. An operator raising the ceiling changes the answer.
            ServerError::BlobTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            ServerError::BlobEmpty => StatusCode::BAD_REQUEST,
            // Authorization failures on device linking. Distinguishable because an honest
            // client needs to know which of its inputs was wrong, and an attacker already
            // knows what they forged.
            ServerError::AuthorizingDeviceNotOnAccount
            | ServerError::BadDeviceAuthorization
            | ServerError::InviteRequired
            | ServerError::InviteInvalid
            | ServerError::BadRequestAuth
            | ServerError::RequestExpired => StatusCode::UNAUTHORIZED,
            // Membership failures are 403, not 404: the caller proved who they are, and
            // hiding the room's existence would be pretence — they already hold its id.
            ServerError::NotAMember
            | ServerError::RoomNotOpen
            | ServerError::InsufficientRole
            | ServerError::LastOwner => StatusCode::FORBIDDEN,
            ServerError::TargetNotAMember => StatusCode::NOT_FOUND,
            ServerError::RoomFull => StatusCode::CONFLICT,
            // Publishing for a device you do not own is an authorization failure, not a
            // bad request: the caller is authenticated, just not entitled.
            ServerError::NotYourDevice => StatusCode::FORBIDDEN,
            ServerError::BadKeyPackage => StatusCode::BAD_REQUEST,
            // 409, not 404. The account exists and may be addable later; a 404 would tell
            // the caller to stop trying, which is the wrong instruction.
            ServerError::NoKeyPackages | ServerError::TooManyKeyPackages => StatusCode::CONFLICT,
        };
        (status, Json(ErrorBody { error: self.to_string() })).into_response()
    }
}

#[derive(Serialize)]
struct ErrorBody {
    error: String,
}

async fn health() -> &'static str {
    "ok"
}

#[derive(Deserialize)]
struct ClaimAccountRequest {
    user: uuid::Uuid,
    device: uuid::Uuid,
    /// Hex-encoded signature public key.
    public_key: String,
    /// Required unless the instance's registration policy is `open`.
    #[serde(default)]
    invite: Option<String>,
}

/// Claim a user id, creating the account and registering its first device.
///
/// A user id is public — it appears on every message the account sends — so this is the
/// only point at which one becomes owned. Once claimed, adding further devices requires
/// authorization from a device already on the account.
async fn claim_account(
    State(instance): State<SharedInstance>,
    Json(req): Json<ClaimAccountRequest>,
) -> Result<StatusCode, ServerError> {
    let public_key = hex::decode(&req.public_key).map_err(|_| ServerError::BadSignature)?;
    instance.claim_account(
        cairn_proto::UserId::from_uuid(req.user),
        cairn_proto::DeviceId::from_uuid(req.device),
        &public_key,
        req.invite.as_deref(),
        now_ms(),
    )?;
    Ok(StatusCode::CREATED)
}

#[derive(Deserialize)]
struct LinkDeviceRequest {
    user: uuid::Uuid,
    device: uuid::Uuid,
    public_key: String,
    /// A device already on the account, which vouches for the new one.
    authorizing_device: uuid::Uuid,
    /// Hex signature by `authorizing_device` over `device_authorization_bytes`.
    authorization: String,
}

/// Add a device to an existing account.
async fn link_device(
    State(instance): State<SharedInstance>,
    Json(req): Json<LinkDeviceRequest>,
) -> Result<StatusCode, ServerError> {
    let public_key = hex::decode(&req.public_key).map_err(|_| ServerError::BadSignature)?;
    let authorization =
        hex::decode(&req.authorization).map_err(|_| ServerError::BadDeviceAuthorization)?;
    instance.link_device(
        cairn_proto::UserId::from_uuid(req.user),
        cairn_proto::DeviceId::from_uuid(req.device),
        &public_key,
        cairn_proto::DeviceId::from_uuid(req.authorizing_device),
        &authorization,
    )?;
    Ok(StatusCode::CREATED)
}

/// Authenticate a non-message request from its headers and return the acting account.
///
/// Membership checks in the state layer are only as good as the identity they are checked
/// against, so every membership-gated endpoint proves the caller's account first.
fn signed_actor(
    instance: &SharedInstance,
    headers: &HeaderMap,
    action: &str,
    resource: Option<cairn_proto::ResourceRef>,
) -> Result<cairn_proto::UserId, ServerError> {
    fn header<'a>(h: &'a HeaderMap, name: &str) -> Result<&'a str, ServerError> {
        h.get(name).and_then(|v| v.to_str().ok()).ok_or(ServerError::BadRequestAuth)
    }

    let device = header(headers, "x-cairn-device")?
        .parse::<uuid::Uuid>()
        .map_err(|_| ServerError::BadRequestAuth)?;
    let issued_at: i64 =
        header(headers, "x-cairn-timestamp")?.parse().map_err(|_| ServerError::BadRequestAuth)?;
    let signature = hex::decode(header(headers, "x-cairn-signature")?)
        .map_err(|_| ServerError::BadRequestAuth)?;

    instance.authenticate_request(
        cairn_proto::DeviceId::from_uuid(device),
        action,
        resource,
        issued_at,
        &signature,
        now_ms(),
    )
}

#[derive(Deserialize)]
struct RoomMemberRequest {
    user: uuid::Uuid,
}

/// Add an account to a room. The caller must already be a member.
async fn add_room_member(
    State(instance): State<SharedInstance>,
    Path(room): Path<uuid::Uuid>,
    headers: HeaderMap,
    Json(req): Json<RoomMemberRequest>,
) -> Result<StatusCode, ServerError> {
    let room = RoomId::from_uuid(room);
    let actor = signed_actor(&instance, &headers, "add_member", Some(room.into()))?;
    instance.add_room_member(room, actor, cairn_proto::UserId::from_uuid(req.user))?;
    Ok(StatusCode::CREATED)
}

/// Remove an account from a room, or leave it.
async fn remove_room_member(
    State(instance): State<SharedInstance>,
    Path((room, target)): Path<(uuid::Uuid, uuid::Uuid)>,
    headers: HeaderMap,
) -> Result<StatusCode, ServerError> {
    let room = RoomId::from_uuid(room);
    let actor = signed_actor(&instance, &headers, "remove_member", Some(room.into()))?;
    instance.remove_room_member(room, actor, cairn_proto::UserId::from_uuid(target))?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct SetRoleRequest {
    role: crate::state::RoomRole,
}

/// Change an account's role in a room. Owners only.
async fn set_room_role(
    State(instance): State<SharedInstance>,
    Path((room, target)): Path<(uuid::Uuid, uuid::Uuid)>,
    headers: HeaderMap,
    Json(req): Json<SetRoleRequest>,
) -> Result<StatusCode, ServerError> {
    let room = RoomId::from_uuid(room);
    let actor = signed_actor(&instance, &headers, "set_role", Some(room.into()))?;
    instance.set_room_role(room, actor, cairn_proto::UserId::from_uuid(target), req.role)?;
    Ok(StatusCode::NO_CONTENT)
}

/// Join a room that is open to anyone. Refused for private rooms.
async fn join_room(
    State(instance): State<SharedInstance>,
    Path(room): Path<uuid::Uuid>,
    headers: HeaderMap,
) -> Result<StatusCode, ServerError> {
    let room = RoomId::from_uuid(room);
    let actor = signed_actor(&instance, &headers, "join", Some(room.into()))?;
    instance.join_room(room, actor)?;
    Ok(StatusCode::CREATED)
}

#[derive(Deserialize)]
struct PublishKeyPackagesRequest {
    /// Hex-encoded MLS key package messages.
    packages: Vec<String>,
}

#[derive(Serialize)]
struct PublishKeyPackagesResponse {
    /// How many the device now has unclaimed, so a client knows when to top up.
    remaining: usize,
}

/// Publish key packages for one of the caller's own devices.
async fn publish_key_packages(
    State(instance): State<SharedInstance>,
    Path(device): Path<uuid::Uuid>,
    headers: HeaderMap,
    Json(req): Json<PublishKeyPackagesRequest>,
) -> Result<(StatusCode, Json<PublishKeyPackagesResponse>), ServerError> {
    let device = cairn_proto::DeviceId::from_uuid(device);
    let actor = signed_actor(&instance, &headers, "publish_key_packages", Some(device.into()))?;
    let remaining = instance.publish_key_packages(actor, device, req.packages)?;
    Ok((StatusCode::CREATED, Json(PublishKeyPackagesResponse { remaining })))
}

#[derive(Serialize)]
struct ClaimedKeyPackage {
    device: cairn_proto::DeviceId,
    key_package: String,
}

/// Claim one key package for each of an account's devices, consuming them.
///
/// `POST` rather than `GET` because it mutates: each call permanently consumes packages.
/// A `GET` here would be cached and retried by every intermediary that assumes reads are
/// safe, and each retry would silently burn another set.
///
/// Authenticated, because an anonymous caller could otherwise drain any account's supply
/// and make it unaddable. Authentication bounds that to accounts on the instance rather
/// than preventing it — a hostile member can still drain another member, and there is no
/// rate limiting yet (`docs/10-roadmap.md` M3).
async fn claim_key_packages(
    State(instance): State<SharedInstance>,
    Path(user): Path<uuid::Uuid>,
    headers: HeaderMap,
) -> Result<Json<Vec<ClaimedKeyPackage>>, ServerError> {
    let user = cairn_proto::UserId::from_uuid(user);
    let actor = signed_actor(&instance, &headers, "claim_key_packages", Some(user.into()))?;
    let claimed = instance.claim_key_packages(actor, user, now_ms())?;
    Ok(Json(
        claimed
            .into_iter()
            .map(|(device, key_package)| ClaimedKeyPackage { device, key_package })
            .collect(),
    ))
}

#[derive(Serialize)]
struct UploadedBlob {
    blob: String,
}

/// Store an encrypted attachment. The body is raw ciphertext.
///
/// Deliberately not JSON: base64 in a JSON envelope would inflate every attachment by a
/// third for no benefit, and the server has no reason to parse bytes it cannot read.
async fn upload_blob(
    State(instance): State<SharedInstance>,
    Path(room): Path<uuid::Uuid>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<(StatusCode, Json<UploadedBlob>), ServerError> {
    let room = cairn_proto::RoomId::from_uuid(room);
    let actor = signed_actor(&instance, &headers, "upload_blob", Some(room.into()))?;
    let id = instance.store_blob(actor, room, body.to_vec())?;
    Ok((StatusCode::CREATED, Json(UploadedBlob { blob: id.to_string() })))
}

/// Fetch an encrypted attachment, for a member of the room it belongs to.
async fn download_blob(
    State(instance): State<SharedInstance>,
    Path(blob): Path<uuid::Uuid>,
    headers: HeaderMap,
) -> Result<(StatusCode, [(axum::http::header::HeaderName, &'static str); 1], Vec<u8>), ServerError>
{
    let blob = cairn_proto::BlobId::from_uuid(blob);
    let actor = signed_actor(&instance, &headers, "download_blob", Some(blob.into()))?;
    let bytes = instance.fetch_blob(actor, blob)?;
    Ok((StatusCode::OK, [(axum::http::header::CONTENT_TYPE, "application/octet-stream")], bytes))
}

fn now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

#[derive(Deserialize)]
struct CreateRoomRequest {
    #[serde(default)]
    is_direct: bool,
    #[serde(default)]
    is_publicly_discoverable: bool,
    member_ceiling: u32,
}

#[derive(Serialize)]
struct CreateRoomResponse {
    room: RoomId,
    /// The tier label, so a client can display it immediately. Per
    /// `docs/02-encryption-tiers.md` §4 this must be surfaced in the UI at all times.
    tier: &'static str,
    e2ee: bool,
}

async fn create_room(
    State(instance): State<SharedInstance>,
    headers: HeaderMap,
    Json(req): Json<CreateRoomRequest>,
) -> Result<Json<CreateRoomResponse>, ServerError> {
    let creator = signed_actor(&instance, &headers, "create_room", None)?;
    let (room, seal) = instance.create_room(
        RoomShape {
            is_direct: req.is_direct,
            is_publicly_discoverable: req.is_publicly_discoverable,
            member_ceiling: req.member_ceiling,
        },
        creator,
    )?;
    Ok(Json(CreateRoomResponse { room, tier: seal.tier().label(), e2ee: seal.tier().is_e2ee() }))
}

/// Describe a room, so a client can display its tier.
///
/// The tier must be shown at all times (`docs/02-encryption-tiers.md` §4), so a client
/// needs to be able to ask for it without having sent or received anything.
async fn describe_room(
    State(instance): State<SharedInstance>,
    Path(room): Path<uuid::Uuid>,
    headers: HeaderMap,
) -> Result<Json<CreateRoomResponse>, ServerError> {
    let room = RoomId::from_uuid(room);
    let seal = instance.room_seal(room).ok_or(ServerError::NoSuchRoom)?;

    // A public room is discoverable by definition, so describing it reveals nothing its
    // tier does not already concede. A private one must not confirm its own existence to
    // a stranger holding the id, which was previously free.
    if !seal.may_mint_public_invite() {
        let actor = signed_actor(&instance, &headers, "describe", Some(room.into()))?;
        if instance.room_role(room, actor).is_none() {
            return Err(ServerError::NotAMember);
        }
    }
    Ok(Json(CreateRoomResponse { room, tier: seal.tier().label(), e2ee: seal.tier().is_e2ee() }))
}

#[derive(Serialize)]
struct SendResponse {
    server_seq: u64,
    /// Hex franking tag, returned so the sender's peers can retain it for reports.
    #[serde(skip_serializing_if = "Option::is_none")]
    franking_tag: Option<String>,
}

async fn send_message(
    State(instance): State<SharedInstance>,
    Path(_room): Path<String>,
    Json(envelope): Json<Envelope>,
) -> Result<Json<SendResponse>, ServerError> {
    let stored = instance.accept(envelope)?;
    Ok(Json(SendResponse {
        server_seq: stored.server_seq,
        franking_tag: stored.franking_tag.map(|t| hex::encode(t.0)),
    }))
}

#[derive(Deserialize)]
struct Since {
    #[serde(default)]
    after: u64,
}

#[derive(Serialize)]
struct FetchedMessage {
    envelope: Envelope,
    server_seq: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    franking_tag: Option<String>,
}

async fn fetch_messages(
    State(instance): State<SharedInstance>,
    Path(room): Path<uuid::Uuid>,
    headers: HeaderMap,
    Query(since): Query<Since>,
) -> Result<Json<Vec<FetchedMessage>>, ServerError> {
    let room = RoomId::from_uuid(room);
    let actor = signed_actor(&instance, &headers, "read", Some(room.into()))?;
    let messages = instance.messages_since(room, actor, since.after)?;
    Ok(Json(
        messages
            .into_iter()
            .map(|m| FetchedMessage {
                envelope: m.envelope,
                server_seq: m.server_seq,
                franking_tag: m.franking_tag.map(|t| hex::encode(t.0)),
            })
            .collect(),
    ))
}

#[derive(Serialize)]
struct ReportResponse {
    verified: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    message_count: usize,
}

/// Verify a franking report.
///
/// A `verified: false` response is not a server error — it means the report did not hold
/// up, which is exactly what the mechanism is for. Returning 200 with a verdict keeps the
/// distinction between "your request was malformed" and "your evidence did not verify".
async fn submit_report(
    State(instance): State<SharedInstance>,
    Json(report): Json<TranscriptReport>,
) -> Json<ReportResponse> {
    let count = report.messages.len();
    match instance.verify_report(&report) {
        Ok(()) => Json(ReportResponse { verified: true, reason: None, message_count: count }),
        Err(e) => Json(ReportResponse {
            verified: false,
            reason: Some(e.to_string()),
            message_count: count,
        }),
    }
}
