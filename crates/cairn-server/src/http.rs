//! HTTP surface.
//!
//! A thin translation layer over [`crate::state::Instance`]. All rules live in `state`;
//! this module only maps them onto status codes.
//!
//! This is a development API, not the eventual wire protocol — see
//! `docs/03-protocol-evaluation.md`. It exists so the vertical slice is exercisable
//! end to end.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use cairn_crypto::TranscriptReport;
use cairn_proto::{Envelope, RoomId, RoomShape};

use crate::state::{ServerError, SharedInstance};

pub fn router(instance: SharedInstance) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/v1/devices", post(register_device))
        .route("/v1/rooms", post(create_room))
        .route("/v1/rooms/{room}", get(describe_room))
        .route("/v1/rooms/{room}/messages", post(send_message).get(fetch_messages))
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
            ServerError::DeviceAlreadyRegistered => StatusCode::CONFLICT,
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
struct RegisterDeviceRequest {
    user: uuid::Uuid,
    device: uuid::Uuid,
    /// Hex-encoded signature public key.
    public_key: String,
}

/// Register a device's signing key.
///
/// There is no account system yet, so anyone may claim any `user` on first registration.
/// That is a real gap — it means account *creation* is unauthenticated even though
/// message *sending* now is not. What this does provide is that once a device is bound to
/// an account, nobody else can send as that account without its key.
async fn register_device(
    State(instance): State<SharedInstance>,
    Json(req): Json<RegisterDeviceRequest>,
) -> Result<StatusCode, ServerError> {
    let public_key = hex::decode(&req.public_key).map_err(|_| ServerError::BadSignature)?;
    instance.register_device(
        cairn_proto::UserId::from_uuid(req.user),
        cairn_proto::DeviceId::from_uuid(req.device),
        &public_key,
    )?;
    Ok(StatusCode::CREATED)
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
    Json(req): Json<CreateRoomRequest>,
) -> Result<Json<CreateRoomResponse>, ServerError> {
    let (room, seal) = instance.create_room(RoomShape {
        is_direct: req.is_direct,
        is_publicly_discoverable: req.is_publicly_discoverable,
        member_ceiling: req.member_ceiling,
    })?;
    Ok(Json(CreateRoomResponse { room, tier: seal.tier().label(), e2ee: seal.tier().is_e2ee() }))
}

/// Describe a room, so a client can display its tier.
///
/// The tier must be shown at all times (`docs/02-encryption-tiers.md` §4), so a client
/// needs to be able to ask for it without having sent or received anything.
async fn describe_room(
    State(instance): State<SharedInstance>,
    Path(room): Path<uuid::Uuid>,
) -> Result<Json<CreateRoomResponse>, ServerError> {
    let room = RoomId::from_uuid(room);
    let seal = instance.room_seal(room).ok_or(ServerError::NoSuchRoom)?;
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
    Query(since): Query<Since>,
) -> Result<Json<Vec<FetchedMessage>>, ServerError> {
    let messages = instance.messages_since(RoomId::from_uuid(room), since.after)?;
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
