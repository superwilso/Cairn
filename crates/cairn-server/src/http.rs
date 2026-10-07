//! HTTP surface.
//!
//! A thin translation layer over [`crate::state::Instance`]. All rules live in `state`;
//! this module only maps them onto status codes.
//!
//! This is a development API, not the eventual wire protocol — see
//! `docs/03-protocol-evaluation.md`. It exists so the vertical slice is exercisable
//! end to end.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use axum::extract::{ConnectInfo, DefaultBodyLimit, FromRef, Path, Query, State};
use axum::http::HeaderMap;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use cairn_crypto::TranscriptReport;
use cairn_proto::{Envelope, RoomId, RoomShape};

use crate::address::{AddressBucket, TrustedProxies};
use crate::state::{ServerError, SharedInstance};

/// What the handlers share. Most of them only want the instance, and get it via
/// [`FromRef`]; registration also needs to know which proxies to believe.
#[derive(Clone)]
struct AppState {
    instance: SharedInstance,
    proxies: Arc<TrustedProxies>,
    /// Set after the first misconfiguration warning, so a busy instance logs it once.
    warned_untrusted_forwarding: Arc<AtomicBool>,
}

impl FromRef<AppState> for SharedInstance {
    fn from_ref(state: &AppState) -> Self {
        Arc::clone(&state.instance)
    }
}

/// The instance's HTTP surface, trusting no proxy: the socket address is the client.
///
/// **Must be served with connect info** —
/// `axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>())` — or
/// registration fails with a 500. That failure is deliberate: a server that could not see
/// addresses would otherwise register without any limit at all.
pub fn router(instance: SharedInstance) -> Router {
    router_behind(instance, TrustedProxies::default())
}

/// As [`router`], believing `X-Forwarded-For` from the given reverse proxies only.
pub fn router_behind(instance: SharedInstance, proxies: TrustedProxies) -> Router {
    let state = AppState {
        instance,
        proxies: Arc::new(proxies),
        warned_untrusted_forwarding: Arc::new(AtomicBool::new(false)),
    };
    Router::new()
        .route("/health", get(health))
        .route("/v1/accounts", post(claim_account))
        .route("/v1/devices", post(link_device))
        .route("/v1/rooms", post(create_room))
        .route("/v1/rooms/{room}", get(describe_room))
        .route("/v1/rooms/{room}/messages", post(send_message).get(fetch_messages))
        .route("/v1/rooms/{room}/members", post(add_room_member).get(list_room_members))
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
        .route("/v1/rooms/{room}/ttl", post(set_room_ttl))
        .route("/v1/rooms/{room}/invites", post(create_room_invite))
        .route("/v1/invites/redeem", post(redeem_room_invite))
        .route("/v1/usernames", post(claim_username))
        .route("/v1/usernames/{name}", get(lookup_username))
        .route("/v1/reports", post(submit_report))
        .route("/v1/gifs", get(gif_capability))
        .route("/v1/gifs/tunnel/{target}", get(gif_tunnel))
        .with_state(state)
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
            ServerError::NoSuchBlob | ServerError::NoSuchUsername => StatusCode::NOT_FOUND,
            ServerError::UsernameTaken | ServerError::UsernameAlreadySet => StatusCode::CONFLICT,
            ServerError::BadUsername(_) | ServerError::InviteUsesTooHigh | ServerError::BadTtl => {
                StatusCode::BAD_REQUEST
            }
            // Deliberately the same 401 as any other bad credential, and deliberately not
            // 404: distinguishing "no such invite" from "spent" would tell someone probing
            // tokens when they had found a real one.
            ServerError::RoomInviteInvalid => StatusCode::UNAUTHORIZED,
            // 413 rather than 400: the request was well-formed, the instance just will not
            // hold something this big. An operator raising the ceiling changes the answer.
            ServerError::BlobTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            ServerError::BlobEmpty => StatusCode::BAD_REQUEST,
            // Only reachable from the operator's own startup path, never from a request,
            // but the mapping must be total.
            ServerError::InviteTooShort => StatusCode::BAD_REQUEST,
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
            // 403 rather than 400: the package parsed fine, the caller is simply not
            // entitled to publish one naming that account.
            ServerError::KeyPackageIdentityMismatch => StatusCode::FORBIDDEN,
            // 409, not 404. The account exists and may be addable later; a 404 would tell
            // the caller to stop trying, which is the wrong instruction.
            ServerError::NoKeyPackages | ServerError::TooManyKeyPackages => StatusCode::CONFLICT,
            // 404: there is no relay here to use. A client asks the capability endpoint
            // first and hides its picker, so this is only seen by one that did not.
            ServerError::GifsDisabled => StatusCode::NOT_FOUND,
            ServerError::GifTargetRefused => StatusCode::FORBIDDEN,
            ServerError::GifUpstreamUnreachable => StatusCode::BAD_GATEWAY,
            // Startup only, like `InviteTooShort`.
            ServerError::GifConfigInvalid(_) => StatusCode::BAD_REQUEST,
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
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<ClaimAccountRequest>,
) -> Result<StatusCode, ServerError> {
    let from = AddressBucket::of(client_address(&state, peer, &headers));
    let public_key = hex::decode(&req.public_key).map_err(|_| ServerError::BadSignature)?;
    state.instance.register(
        from,
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

/// The address a request is charged to, per the operator's trusted proxies.
fn client_address(state: &AppState, peer: SocketAddr, headers: &HeaderMap) -> std::net::IpAddr {
    let values = headers.get_all("x-forwarded-for");
    if !state.proxies.trusts(peer.ip())
        && values.iter().next().is_some()
        && !state.warned_untrusted_forwarding.swap(true, Ordering::Relaxed)
    {
        // The likeliest cause is a reverse proxy the operator has not named, which leaves
        // every client sharing the proxy's one registration budget. It could also be a
        // client setting the header itself, which is exactly why it is ignored either way.
        tracing::warn!(
            %peer,
            "ignoring X-Forwarded-For from an untrusted peer. If this is your reverse proxy, \
             add it to CAIRN_TRUSTED_PROXIES, or every client will share its rate limits"
        );
    }
    state.proxies.client_address(peer.ip(), values.iter().filter_map(|v| v.to_str().ok()))
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
/// than preventing it — a hostile member can still drain another member, slowly:
/// `MAX_CLAIMS_PER_TARGET` bounds the rate, not the total.
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
    let id = instance.store_blob(actor, room, body.to_vec(), now_ms())?;
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

#[derive(Deserialize)]
struct SetTtlRequest {
    /// Milliseconds, or `null` to turn disappearing messages off.
    #[serde(default)]
    ttl_ms: Option<i64>,
}

/// Set the room's disappearing-message timer. Any member may.
async fn set_room_ttl(
    State(instance): State<SharedInstance>,
    Path(room): Path<uuid::Uuid>,
    headers: HeaderMap,
    Json(request): Json<SetTtlRequest>,
) -> Result<StatusCode, ServerError> {
    let room = RoomId::from_uuid(room);
    let actor = signed_actor(&instance, &headers, "set_room_ttl", Some(room.into()))?;
    instance.set_room_ttl(room, actor, request.ttl_ms)?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize)]
struct RoomMemberEntry {
    user: String,
    role: String,
}

/// The room's server-side membership. Members only.
async fn list_room_members(
    State(instance): State<SharedInstance>,
    Path(room): Path<uuid::Uuid>,
    headers: HeaderMap,
) -> Result<Json<Vec<RoomMemberEntry>>, ServerError> {
    let room = RoomId::from_uuid(room);
    let actor = signed_actor(&instance, &headers, "list_room_members", Some(room.into()))?;
    Ok(Json(
        instance
            .room_members(room, actor)?
            .into_iter()
            .map(|m| RoomMemberEntry {
                user: m.user.to_string(),
                role: format!("{:?}", m.role).to_lowercase(),
            })
            .collect(),
    ))
}

#[derive(Deserialize)]
struct CreateRoomInviteRequest {
    /// How many people this link may admit. Capped server-side; there is no unlimited.
    uses: u32,
    /// Absolute expiry in ms since the epoch, or `null` for none.
    #[serde(default)]
    expires_at_ms: Option<i64>,
}

#[derive(Serialize)]
struct MintedInvite {
    /// Returned **once**. Only a hash is stored, so this cannot be recovered later.
    token: String,
}

#[derive(Deserialize)]
struct RedeemInviteRequest {
    token: String,
}

#[derive(Serialize)]
struct RedeemedInvite {
    room: String,
}

/// Mint an invite for a room. Moderator or owner, same as adding someone directly.
async fn create_room_invite(
    State(instance): State<SharedInstance>,
    Path(room): Path<uuid::Uuid>,
    headers: HeaderMap,
    Json(request): Json<CreateRoomInviteRequest>,
) -> Result<(StatusCode, Json<MintedInvite>), ServerError> {
    let room = cairn_proto::RoomId::from_uuid(room);
    let actor = signed_actor(&instance, &headers, "create_room_invite", Some(room.into()))?;
    let token = instance.create_room_invite(actor, room, request.uses, request.expires_at_ms)?;
    Ok((StatusCode::CREATED, Json(MintedInvite { token })))
}

/// Redeem an invite, joining the caller to its room.
///
/// The token is in the body rather than the path: a path lands in access logs and proxy
/// logs, and this one is a credential.
async fn redeem_room_invite(
    State(instance): State<SharedInstance>,
    headers: HeaderMap,
    Json(request): Json<RedeemInviteRequest>,
) -> Result<Json<RedeemedInvite>, ServerError> {
    let actor = signed_actor(&instance, &headers, "redeem_room_invite", None)?;
    let room = instance.redeem_room_invite(actor, &request.token, now_ms())?;
    Ok(Json(RedeemedInvite { room: room.to_string() }))
}

#[derive(Deserialize)]
struct ClaimUsernameRequest {
    username: String,
}

#[derive(Serialize)]
struct ResolvedUser {
    user: String,
}

/// Claim a handle for the acting account.
async fn claim_username(
    State(instance): State<SharedInstance>,
    headers: HeaderMap,
    Json(request): Json<ClaimUsernameRequest>,
) -> Result<StatusCode, ServerError> {
    let actor = signed_actor(&instance, &headers, "claim_username", None)?;
    let name = cairn_proto::Username::parse(&request.username)
        .map_err(|e| ServerError::BadUsername(e.to_string()))?;
    instance.claim_username(actor, name)?;
    Ok(StatusCode::CREATED)
}

/// Resolve a handle. Authenticated, so lookups can be attributed and bounded.
async fn lookup_username(
    State(instance): State<SharedInstance>,
    Path(name): Path<String>,
    headers: HeaderMap,
) -> Result<Json<ResolvedUser>, ServerError> {
    let actor = signed_actor(&instance, &headers, "lookup_username", None)?;
    let name =
        cairn_proto::Username::parse(&name).map_err(|e| ServerError::BadUsername(e.to_string()))?;
    let user = instance.lookup_username(actor, &name, now_ms())?;
    Ok(Json(ResolvedUser { user: user.to_string() }))
}

#[derive(Serialize)]
struct GifCapabilityResponse {
    /// False when the operator configured no provider. A client hides its picker.
    enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    provider: Option<&'static str>,
    /// An instance-scoped quota token, not a secret from members — see
    /// `Instance::gif_capability` for why it cannot be otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    api_key: Option<String>,
    /// The only hosts the relay will reach. Sent so a client refuses to *ask* for anything
    /// else, which turns a hostile provider response into an error rather than a probe.
    hosts: &'static [&'static str],
}

/// Whether GIF search is available here, and what a client needs to use it.
///
/// Authenticated: the key is not a secret from members, but it is from everyone else.
async fn gif_capability(
    State(instance): State<SharedInstance>,
    headers: HeaderMap,
) -> Result<Json<GifCapabilityResponse>, ServerError> {
    let actor = signed_actor(&instance, &headers, "gif_capability", None)?;
    Ok(Json(match instance.gif_capability(actor) {
        Some(c) => GifCapabilityResponse {
            enabled: true,
            provider: Some(c.provider.label()),
            api_key: Some(c.api_key),
            hosts: c.hosts,
        },
        None => GifCapabilityResponse { enabled: false, provider: None, api_key: None, hosts: &[] },
    }))
}

/// The protocol name a client asks to upgrade to.
pub const GIF_TUNNEL_PROTOCOL: &str = "cairn-gif-tunnel";

/// The action a tunnel request is signed for. The target is *inside* the signed action, so
/// a captured authorization cannot be replayed to open a tunnel to a different host —
/// `request_signing_bytes` length-prefixes the action, so no two targets collide.
pub fn gif_tunnel_action(target: &str) -> String {
    format!("gif_tunnel:{target}")
}

/// Open an opaque byte tunnel from the client to the GIF provider.
///
/// ## Why an upgrade rather than `CONNECT`
///
/// The Signal shape this copies is a `CONNECT` proxy, and the rules here are the same — an
/// authenticated tunnel to an allowlisted `host:443`, carrying TLS the instance cannot
/// read. But a `CONNECT` request targets an *authority*, not a path, and the deployment
/// this project documents puts Caddy in front of the instance: Caddy's reverse proxy
/// routes paths and does not forward a bare `CONNECT` to its upstream. An HTTP/1.1
/// `Upgrade` on an ordinary path travels through any reverse proxy that carries
/// WebSockets, and leaves exactly the same bytes on the wire afterwards. What the instance
/// can see is unchanged: the account, the provider host, the time, and the size of what
/// went each way — never the query, which is inside the client's TLS session.
///
/// The upstream is dialled *before* the 101 is sent, so a provider that cannot be reached
/// is an ordinary 502 rather than a tunnel that opens and immediately dies.
async fn gif_tunnel(
    State(instance): State<SharedInstance>,
    Path(target): Path<String>,
    mut request: axum::extract::Request,
) -> Result<Response, ServerError> {
    let actor = signed_actor(&instance, request.headers(), &gif_tunnel_action(&target), None)?;

    let wants_tunnel = request
        .headers()
        .get(axum::http::header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case(GIF_TUNNEL_PROTOCOL));
    if !wants_tunnel {
        return Ok((StatusCode::UPGRADE_REQUIRED, [(axum::http::header::UPGRADE, GIF_TUNNEL_PROTOCOL)])
            .into_response());
    }

    // `rsplit_once`, so an IPv6 literal's colons cannot be mistaken for the port separator
    // — not that one would pass the allowlist, which is the point of not parsing further.
    let (host, port) = target
        .rsplit_once(':')
        .and_then(|(h, p)| Some((h, p.parse::<u16>().ok()?)))
        .ok_or(ServerError::GifTargetRefused)?;
    let grant = instance.authorize_gif_tunnel(actor, host, port, now_ms())?;
    let upstream = dial_gif_upstream(&grant).await?;

    let on_upgrade = hyper::upgrade::on(&mut request);
    tokio::spawn(async move {
        let carried = match on_upgrade.await {
            Ok(upgraded) => {
                splice_gif_tunnel(hyper_util::rt::TokioIo::new(upgraded), upstream, &grant).await
            }
            Err(e) => {
                tracing::debug!(error = %e, "GIF tunnel upgrade did not complete");
                0
            }
        };
        instance.record_gif_relay_bytes(grant.actor, carried, now_ms());
    });

    Ok(Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header(axum::http::header::UPGRADE, GIF_TUNNEL_PROTOCOL)
        .header(axum::http::header::CONNECTION, "upgrade")
        .body(axum::body::Body::empty())
        .expect("a static response is well-formed"))
}

/// Connect to an approved provider host, refusing any address that points inward.
async fn dial_gif_upstream(
    grant: &crate::state::GifTunnelGrant,
) -> Result<tokio::net::TcpStream, ServerError> {
    const DIAL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

    let candidates: Vec<SocketAddr> = match grant.upstream_override {
        Some(addr) => vec![addr],
        None => {
            let resolved = tokio::time::timeout(
                DIAL_TIMEOUT,
                tokio::net::lookup_host((grant.host.as_str(), grant.port)),
            )
            .await
            .map_err(|_| ServerError::GifUpstreamUnreachable)?
            .map_err(|_| ServerError::GifUpstreamUnreachable)?;
            let all: Vec<SocketAddr> = resolved.collect();
            let public: Vec<SocketAddr> = all
                .iter()
                .copied()
                .filter(|a| crate::state::gif_upstream_permitted(a.ip()))
                .collect();
            if public.is_empty() && !all.is_empty() {
                tracing::warn!(
                    host = %grant.host,
                    ?all,
                    "a GIF provider host resolved only to non-public addresses; refusing. \
                     Check this instance's DNS"
                );
                return Err(ServerError::GifTargetRefused);
            }
            public
        }
    };
    for addr in candidates {
        if let Ok(Ok(stream)) =
            tokio::time::timeout(DIAL_TIMEOUT, tokio::net::TcpStream::connect(addr)).await
        {
            return Ok(stream);
        }
    }
    Err(ServerError::GifUpstreamUnreachable)
}

/// Copy bytes both ways until either side closes or a limit from the grant is reached.
/// Returns how many bytes crossed, both directions together, for the account's budget.
///
/// Hand-rolled rather than `tokio::io::copy_bidirectional`, which has no byte ceiling, no
/// idle timeout and no lifetime — the three things that stop a member parking a pipe to
/// the provider on the operator's connection.
async fn splice_gif_tunnel<C>(
    client: C,
    upstream: tokio::net::TcpStream,
    grant: &crate::state::GifTunnelGrant,
) -> u64
where
    C: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (mut client_read, mut client_write) = tokio::io::split(client);
    let (mut upstream_read, mut upstream_write) = upstream.into_split();
    let idle = std::time::Duration::from_millis(grant.idle_timeout_ms);
    let deadline =
        tokio::time::Instant::now() + std::time::Duration::from_millis(grant.max_lifetime_ms);
    let mut from_client = vec![0u8; 16 * 1024];
    let mut from_upstream = vec![0u8; 16 * 1024];
    let mut carried: u64 = 0;

    loop {
        let remaining = grant.max_bytes.saturating_sub(carried);
        if remaining == 0 {
            break;
        }
        // Never read more than the grant has left, so the ceiling is exact rather than
        // overshot by up to a buffer.
        let cap = usize::try_from(remaining).unwrap_or(usize::MAX).min(from_client.len());
        tokio::select! {
            read = client_read.read(&mut from_client[..cap]) => match read {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    carried += n as u64;
                    if upstream_write.write_all(&from_client[..n]).await.is_err() {
                        break;
                    }
                }
            },
            read = upstream_read.read(&mut from_upstream[..cap]) => match read {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    carried += n as u64;
                    if client_write.write_all(&from_upstream[..n]).await.is_err() {
                        break;
                    }
                }
            },
            () = tokio::time::sleep(idle) => break,
            () = tokio::time::sleep_until(deadline) => break,
        }
    }
    let _ = client_write.shutdown().await;
    let _ = upstream_write.shutdown().await;
    carried
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
    /// The room's disappearing-message timer, so a client can apply the same rule to its
    /// own stored copy rather than keeping messages the server has already dropped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ttl_ms: Option<i64>,
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
    Ok(Json(CreateRoomResponse {
        room,
        tier: seal.tier().label(),
        e2ee: seal.tier().is_e2ee(),
        ttl_ms: instance.room_ttl(room),
    }))
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
    Ok(Json(CreateRoomResponse {
        room,
        tier: seal.tier().label(),
        e2ee: seal.tier().is_e2ee(),
        ttl_ms: instance.room_ttl(room),
    }))
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
    let stored = instance.accept(envelope, now_ms())?;
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
    let messages = instance.messages_since(room, actor, since.after, now_ms())?;
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
