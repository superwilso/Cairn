//! Cairn desktop — the Tauri shell.
//!
//! **This file is deliberately boring, and that is the design.** Every command below is a
//! one-line delegation to `cairn_client_core::session::Session`. Nothing here constructs an
//! envelope, decides a tier, or touches a key, and neither does the JavaScript it serves.
//!
//! [ADR-006](../../../../docs/adr/006-platform-architecture.md) drew that line to stop five
//! native clients becoming five sets of security bugs; [ADR-008](../../../../docs/adr/008-client-architecture.md)
//! replaced those five with one web client and kept the line exactly where it was. In a
//! Tauri app the line falls between Rust and JavaScript: this crate is *below* it, the UI in
//! `../ui` is above it, and the UI only ever receives plain data.
//!
//! If a command here starts doing more than forwarding a call, that is the signal that
//! logic is leaking upward and belongs in `client-core` instead.

#![forbid(unsafe_code)]
// Stops a console window appearing behind the app on Windows.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::sync::Mutex;

use cairn_client_core::call::{CallConfig, CallSignal};
use cairn_client_core::custom::Kind as CustomKind;
use cairn_client_core::gifs::{GifProviderView, GifView};
use cairn_client_core::session::{
    CustomLimits, CustomSetView, Event, ImageSlot, LinkPreviewSettings, MemberView, MessageView,
    ProfileEdit, ProfileLimits, ProfileView, ReactionView, RoomSummary, Session, SpaceDisplay,
    SpaceListing,
};
use cairn_client_core::verify::SafetyView;
use tauri::State;

/// The one session this window is signed in as.
///
/// A `Mutex` rather than anything cleverer: every operation here touches the MLS group state,
/// which must not be mutated from two places at once. Serialising them is correctness, not
/// laziness — two concurrent commits to one group is exactly how a client corrupts its own
/// epoch.
#[derive(Default)]
struct AppState(Mutex<Option<Session>>);

/// Errors cross to JavaScript as strings.
///
/// The UI must never branch on an error *type* to decide something protocol-shaped; if it
/// ever needs to, that decision belongs below this line.
type CmdResult<T> = Result<T, String>;

fn with<T>(
    state: &State<'_, AppState>,
    f: impl FnOnce(&mut Session) -> Result<T, cairn_client_core::session::SessionError>,
) -> CmdResult<T> {
    let mut guard = state.0.lock().map_err(|_| "session lock poisoned".to_string())?;
    let session = guard.as_mut().ok_or("not signed in yet")?;
    f(session).map_err(|e| e.to_string())
}

#[tauri::command]
fn sign_in(
    state: State<'_, AppState>,
    profile: String,
    server: String,
    invite: Option<String>,
) -> CmdResult<SignedIn> {
    // The **registration** invite, not a room one. Most instances should require it — it is
    // the server's default and what the self-hosting guide recommends — so without it this
    // client could only sign in to an instance that had opened registration to everyone.
    let invite = invite.map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    let session = Session::open_with_invite(&profile, &server, None, invite.as_deref())
        .map_err(|e| e.to_string())?;
    let signed = SignedIn { user: session.user_id(), tls: session.is_tls() };
    *state.0.lock().map_err(|_| "session lock poisoned".to_string())? = Some(session);
    Ok(signed)
}

#[derive(serde::Serialize)]
struct SignedIn {
    user: String,
    /// False over `http://`. The UI must say so rather than showing a clean badge — a lock
    /// over a plaintext transport is the false assurance the threat model forbids.
    tls: bool,
}

#[tauri::command]
fn publish_key_packages(state: State<'_, AppState>, count: usize) -> CmdResult<usize> {
    with(&state, |s| s.publish_key_packages(count))
}

#[tauri::command]
fn create_group(state: State<'_, AppState>, ceiling: u32) -> CmdResult<String> {
    with(&state, |s| s.create_group(ceiling))
}

#[tauri::command]
fn create_direct(state: State<'_, AppState>) -> CmdResult<String> {
    with(&state, |s| s.create_direct())
}

#[tauri::command]
fn rooms(state: State<'_, AppState>) -> CmdResult<Vec<RoomSummary>> {
    let mut guard = state.0.lock().map_err(|_| "session lock poisoned".to_string())?;
    let session = guard.as_mut().ok_or("not signed in yet")?;
    Ok(session.rooms())
}

#[tauri::command]
fn open_room(state: State<'_, AppState>, room: String) -> CmdResult<Vec<MessageView>> {
    with(&state, |s| s.open_room(&room))
}

/// The open room's tier, derived locally from its sealed shape.
///
/// Never the instance's word for it: a badge taken from the server is a badge the server can
/// lie about, and users calibrate what they say to what the badge claims.
#[tauri::command]
fn open_room_tier(state: State<'_, AppState>) -> CmdResult<Option<String>> {
    let guard = state.0.lock().map_err(|_| "session lock poisoned".to_string())?;
    let session = guard.as_ref().ok_or("not signed in yet")?;
    Ok(session.open_room_tier())
}

/// Send a message, with a link card if it has a link and previews are on.
///
/// **Async, and the fetch runs with the session unlocked.** A synchronous command runs on
/// the main thread, so a slow site would freeze the window for as long as it took; and
/// holding the session lock across the fetch would stall polling the same way. So: decide
/// under the lock, fetch with it released, and send under the lock again — `finish_send`
/// refuses if the user switched rooms in between.
///
/// Returns the message as the timeline should show it, card included, because MLS never
/// decrypts a device's own message back to it.
#[tauri::command]
async fn send(app: tauri::AppHandle, text: String) -> CmdResult<MessageView> {
    off_main(move || send_with_preview(&app, &text, None)).await
}

/// Reply to a message on screen. The quote recipients see is resolved from their own
/// transcripts; this sends only which message it answers. A reply can carry a link card
/// like any other message.
#[tauri::command]
async fn reply(
    app: tauri::AppHandle,
    text: String,
    sender: String,
    id: String,
) -> CmdResult<MessageView> {
    off_main(move || send_with_preview(&app, &text, Some((&sender, &id)))).await
}

fn send_with_preview(
    app: &tauri::AppHandle,
    text: &str,
    reply: Option<(&str, &str)>,
) -> CmdResult<MessageView> {
    let mut pending = with_app(app, |s| s.begin_send(text, reply))?;
    // The only network fetch a link card ever causes, and it is the sender's: the session
    // lock is not held here.
    pending.unfurl();
    with_app(app, |s| s.finish_send(pending))
}

#[tauri::command]
fn link_previews(state: State<'_, AppState>) -> CmdResult<LinkPreviewSettings> {
    with(&state, |s| Ok(s.link_previews()))
}

#[tauri::command]
fn set_link_previews(state: State<'_, AppState>, settings: LinkPreviewSettings) -> CmdResult<()> {
    with(&state, |s| s.set_link_previews(settings))
}

/// The text the Instagram proxy setting must show before it can be switched on.
#[tauri::command]
fn instagram_proxy_disclosure() -> String {
    format!(
        "{} The proxy used is {}.",
        cairn_client_core::embed::instagram::disclosure(),
        cairn_client_core::embed::instagram::SUGGESTED_PROXY
    )
}

/// Open a card's link in the system browser. The check is `embed::openable`'s, not this
/// shell's: only a plain http(s) URL ever reaches the platform opener.
#[tauri::command]
fn open_link(url: String) -> CmdResult<()> {
    let url = cairn_client_core::embed::openable(&url).ok_or("not a link that can be opened")?;
    open::that_detached(url).map_err(|e| e.to_string())
}

/// React to a message, or withdraw this user's reaction with `emoji: null`. Returns every
/// reaction now under it.
#[tauri::command]
fn react(
    state: State<'_, AppState>,
    sender: String,
    id: String,
    emoji: Option<String>,
) -> CmdResult<Vec<ReactionView>> {
    with(&state, |s| s.react(&sender, &id, emoji.as_deref()))
}

#[tauri::command]
fn poll(state: State<'_, AppState>) -> CmdResult<Vec<Event>> {
    with(&state, |s| s.poll())
}

#[tauri::command]
fn members(state: State<'_, AppState>) -> CmdResult<Vec<MemberView>> {
    with(&state, |s| s.members())
}

/// One account's safety numbers in the open room, one per device.
///
/// Computed in `client-core` from the group's own roster. The UI displays the string it is
/// given and hands it back unchanged to `mark_verified`; it never derives one itself.
#[tauri::command]
fn safety_numbers(state: State<'_, AppState>, user: String) -> CmdResult<Vec<SafetyView>> {
    with(&state, |s| s.safety_numbers(&user))
}

/// Record a comparison. `number` is the one the user was shown: `Session::verify` refuses if
/// it is no longer the device's number, so a key that changed while the panel was open is
/// never the one certified.
#[tauri::command]
fn mark_verified(
    state: State<'_, AppState>,
    user: String,
    device: String,
    number: String,
) -> CmdResult<Vec<SafetyView>> {
    with(&state, |s| s.verify(&user, &device, &number))
}

#[tauri::command]
fn admit_waiting(state: State<'_, AppState>) -> CmdResult<Vec<String>> {
    with(&state, |s| s.admit_waiting())
}

#[tauri::command]
fn create_invite(state: State<'_, AppState>, uses: u32, hours: i64) -> CmdResult<String> {
    with(&state, |s| s.create_invite(uses, hours))
}

#[tauri::command]
fn redeem_invite(state: State<'_, AppState>, token: String) -> CmdResult<String> {
    with(&state, |s| s.redeem_invite(&token))
}

// ---- spaces ----------------------------------------------------------------------------
//
// One-line delegations, like everything else here. Every permission the UI shows arrives in
// `space`'s answer, decided by the instance; nothing below or above this line computes one.

#[tauri::command]
fn spaces(state: State<'_, AppState>) -> CmdResult<Vec<SpaceListing>> {
    with(&state, |s| s.spaces())
}

#[tauri::command]
fn space(state: State<'_, AppState>, space: String) -> CmdResult<SpaceDisplay> {
    with(&state, |s| s.space(&space))
}

#[tauri::command]
fn create_space(state: State<'_, AppState>, name: String) -> CmdResult<String> {
    with(&state, |s| s.create_space(&name, None))
}

#[tauri::command]
fn create_channel(state: State<'_, AppState>, space: String, name: String) -> CmdResult<String> {
    with(&state, |s| s.create_channel(&space, &name))
}

#[tauri::command]
fn rename_channel(
    state: State<'_, AppState>,
    space: String,
    channel: String,
    name: String,
) -> CmdResult<()> {
    with(&state, |s| s.rename_channel(&space, &channel, &name))
}

#[tauri::command]
fn delete_channel(state: State<'_, AppState>, space: String, channel: String) -> CmdResult<()> {
    with(&state, |s| s.delete_channel(&space, &channel))
}

#[tauri::command]
fn set_channel_override(
    state: State<'_, AppState>,
    space: String,
    channel: String,
    role: Option<String>,
    allow: Vec<String>,
    deny: Vec<String>,
) -> CmdResult<()> {
    with(&state, |s| s.set_channel_override(&space, &channel, role.as_deref(), &allow, &deny))
}

#[tauri::command]
fn create_role(
    state: State<'_, AppState>,
    space: String,
    name: String,
    grants: Vec<String>,
    position: u32,
) -> CmdResult<String> {
    with(&state, |s| s.create_role(&space, &name, &grants, position))
}

#[tauri::command]
fn assign_role(
    state: State<'_, AppState>,
    space: String,
    user: String,
    role: String,
) -> CmdResult<()> {
    with(&state, |s| s.assign_role(&space, &user, &role))
}

#[tauri::command]
fn unassign_role(
    state: State<'_, AppState>,
    space: String,
    user: String,
    role: String,
) -> CmdResult<()> {
    with(&state, |s| s.unassign_role(&space, &user, &role))
}

#[tauri::command]
fn kick(state: State<'_, AppState>, space: String, user: String) -> CmdResult<()> {
    with(&state, |s| s.kick(&space, &user))
}

#[tauri::command]
fn leave_space(state: State<'_, AppState>, space: String) -> CmdResult<()> {
    with(&state, |s| s.leave_space(&space))
}

#[tauri::command]
fn create_space_invite(
    state: State<'_, AppState>,
    space: String,
    uses: u32,
    hours: i64,
) -> CmdResult<String> {
    with(&state, |s| s.create_space_invite(&space, uses, hours))
}

#[tauri::command]
fn redeem_space_invite(state: State<'_, AppState>, token: String) -> CmdResult<String> {
    with(&state, |s| s.redeem_space_invite(&token))
}

#[tauri::command]
fn remove_departed(state: State<'_, AppState>) -> CmdResult<Vec<String>> {
    with(&state, |s| s.remove_departed())
}

#[tauri::command]
fn call_join(state: State<'_, AppState>) -> CmdResult<String> {
    with(&state, |s| s.call_join())
}

#[tauri::command]
fn call_leave(state: State<'_, AppState>) -> CmdResult<()> {
    with(&state, |s| s.call_leave())
}

#[tauri::command]
fn signal(state: State<'_, AppState>, signal: CallSignal) -> CmdResult<()> {
    with(&state, |s| s.signal(signal))
}

#[tauri::command]
fn call_id(state: State<'_, AppState>) -> CmdResult<Option<String>> {
    let mut guard = state.0.lock().map_err(|_| "session lock poisoned".to_string())?;
    let session = guard.as_mut().ok_or("not signed in yet")?;
    Ok(session.call_id())
}

/// Decline the call this device is being rung for. The caller sees "declined".
#[tauri::command]
fn call_decline(state: State<'_, AppState>) -> CmdResult<()> {
    with(&state, |s| s.call_decline())
}

/// What the WebRTC layer needs before it can build a peer connection, for the open room.
///
/// Sent as data rather than baked into the JavaScript so a self-hosted instance points
/// calls at its own STUN/TURN without a frontend change — and so the honest caveat travels
/// with the config instead of living in a comment nobody reads. Relay credentials in it are
/// fresh each time and expire; see `Session::call_config`.
#[tauri::command]
fn call_config(state: State<'_, AppState>) -> CmdResult<CallConfig> {
    with(&state, |s| s.call_config())
}

// ---- voice channels --------------------------------------------------------
//
// The room-attached call through the instance's SFU (docs/adr/012-sfu-voice-channels.md).
// Whether it is end to end, and with which keys, is decided in `Session` — these only carry
// the answers across.

/// Join the open room's voice channel with this webview's SDP offer. `e2ee` is whether the
/// webview can transform frames; `false` makes the call transport-only for everyone, and
/// everyone is told.
#[tauri::command]
fn voice_join(
    state: State<'_, AppState>,
    offer: String,
    e2ee: bool,
) -> CmdResult<cairn_client_core::session::VoiceJoined> {
    with(&state, |s| s.voice_join(&offer, e2ee))
}

#[tauri::command]
fn voice_leave(state: State<'_, AppState>) -> CmdResult<()> {
    with(&state, |s| s.voice_leave())
}

#[tauri::command]
fn voice_state(
    state: State<'_, AppState>,
) -> CmdResult<cairn_client_core::session::VoiceStateView> {
    with(&state, |s| s.voice_state())
}

/// The current epoch's media keys. The one place raw keys cross this line; the webview
/// imports them as non-extractable and keeps no other copy.
#[tauri::command]
fn voice_keys(state: State<'_, AppState>) -> CmdResult<cairn_client_core::session::VoiceKeysView> {
    with(&state, |s| s.voice_keys())
}

// ---- attachments -----------------------------------------------------------
//
// Async, and off the main thread: a 25 MiB upload over a home connection would otherwise
// freeze the window for as long as it took. Each one takes the session lock only for the
// short steps that touch MLS state — sealing, and sending the message that carries the key —
// and runs the transfer itself on a clone of the network client with the lock released, so
// polling (and with it, an ongoing call) carries on while a file goes up. The sequencing is
// `Session`'s; see `cairn_client_core::session::attachments`.

/// Run blocking work on Tauri's blocking pool rather than the main thread.
async fn off_main<T: Send + 'static>(
    work: impl FnOnce() -> CmdResult<T> + Send + 'static,
) -> CmdResult<T> {
    tauri::async_runtime::spawn_blocking(work).await.map_err(|e| e.to_string())?
}

fn with_app<T>(
    app: &tauri::AppHandle,
    f: impl FnOnce(&mut Session) -> Result<T, cairn_client_core::session::SessionError>,
) -> CmdResult<T> {
    use tauri::Manager as _;
    with(&app.state::<AppState>(), f)
}

/// The file's claimed name and type, sent in a header beside the raw bytes.
#[derive(serde::Deserialize)]
struct FileMeta {
    name: String,
    mime: String,
}

/// Send a file to the open room.
///
/// The bytes arrive as the raw IPC body rather than a JSON array of numbers, which would
/// make a 25 MiB photo roughly 100 MB of JSON. The UI never sees the key this creates.
#[tauri::command]
async fn send_file(
    app: tauri::AppHandle,
    request: tauri::ipc::Request<'_>,
) -> CmdResult<MessageView> {
    let meta: FileMeta = request
        .headers()
        .get("x-cairn-file")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| serde_json::from_str(v).ok())
        .ok_or("the file's name and type are missing")?;
    let bytes = match request.body() {
        tauri::ipc::InvokeBody::Raw(bytes) => bytes.clone(),
        // Found by running the real shell: when the webview cannot reach the `ipc:`
        // protocol (a CSP without it in `connect-src` is enough) Tauri falls back to
        // `postMessage` and re-encodes the bytes as a JSON array of numbers. Slow for a big
        // file, but a file that sends slowly beats one that cannot be sent.
        tauri::ipc::InvokeBody::Json(value) => <Vec<u8> as serde::Deserialize>::deserialize(value)
            .map_err(|_| "expected the file's bytes")?,
    };
    off_main(move || {
        let pending = with_app(&app, |s| s.prepare_upload(&meta.name, &meta.mime, &bytes))?;
        drop(bytes);
        let uploaded = pending.upload().map_err(|e| e.to_string())?;
        with_app(&app, |s| s.send_uploaded(uploaded))
    })
    .await
}

/// The plaintext of an attachment in the open room, as raw bytes for the UI to show.
#[tauri::command]
async fn fetch_attachment(app: tauri::AppHandle, id: String) -> CmdResult<tauri::ipc::Response> {
    off_main(move || {
        let pending = with_app(&app, |s| s.prepare_download(&id))?;
        let bytes = pending.fetch().map_err(|e| e.to_string())?;
        Ok(tauri::ipc::Response::new(bytes))
    })
    .await
}

/// Save an attachment into the user's Downloads folder, returning where it landed.
///
/// Written by Rust rather than by a webview download, because the name is the sender's and
/// turning it into a path safely is exactly the kind of decision that belongs below this line.
#[tauri::command]
async fn save_attachment(app: tauri::AppHandle, id: String) -> CmdResult<String> {
    use tauri::Manager as _;
    // Found by running the real shell: a Linux session without xdg-user-dirs configured
    // has no Downloads directory to report, and every save failed with "unknown path".
    // `~/Downloads` is what that directory would have been called; `save_into` creates it.
    let dir = app
        .path()
        .download_dir()
        .or_else(|_| app.path().home_dir().map(|home| home.join("Downloads")))
        .map_err(|e| e.to_string())?;
    off_main(move || {
        let pending = with_app(&app, |s| s.prepare_download(&id))?;
        let path = pending.save_into(&dir).map_err(|e| e.to_string())?;
        Ok(path.display().to_string())
    })
    .await
}

/// The ceiling, so the UI can refuse an oversized file before reading it — and say the
/// number, which lives in Rust rather than being copied into JavaScript.
#[derive(serde::Serialize)]
struct AttachmentLimits {
    max_bytes: usize,
}

#[tauri::command]
fn attachment_limits() -> AttachmentLimits {
    AttachmentLimits { max_bytes: cairn_client_core::session::MAX_ATTACHMENT_BYTES }
}

/// The open room's disappearing-message timer, in milliseconds; `None` is off.
#[tauri::command]
fn room_timer(state: State<'_, AppState>) -> CmdResult<Option<i64>> {
    with(&state, |s| s.room_timer())
}

/// Set it. Returns what the instance holds afterwards, which is what the UI shows.
#[tauri::command]
fn set_room_timer(state: State<'_, AppState>, ttl_ms: Option<i64>) -> CmdResult<Option<i64>> {
    with(&state, |s| s.set_room_timer(ttl_ms))
}

// ---- GIFs ------------------------------------------------------------------
//
// Search, previews and the fetch for sending all run through the instance's relay, off the
// main thread and without the session lock — `Gifs` is shared out of the session for that.
// The UI only ever holds opaque result ids; see `cairn_client_core::gifs`.

fn gifs_of(app: &tauri::AppHandle) -> CmdResult<std::sync::Arc<cairn_client_core::gifs::Gifs>> {
    with_app(app, |s| s.gifs())
}

/// The providers this instance relays, with each one's required placeholder and
/// attribution. Empty when the operator configured none.
#[tauri::command]
async fn gif_providers(app: tauri::AppHandle) -> CmdResult<Vec<GifProviderView>> {
    off_main(move || gifs_of(&app)?.providers().map_err(|e| e.to_string())).await
}

/// Search one provider, or list what is trending when `query` is blank.
#[tauri::command]
async fn gif_search(
    app: tauri::AppHandle,
    provider: String,
    query: String,
) -> CmdResult<Vec<GifView>> {
    off_main(move || gifs_of(&app)?.search(&provider, &query).map_err(|e| e.to_string())).await
}

/// A result's preview, as raw bytes, by the id a search returned.
#[tauri::command]
async fn gif_preview(app: tauri::AppHandle, id: String) -> CmdResult<tauri::ipc::Response> {
    off_main(move || {
        let media = gifs_of(&app)?.preview(&id).map_err(|e| e.to_string())?;
        Ok(tauri::ipc::Response::new(media.bytes))
    })
    .await
}

/// Send a result to the open room as an encrypted attachment. The same three steps as
/// `send_file`, with the fetch through the relay in front.
#[tauri::command]
async fn send_gif(app: tauri::AppHandle, id: String) -> CmdResult<MessageView> {
    off_main(move || {
        let file = gifs_of(&app)?.fetch_for_sending(&id).map_err(|e| e.to_string())?;
        let pending = with_app(&app, |s| s.prepare_upload(&file.name, file.mime, &file.bytes))?;
        drop(file);
        let uploaded = pending.upload().map_err(|e| e.to_string())?;
        with_app(&app, |s| s.send_uploaded(uploaded))
    })
    .await
}

// ---- profiles --------------------------------------------------------------
//
// The record, its rules, which room hears what and when, and every label the UI draws are
// `cairn_client_core::session::profiles`. The UI sends edits and bytes, and gets views.

#[tauri::command]
fn my_profile(state: State<'_, AppState>) -> CmdResult<ProfileView> {
    with(&state, |s| Ok(s.my_profile()))
}

#[tauri::command]
fn profiles(state: State<'_, AppState>) -> CmdResult<Vec<ProfileView>> {
    with(&state, |s| s.profiles())
}

#[tauri::command]
fn set_profile(state: State<'_, AppState>, edit: ProfileEdit) -> CmdResult<ProfileView> {
    with(&state, |s| s.set_profile(edit))
}

#[tauri::command]
fn set_nickname(state: State<'_, AppState>, nickname: Option<String>) -> CmdResult<ProfileView> {
    with(&state, |s| s.set_nickname(nickname.as_deref()))
}

#[tauri::command]
fn profile_limits() -> ProfileLimits {
    cairn_client_core::session::profile_limits()
}

#[derive(serde::Deserialize)]
struct ImageMeta {
    slot: ImageSlot,
    mime: String,
}

/// Set an avatar or banner. Raw bytes as the IPC body, the slot and type in a header — the
/// same shape as `send_file`, for the same reason.
#[tauri::command]
async fn set_profile_image(
    app: tauri::AppHandle,
    request: tauri::ipc::Request<'_>,
) -> CmdResult<ProfileView> {
    let meta: ImageMeta = request
        .headers()
        .get("x-cairn-image")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| serde_json::from_str(v).ok())
        .ok_or("the image's slot and type are missing")?;
    let bytes = match request.body() {
        tauri::ipc::InvokeBody::Raw(bytes) => bytes.clone(),
        tauri::ipc::InvokeBody::Json(value) => <Vec<u8> as serde::Deserialize>::deserialize(value)
            .map_err(|_| "expected the image's bytes")?,
    };
    off_main(move || with_app(&app, |s| s.set_profile_image(meta.slot, Some((&bytes, &meta.mime)))))
        .await
}

#[tauri::command]
fn clear_profile_image(state: State<'_, AppState>, slot: ImageSlot) -> CmdResult<ProfileView> {
    with(&state, |s| s.set_profile_image(slot, None))
}

/// One member's avatar or banner in the open room, decrypted, as raw bytes.
#[tauri::command]
async fn fetch_profile_image(
    app: tauri::AppHandle,
    user: String,
    slot: ImageSlot,
) -> CmdResult<tauri::ipc::Response> {
    off_main(move || {
        let pending = with_app(&app, |s| s.prepare_profile_image(&user, slot))?;
        let bytes = pending.fetch().map_err(|e| e.to_string())?;
        Ok(tauri::ipc::Response::new(bytes))
    })
    .await
}

// ---- custom emoji, stickers, soundboard -------------------------------------
//
// The set, who may change it, and every fetch are `cairn_client_core::session::custom`. The
// UI gets a view with ids and asks for bytes by id; `custom_asset` reads this device's cache
// and never the network, which is the property the whole design exists for.

#[tauri::command]
fn custom_set(state: State<'_, AppState>) -> CmdResult<CustomSetView> {
    with(&state, |s| s.custom_set())
}

#[tauri::command]
fn custom_limits() -> CustomLimits {
    cairn_client_core::session::custom_limits()
}

/// Download every asset of the open room's set this device lacks — all of them, at once,
/// off the main thread and with the session unlocked. Returns how many were cached.
#[tauri::command]
async fn custom_sync(app: tauri::AppHandle) -> CmdResult<usize> {
    off_main(move || {
        let sync = with_app(&app, |s| s.prepare_custom_sync())?;
        Ok(sync.run())
    })
    .await
}

/// One item's bytes, from the local cache only.
#[tauri::command]
fn custom_asset(state: State<'_, AppState>, id: String) -> CmdResult<tauri::ipc::Response> {
    with(&state, |s| s.custom_asset(&id)).map(tauri::ipc::Response::new)
}

#[derive(serde::Deserialize)]
struct CustomMeta {
    kind: CustomKind,
    name: String,
}

/// Add an emoji, sticker or sound. Raw bytes as the IPC body, kind and name in a header —
/// the shape of `send_file`. The type is sniffed from the bytes in Rust, not taken from here.
#[tauri::command]
async fn custom_add(
    app: tauri::AppHandle,
    request: tauri::ipc::Request<'_>,
) -> CmdResult<CustomSetView> {
    let meta: CustomMeta = request
        .headers()
        .get("x-cairn-custom")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| serde_json::from_str(v).ok())
        .ok_or("the item's kind and name are missing")?;
    let bytes = match request.body() {
        tauri::ipc::InvokeBody::Raw(bytes) => bytes.clone(),
        tauri::ipc::InvokeBody::Json(value) => <Vec<u8> as serde::Deserialize>::deserialize(value)
            .map_err(|_| "expected the file's bytes")?,
    };
    off_main(move || {
        let pending = with_app(&app, |s| s.prepare_custom_upload(meta.kind, &meta.name, &bytes))?;
        drop(bytes);
        let uploaded = pending.upload().map_err(|e| e.to_string())?;
        with_app(&app, |s| s.commit_custom(uploaded))
    })
    .await
}

#[tauri::command]
fn custom_remove(
    state: State<'_, AppState>,
    kind: CustomKind,
    name: String,
) -> CmdResult<CustomSetView> {
    with(&state, |s| s.remove_custom(kind, &name))
}

#[tauri::command]
fn send_sticker(state: State<'_, AppState>, name: String) -> CmdResult<MessageView> {
    with(&state, |s| s.send_sticker(&name))
}

/// WebKitGTK's default answer to `getUserMedia` is **deny**: its `permission-request` signal
/// goes unanswered unless the app connects to it, and wry only handles the clipboard. So on
/// Linux calls could not start at all. This grants microphone, camera and device-list
/// requests — nothing else — and only while the webview shows the app's own bundled UI, so a
/// page that somehow navigated elsewhere gets WebKitGTK's default instead. Windows needs
/// none of this: WebView2 raises its own prompt.
///
/// Unlike WebView2 there is no system prompt here: the app's UI asks only when the user
/// starts or joins a call, and that click is the consent.
#[cfg(target_os = "linux")]
fn grant_media_requests(app: &tauri::App) {
    use tauri::Manager;
    use webkit2gtk::glib::ObjectExt;
    use webkit2gtk::{
        DeviceInfoPermissionRequest, PermissionRequestExt, UserMediaPermissionRequest, WebViewExt,
    };
    for window in app.webview_windows().values() {
        let _ = window.with_webview(|webview| {
            webview.inner().connect_permission_request(|view, request| {
                let ours = view.uri().is_some_and(|uri| {
                    uri.starts_with("tauri://localhost")
                        || uri.starts_with("http://tauri.localhost")
                });
                let media = request.is::<UserMediaPermissionRequest>()
                    || request.is::<DeviceInfoPermissionRequest>();
                if ours && media {
                    request.allow();
                    true
                } else {
                    false
                }
            });
        });
    }
}

fn main() {
    tauri::Builder::default()
        .manage(AppState::default())
        .setup(|_app| {
            #[cfg(target_os = "linux")]
            grant_media_requests(_app);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            sign_in,
            publish_key_packages,
            create_group,
            create_direct,
            rooms,
            open_room,
            open_room_tier,
            send,
            poll,
            members,
            safety_numbers,
            mark_verified,
            admit_waiting,
            create_invite,
            redeem_invite,
            call_join,
            call_leave,
            signal,
            call_id,
            call_config,
            voice_join,
            voice_leave,
            voice_state,
            voice_keys,
            call_decline,
            send_file,
            fetch_attachment,
            save_attachment,
            attachment_limits,
            room_timer,
            set_room_timer,
            reply,
            react,
            gif_providers,
            gif_search,
            gif_preview,
            send_gif,
            my_profile,
            profiles,
            set_profile,
            set_nickname,
            profile_limits,
            set_profile_image,
            clear_profile_image,
            fetch_profile_image,
            link_previews,
            set_link_previews,
            instagram_proxy_disclosure,
            open_link,
            custom_set,
            custom_limits,
            custom_sync,
            custom_asset,
            custom_add,
            custom_remove,
            send_sticker,
            spaces,
            space,
            create_space,
            create_channel,
            rename_channel,
            delete_channel,
            set_channel_override,
            create_role,
            assign_role,
            unassign_role,
            kick,
            leave_space,
            create_space_invite,
            redeem_space_invite,
            remove_departed,
        ])
        .run(tauri::generate_context!())
        .expect("failed to start the Cairn desktop client");
}
