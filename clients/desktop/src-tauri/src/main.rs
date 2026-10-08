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

use cairn_client_core::call::{self, CallSignal, IceServer};
use cairn_client_core::session::{
    Event, MemberView, MessageView, ReactionView, RoomSummary, Session,
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

/// Returns the message as sent, so the sender sees it at once — polling never delivers a
/// device's own messages back to it.
#[tauri::command]
fn send(state: State<'_, AppState>, text: String) -> CmdResult<MessageView> {
    with(&state, |s| s.send(&text))
}

/// Reply to a message on screen. The quote recipients see is resolved from their own
/// transcripts; this sends only which message it answers.
#[tauri::command]
fn reply(
    state: State<'_, AppState>,
    text: String,
    sender: String,
    id: String,
) -> CmdResult<MessageView> {
    with(&state, |s| s.reply(&text, &sender, &id))
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

/// What the WebRTC layer needs before it can build a peer connection.
///
/// Sent as data rather than baked into the JavaScript so a self-hosted instance can point
/// calls at its own STUN/TURN later without a frontend change — and so the honest caveat
/// travels with the config instead of living in a comment nobody reads.
#[derive(serde::Serialize)]
struct CallConfig {
    ice_servers: Vec<IceServer>,
    /// False on STUN alone. The UI says so: without a relay a minority of users behind
    /// symmetric NATs will find calls simply do not connect, and "it is your network" is
    /// not something a client should leave them to work out themselves.
    has_relay: bool,
    max_participants: usize,
}

#[tauri::command]
fn call_config() -> CallConfig {
    let ice_servers = call::default_ice_servers();
    CallConfig {
        has_relay: call::has_relay(&ice_servers),
        ice_servers,
        max_participants: call::MAX_MESH_PARTICIPANTS,
    }
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

fn main() {
    tauri::Builder::default()
        .manage(AppState::default())
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
            send_file,
            fetch_attachment,
            save_attachment,
            attachment_limits,
            room_timer,
            set_room_timer,
            reply,
            react,
        ])
        .run(tauri::generate_context!())
        .expect("failed to start the Cairn desktop client");
}
