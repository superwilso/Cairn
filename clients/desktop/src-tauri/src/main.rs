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
    Event, LinkPreviewSettings, MemberView, MessageView, RoomSummary, Session,
};
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
/// under the lock, fetch on a blocking thread without it, and send under the lock again —
/// `finish_send` refuses if the user switched rooms in between.
///
/// Returns the message as the timeline should show it, card included, because MLS never
/// decrypts a device's own message back to it.
#[tauri::command]
async fn send(state: State<'_, AppState>, text: String) -> CmdResult<MessageView> {
    let mut pending = with(&state, |s| s.begin_send(&text))?;
    let pending = tauri::async_runtime::spawn_blocking(move || {
        pending.unfurl();
        pending
    })
    .await
    .map_err(|e| e.to_string())?;
    with(&state, |s| s.finish_send(pending))
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

#[tauri::command]
fn poll(state: State<'_, AppState>) -> CmdResult<Vec<Event>> {
    with(&state, |s| s.poll())
}

#[tauri::command]
fn members(state: State<'_, AppState>) -> CmdResult<Vec<MemberView>> {
    with(&state, |s| s.members())
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
            admit_waiting,
            create_invite,
            redeem_invite,
            call_join,
            call_leave,
            signal,
            call_id,
            call_config,
            link_previews,
            set_link_previews,
            instagram_proxy_disclosure,
            open_link,
        ])
        .run(tauri::generate_context!())
        .expect("failed to start the Cairn desktop client");
}
