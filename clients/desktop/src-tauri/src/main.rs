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

use cairn_client_core::session::{Event, MemberView, MessageView, RoomSummary, Session};
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
fn sign_in(state: State<'_, AppState>, profile: String, server: String) -> CmdResult<SignedIn> {
    let session = Session::open(&profile, &server, None).map_err(|e| e.to_string())?;
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

#[tauri::command]
fn send(state: State<'_, AppState>, text: String) -> CmdResult<()> {
    with(&state, |s| s.send(&text))
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
            send,
            poll,
            members,
            admit_waiting,
            create_invite,
            redeem_invite,
        ])
        .run(tauri::generate_context!())
        .expect("failed to start the Cairn desktop client");
}
