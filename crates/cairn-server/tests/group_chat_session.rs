//! The desktop client's session layer, against a real instance over HTTP.
//!
//! `cairn_client_core::session::Session` is what the Tauri commands delegate to, so this is
//! the seam the whole desktop client stands on. Proving it here means the GUI is only ever
//! presentation — and it can be proven without a display, which is the point.
//!
//! The flow is the one a group chat actually needs and that no client could do before:
//! create a **group** (not a DM), invite, redeem, admit, and talk.

use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::sync::Arc;

use cairn_client_core::session::{Event, Session};
use cairn_server::state::{Instance, RegistrationPolicy};

struct Server {
    addr: SocketAddr,
    _runtime: tokio::runtime::Runtime,
}

fn start() -> Server {
    let instance = Arc::new(Instance::in_memory());
    instance.set_registration_policy(RegistrationPolicy::Open).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();
    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
    let router = cairn_server::http::router(instance);
    runtime.spawn(async move {
        let listener = tokio::net::TcpListener::from_std(listener).unwrap();
        axum::serve(listener, router).await.unwrap();
    });
    Server { addr, _runtime: runtime }
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("cairn-sess-{name}-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn session(server: &Server, name: &str) -> Session {
    Session::open(name, &format!("http://{}", server.addr), Some(&scratch(name))).unwrap()
}

#[test]
fn a_group_chat_works_end_to_end_through_the_session_layer() {
    let server = start();
    let mut alice = session(&server, "alice");
    let mut bob = session(&server, "bob");

    // Without published key packages nobody can be admitted to a group, and the failure
    // surfaces much later as "my friend cannot add me".
    bob.publish_key_packages(3).unwrap();

    // A group, not a DM. This is the case no client could reach before: `cairn-cli`
    // hardcoded is_direct/ceiling 2, so every room was two people.
    let room = alice.create_group(50).unwrap();
    assert_eq!(
        alice.open_room_tier().as_deref(),
        Some("T2"),
        "a private group must seal as T2 — end-to-end encrypted, not merely transport"
    );

    // Bob joins by invite. No user id crosses between them.
    let token = alice.create_invite(1, 24).unwrap();
    let joined = bob.redeem_invite(&token).unwrap();
    assert_eq!(joined, room, "the invite must land bob in alice's room");

    // Redeeming joins the room; it does not hand over the keys. Bob is present and cannot
    // read anything, which is the property the UI has to show rather than hide.
    let waiting = alice.waiting().unwrap();
    assert_eq!(waiting.len(), 1, "bob must show as waiting, identified by account");

    let admitted = alice.admit_waiting().unwrap();
    assert_eq!(admitted.len(), 1, "admitting must let exactly bob in");
    assert!(
        alice.waiting().unwrap().is_empty(),
        "after admission nobody is left waiting — without this a check that always \
         reported everyone would pass the assertion above"
    );

    // Bob picks up the welcome and the message that follows it.
    bob.open_room(&room).unwrap();
    bob.poll().unwrap();

    alice.send("first thing said in a group").unwrap();

    let mut heard = None;
    for _ in 0..8 {
        for event in bob.poll().unwrap() {
            if let Event::Message(m) = event {
                heard = Some(m.body);
            }
        }
        if heard.is_some() {
            break;
        }
    }
    assert_eq!(
        heard.as_deref(),
        Some("first thing said in a group"),
        "bob must be able to read the group he was admitted to"
    );

    // And the member view keeps the two lists distinct rather than flattening them.
    let members = alice.members().unwrap();
    assert_eq!(members.len(), 2);
    assert!(members.iter().all(|m| m.in_group), "both are in the encrypted group now");
}

#[test]
fn a_group_is_still_end_to_end_encrypted_not_merely_transport() {
    // The property most likely to be quietly lost when "group" is added to a product: a
    // bigger room drifting to a server-readable tier. Only discoverability should do that.
    let server = start();
    let mut alice = session(&server, "tier");
    alice.create_group(500).unwrap();
    assert_eq!(alice.open_room_tier().as_deref(), Some("T2"));
}

#[test]
fn a_group_larger_than_the_private_ceiling_is_refused_rather_than_downgraded() {
    // Asking for more members than T2 allows does not get a bigger private room — it would
    // get a public, server-readable one. Refusing beats silently handing back something
    // weaker than was asked for.
    let server = start();
    let mut alice = session(&server, "toobig");
    assert!(alice.create_group(cairn_proto::tier::T2_MAX_MEMBERS + 1).is_err());
}

#[test]
fn a_member_who_has_not_been_admitted_cannot_send() {
    // Bob is in the room and has no group. Sending must fail loudly rather than appear to
    // work and vanish.
    let server = start();
    let mut alice = session(&server, "nosend-a");
    let mut bob = session(&server, "nosend-b");
    let room = alice.create_group(10).unwrap();
    let token = alice.create_invite(1, 24).unwrap();
    bob.redeem_invite(&token).unwrap();
    bob.open_room(&room).unwrap();

    assert!(bob.send("can anyone hear me").is_err(), "an unadmitted member cannot send");
}
