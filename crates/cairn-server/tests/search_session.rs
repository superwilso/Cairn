//! Local search, through a real instance and the session layer the desktop client
//! delegates to.
//!
//! Matching is unit-tested in `cairn_client_core::search`. What is tested here is the part
//! that can leak: that search finds what was said, that it never returns a message past
//! its room's timer, and that a room whose timer cannot be read is skipped rather than
//! searched as if it had none.

use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use cairn_client_core::history::History;
use cairn_client_core::session::{Event, Session};
use cairn_server::state::{Instance, RegistrationPolicy};

struct Server {
    addr: SocketAddr,
    runtime: tokio::runtime::Runtime,
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
    Server { addr, runtime }
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("cairn-search-{name}-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn session_in(server: &Server, name: &str, dir: &Path) -> Session {
    let mut s = Session::open(name, &format!("http://{}", server.addr), Some(dir)).unwrap();
    s.set_timer_recheck_ms(0);
    s
}

fn two_in_a_group(server: &Server) -> (Session, Session, String, PathBuf) {
    let mut alice = session_in(server, "alice", &scratch("alice"));
    let bob_dir = scratch("bob");
    let mut bob = session_in(server, "bob", &bob_dir);
    bob.publish_key_packages(3).unwrap();
    let room = alice.create_group(10).unwrap();
    let token = alice.create_invite(1, 24).unwrap();
    bob.redeem_invite(&token).unwrap();
    alice.admit_waiting().unwrap();
    bob.open_room(&room).unwrap();
    bob.poll().unwrap();
    (alice, bob, room, bob_dir)
}

fn hear(session: &mut Session, body: &str) {
    for _ in 0..6 {
        let events = session.poll().unwrap();
        if events.iter().any(|e| matches!(e, Event::Message(m) if m.body == body)) {
            return;
        }
    }
    panic!("never heard {body:?}");
}

#[test]
fn search_finds_what_was_said_on_both_sides() {
    let server = start();
    let (mut alice, mut bob, room, _) = two_in_a_group(&server);
    alice.send("The Quarterly numbers are in").unwrap();
    hear(&mut bob, "The Quarterly numbers are in");
    bob.send("nothing to see here").unwrap();

    for (who, session) in [("bob, who received it", &bob), ("alice, who sent it", &alice)] {
        let found = session.search("quarterly NUMBERS").unwrap();
        assert_eq!(found.hits.len(), 1, "{who}: {found:?}");
        let hit = &found.hits[0];
        assert_eq!(hit.room, room);
        assert_eq!(hit.matched, "Quarterly numbers");
        assert!(hit.id.is_some(), "{who} must be able to jump to it");
        assert!(found.unsearched.is_empty());
    }
}

#[test]
fn search_never_brings_back_an_expired_message() {
    // Bob does not poll after the timer runs out, so nothing else has swept his disk: if
    // search matched before sweeping, this is the message it would return.
    let server = start();
    let (mut alice, mut bob, room, bob_dir) = two_in_a_group(&server);
    alice.set_room_timer(Some(1_500)).unwrap();
    alice.send("self destructing").unwrap();
    hear(&mut bob, "self destructing");
    assert_eq!(bob.search("destruct").unwrap().hits.len(), 1, "found while it is alive");

    std::thread::sleep(Duration::from_millis(1_800));
    let found = bob.search("destruct").unwrap();
    assert!(found.hits.is_empty(), "an expired message must not be a search result: {found:?}");
    let on_disk = History::open(&bob_dir).unwrap().replay(room.parse().unwrap(), None, 0).unwrap();
    assert!(on_disk.is_empty(), "and searching must have swept it from the disk");
}

#[test]
fn a_room_whose_timer_cannot_be_read_is_skipped_and_named() {
    // Offline, the timer is unknown. Searching as if there were none would return a message
    // that may have expired while this device was away — so the room is skipped, and the
    // user is told which one.
    let server = start();
    let (mut alice, mut bob, room, _) = two_in_a_group(&server);
    alice.send("find me if you can").unwrap();
    hear(&mut bob, "find me if you can");

    server.runtime.shutdown_timeout(Duration::from_secs(2));
    let found = bob.search("find me").unwrap();
    assert!(found.hits.is_empty(), "{found:?}");
    assert_eq!(found.unsearched, vec![room]);
}

#[test]
fn a_blank_search_asks_the_instance_nothing() {
    let server = start();
    let (mut alice, mut bob, _room, _) = two_in_a_group(&server);
    alice.send("something to search").unwrap();
    hear(&mut bob, "something to search");
    // With the instance gone, any lookup would name the room as unsearched.
    server.runtime.shutdown_timeout(Duration::from_secs(2));
    let found = bob.search("   ").unwrap();
    assert!(found.hits.is_empty() && found.unsearched.is_empty());
}
