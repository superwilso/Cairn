//! Disappearing messages, through the session layer the desktop client delegates to.
//!
//! The instance's own rules for the timer are tested in `state.rs`. What is tested here is
//! the part a user actually sees: that a timer set on one device is the timer every member's
//! client shows, that a change is announced rather than discovered, and that an expired
//! message leaves this device's disk while the room is still open — not only at the next
//! restart.

use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use cairn_client_core::history::History;
use cairn_client_core::session::{Event, Session, SessionError};
use cairn_server::state::{Instance, RegistrationPolicy};

struct Server {
    addr: SocketAddr,
    instance: Arc<Instance>,
    _runtime: tokio::runtime::Runtime,
}

fn start() -> Server {
    let instance = Arc::new(Instance::in_memory());
    instance.set_registration_policy(RegistrationPolicy::Open).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();
    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
    let router = cairn_server::http::router(Arc::clone(&instance));
    runtime.spawn(async move {
        let listener = tokio::net::TcpListener::from_std(listener).unwrap();
        axum::serve(listener, router).await.unwrap();
    });
    Server { addr, instance, _runtime: runtime }
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("cairn-ttl-{name}-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn session_in(server: &Server, name: &str, dir: &Path) -> Session {
    let mut s = Session::open(name, &format!("http://{}", server.addr), Some(dir)).unwrap();
    // Every poll re-reads the timer, so a test does not wait out ten seconds per assertion.
    s.set_timer_recheck_ms(0);
    s
}

/// Alice and bob in one encrypted group, both polling, with bob's state directory returned
/// so a test can read his transcript off the disk.
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
    // The welcome has to be fetched before anything else: a joiner that has not got it cannot
    // read a word, and these tests are about what happens to words.
    bob.poll().unwrap();
    (alice, bob, room, bob_dir)
}

fn drain(session: &mut Session) -> Vec<Event> {
    let mut all = Vec::new();
    for _ in 0..6 {
        all.extend(session.poll().unwrap());
    }
    all
}

#[test]
fn a_timer_set_on_one_device_is_announced_to_the_others() {
    // Any member may set it, from any client, and the instance does not push. A member whose
    // screen still said "off" would go on writing things they meant to keep.
    let server = start();
    let (mut alice, mut bob, room, _) = two_in_a_group(&server);
    assert_eq!(bob.room_timer().unwrap(), None, "a new room starts without a timer");

    let confirmed = alice.set_room_timer(Some(3_600_000)).unwrap();
    assert_eq!(confirmed, Some(3_600_000), "the setter is told what is now in force");

    let announced = drain(&mut bob)
        .into_iter()
        .find_map(|e| match e {
            Event::Timer { ttl_ms } => Some(ttl_ms),
            _ => None,
        })
        .expect("bob must be told the timer changed, not left to reopen the room");
    assert_eq!(announced, Some(3_600_000));
    assert_eq!(bob.room_timer().unwrap(), Some(3_600_000), "and his header must agree");

    // Opening the room fresh reads the same value — the announcement and the state agree.
    bob.open_room(&room).unwrap();
    assert_eq!(bob.room_timer().unwrap(), Some(3_600_000));
}

#[test]
fn an_unchanged_timer_is_not_announced_again() {
    // Counterfactual for the test above: a recheck that announced on every poll would pass
    // it, and fill the timeline with the same notice every ten seconds.
    let server = start();
    let (mut alice, mut bob, _room, _) = two_in_a_group(&server);
    alice.set_room_timer(Some(3_600_000)).unwrap();
    drain(&mut bob);

    let again = drain(&mut bob);
    assert!(
        !again.iter().any(|e| matches!(e, Event::Timer { .. })),
        "a timer that did not change must not be announced again"
    );
}

#[test]
fn clearing_the_timer_is_announced_as_off() {
    let server = start();
    let (mut alice, mut bob, _room, _) = two_in_a_group(&server);
    alice.set_room_timer(Some(3_600_000)).unwrap();
    drain(&mut bob);

    assert_eq!(alice.set_room_timer(None).unwrap(), None);
    let cleared = drain(&mut bob).into_iter().any(|e| matches!(e, Event::Timer { ttl_ms: None }));
    assert!(cleared, "turning the timer off is a change members must see too");
}

#[test]
fn a_timer_of_zero_or_less_is_refused_with_a_reason() {
    let server = start();
    let (mut alice, _bob, _room, _) = two_in_a_group(&server);
    assert!(matches!(alice.set_room_timer(Some(0)), Err(SessionError::BadTimer)));
    assert!(matches!(alice.set_room_timer(Some(-5)), Err(SessionError::BadTimer)));
    assert_eq!(
        alice.room_timer().unwrap(),
        None,
        "a refused change must leave the timer as it was"
    );
}

#[test]
fn an_expired_message_leaves_the_disk_while_the_room_is_still_open() {
    // `History::replay` deletes expired entries, but it used to run only on opening a room.
    // A client left open for a day kept a one-hour message on disk for that whole day,
    // which is a timer true of the instance and false of the one device its user controls.
    let server = start();
    let (mut alice, mut bob, room, bob_dir) = two_in_a_group(&server);
    alice.set_room_timer(Some(1_500)).unwrap();
    drain(&mut bob);

    alice.send("gone in a second and a half").unwrap();
    // Stops at the first poll that hears it: a debug build polls slowly enough that draining
    // could outlast the timer, and this needs to catch the message while it is still alive.
    let mut heard = false;
    for _ in 0..6 {
        if bob.poll().unwrap().iter().any(|e| matches!(e, Event::Message(_))) {
            heard = true;
            break;
        }
    }
    assert!(heard, "bob must have received it, or there is nothing to expire");
    let on_disk = || {
        History::open(&bob_dir)
            .unwrap()
            .replay(room.parse().unwrap(), None, i64::MAX)
            .unwrap()
            .len()
    };
    assert_eq!(on_disk(), 1, "and it must be on his disk to begin with");

    std::thread::sleep(Duration::from_millis(1_700));
    let expired = drain(&mut bob).into_iter().any(|e| matches!(e, Event::Expired { .. }));
    assert!(expired, "the frontend must be told to take it off the screen");
    // Read with no timer at all, so a filter-on-read implementation cannot pass.
    assert_eq!(on_disk(), 0, "the expired message must be gone from the file itself");
}

#[test]
fn a_new_timer_reaches_messages_already_sent() {
    // **This documents present behaviour that contradicts a recorded decision**, and the
    // desktop client warns about it before anyone picks a timer.
    //
    // `docs/10-roadmap.md` says the timer "applies to future messages only". The instance
    // measures every stored message against the *current* setting on each read, so turning a
    // timer on deletes everything already older than it — on the instance, and on every
    // honest member's device. A client promising otherwise would be promising a history
    // that is about to be deleted.
    //
    // If the instance is changed to honour the decision, this test fails — and the warning
    // in `clients/desktop/ui/timer.js` must change in the same commit.
    let server = start();
    let (mut alice, mut bob, room, _) = two_in_a_group(&server);
    alice.send("said before any timer existed").unwrap();
    drain(&mut bob);
    std::thread::sleep(Duration::from_millis(300));

    alice.set_room_timer(Some(100)).unwrap();

    let room_id = room.parse().unwrap();
    let alice_id = alice.user_id().parse().unwrap();
    let stored = server.instance.messages_since(room_id, alice_id, 0, now_ms()).unwrap();
    assert!(
        stored.is_empty(),
        "the instance deletes messages sent before the timer was set (see the comment above)"
    );
    assert!(
        alice.open_room(&room).unwrap().is_empty(),
        "and so does the setter's own device, at once"
    );
}

fn now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as i64
}
