//! Rooms that are not open, followed anyway — against a real instance over HTTP.
//!
//! Before this, `Session::poll` fetched the open room and nothing else, so a ring or a
//! message anywhere else reached nobody until they happened to open that room. Now one
//! request (`GET /v1/activity`) says which readable rooms moved and only those are fetched.
//! These check both halves: that the other rooms really are followed — a welcome joined,
//! messages counted, mentions noticed, a ring delivered and declinable — and that the list
//! the instance answers with never names a room the caller may not read.

use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::sync::Arc;

use cairn_client_core::call::SignalKind;
use cairn_client_core::client::Client;
use cairn_client_core::session::{Event, Session, UnreadView};
use cairn_client_core::transport::HttpTransport;
use cairn_crypto::mls::Session as MlsSession;
use cairn_proto::{DeviceId, DeviceIdentity, UserId};
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
        axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>())
            .await
            .unwrap();
    });
    Server { addr, instance, _runtime: runtime }
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("cairn-bg-{name}-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn session(server: &Server, name: &str) -> Session {
    let s = Session::open(name, &format!("http://{}", server.addr), Some(&scratch(name))).unwrap();
    s.publish_key_packages(4).unwrap();
    s
}

/// A group alice owns with bob admitted, and bob's device in its encrypted group. Bob is
/// left with `room` open.
fn group_with(alice: &mut Session, bob: &mut Session) -> String {
    let room = alice.create_group(10).unwrap();
    let token = alice.create_invite(1, 24).unwrap();
    bob.redeem_invite(&token).unwrap();
    assert_eq!(alice.admit_waiting().unwrap().len(), 1);
    bob.open_room(&room).unwrap();
    for _ in 0..3 {
        bob.poll().unwrap();
    }
    room
}

fn short(user: &str) -> String {
    user.trim_start_matches("usr_").replace('-', "")[..8].to_string()
}

fn unread_in(events: &[Event]) -> Option<Vec<UnreadView>> {
    events.iter().rev().find_map(|e| match e {
        Event::Unread { rooms } => Some(rooms.clone()),
        _ => None,
    })
}

#[test]
fn a_room_that_is_not_open_is_followed_counted_and_rings() {
    let server = start();
    let mut alice = session(&server, "alice");
    let mut bob = session(&server, "bob");
    let lobby = group_with(&mut alice, &mut bob);

    // A second room bob is invited to and admitted to — and never opens. The welcome has to
    // be picked up in the background, or nothing that follows can be read.
    let quiet = alice.create_group(10).unwrap();
    let token = alice.create_invite(1, 24).unwrap();
    bob.redeem_invite(&token).unwrap();
    assert_eq!(alice.admit_waiting().unwrap().len(), 1);
    assert_eq!(bob.open_room_id().as_deref(), Some(lobby.as_str()));
    for _ in 0..3 {
        bob.poll().unwrap();
    }
    assert!(
        bob.rooms().iter().any(|r| r.id == quiet && r.joined),
        "the welcome was taken in the background: {:?}",
        bob.rooms()
    );

    // Two messages there, one naming bob. Alice's open room is `quiet` now.
    assert_eq!(alice.open_room_id().as_deref(), Some(quiet.as_str()));
    alice.send("anyone around?").unwrap();
    alice.send(&format!("@{} can you look at this", short(&bob.user_id()))).unwrap();
    let events = bob.poll().unwrap();
    let unread = unread_in(&events).expect("an unread event for the room that moved");
    assert_eq!(
        unread,
        vec![UnreadView { room: quiet.clone(), space: None, unread: 2, mentions: 1 }]
    );
    assert!(
        !events.iter().any(|e| matches!(e, Event::Message(_))),
        "nothing from another room is drawn into the open one's timeline"
    );
    let listed = bob.rooms().into_iter().find(|r| r.id == quiet).unwrap();
    assert_eq!((listed.unread, listed.mentions), (2, 1));

    // A ring there reaches bob, naming the room, and he can decline it from where he is.
    alice.call_join().unwrap();
    let events = bob.poll().unwrap();
    let ring = events.iter().find_map(|e| match e {
        Event::Signal { from, signal, room } if signal.kind == SignalKind::Join => {
            Some((from.clone(), room.clone()))
        }
        _ => None,
    });
    assert_eq!(ring, Some((alice.user_id(), Some(quiet.clone()))), "{events:?}");
    bob.call_decline().unwrap();
    let declined = alice.poll().unwrap().into_iter().any(|e| {
        matches!(&e, Event::Signal { signal, .. } if signal.kind == SignalKind::Decline)
    });
    assert!(declined, "the decline went into the room that rang, addressed to alice");

    // Opening it shows what was counted, with the mention marked, and clears the count.
    let history = bob.open_room(&quiet).unwrap();
    let bodies: Vec<(&str, bool)> =
        history.iter().map(|m| (m.body.as_str(), m.mentions_me)).collect();
    assert_eq!(bodies.len(), 2, "{bodies:?}");
    assert!(!bodies[0].1 && bodies[1].1, "only the second names bob: {bodies:?}");
    assert!(bob.unread().is_empty());

    // And the room left behind is still followed: a message there is counted now.
    alice.open_room(&lobby).unwrap();
    alice.send("back in the lobby").unwrap();
    let unread = unread_in(&bob.poll().unwrap()).expect("the lobby is counted now");
    assert_eq!(unread, vec![UnreadView { room: lobby, space: None, unread: 1, mentions: 0 }]);
}

#[test]
fn a_room_you_were_removed_from_no_longer_counts_or_rings() {
    let server = start();
    let mut alice = session(&server, "alice");
    let mut bob = session(&server, "bob");
    let first = group_with(&mut alice, &mut bob);
    let second = group_with(&mut alice, &mut bob);
    bob.open_room(&first).unwrap();
    bob.poll().unwrap();

    // The instance stops serving bob the second room. His device still holds its group, so
    // only the activity list stands between him and its traffic.
    let (a, b) = (alice.user_id().parse::<UserId>().unwrap(), bob.user_id().parse().unwrap());
    server.instance.remove_room_member(second.parse().unwrap(), a, b).unwrap();
    alice.open_room(&second).unwrap();
    alice.send("bob cannot see this").unwrap();
    alice.call_join().unwrap();
    let events = bob.poll().unwrap();
    assert!(unread_in(&events).is_none(), "nothing counted: {events:?}");
    assert!(
        !events.iter().any(|e| matches!(e, Event::Signal { .. })),
        "no ring from a room bob was removed from: {events:?}"
    );
}

/// A registered account in no room, signing its requests properly.
fn outsider(server: &Server) -> Client<HttpTransport> {
    let (user, device) = (UserId::new(), DeviceId::new());
    let identity = DeviceIdentity::new(user, device).to_credential();
    let mls = Arc::new(MlsSession::open(scratch("outsider"), &identity).unwrap());
    let client =
        Client::new(HttpTransport::new(format!("http://{}", server.addr)), mls, user, device);
    client.claim_account(None).unwrap();
    client
}

#[test]
fn the_activity_list_over_http_names_no_room_to_a_stranger_or_an_unsigned_request() {
    let server = start();
    let mut alice = session(&server, "alice");
    alice.create_group(10).unwrap();
    alice.send("hello").unwrap();

    assert!(outsider(&server).activity().unwrap().is_empty());

    use std::io::{Read, Write};
    let mut stream = std::net::TcpStream::connect(server.addr).unwrap();
    write!(
        stream,
        "GET /v1/activity HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        server.addr
    )
    .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    let status: u16 = response.split(' ').nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    assert_eq!(status, 401, "{response}");
    assert!(!response.contains("rom_"), "and names no room: {response}");
}
