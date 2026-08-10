//! Joining a room over HTTP, and seeing who is in it.
//!
//! M1's slice handed the MLS welcome from Alice to Bob in-process, which is not a thing a
//! real client can do. This covers the path the interactive client actually takes: the
//! welcome travels as an ordinary room message, the joiner recognises it among traffic it
//! cannot read, and every later roster change surfaces as an event rather than a silent
//! state advance.

use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::sync::Arc;

use cairn_client_core::client::Client;
use cairn_client_core::transport::HttpTransport;
use cairn_client_core::{accept_welcome, Conversation, TimelineEvent};
use cairn_crypto::mls::Session;
use cairn_proto::{DeviceId, RoomSeal, RoomShape, UserId};
use cairn_server::state::{Instance, RegistrationPolicy};

fn shape() -> RoomShape {
    RoomShape { is_direct: true, is_publicly_discoverable: false, member_ceiling: 10 }
}

fn scratch(name: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join("cairn-join").join(format!("{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

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

struct Peer {
    session: Arc<Session>,
    client: Client<HttpTransport>,
    user: UserId,
    device: DeviceId,
}

impl Peer {
    fn new(server: &Server, name: &str) -> Self {
        let session = Arc::new(Session::open(scratch(name), name.as_bytes()).unwrap());
        let (user, device) = (UserId::new(), DeviceId::new());
        let client = Client::new(
            HttpTransport::new(format!("http://{}", server.addr)),
            session.clone(),
            user,
            device,
        );
        client.claim_account(None).unwrap();
        Self { session, client, user, device }
    }

    fn conversation(&self, seal: RoomSeal, room: cairn_proto::RoomId) -> Conversation {
        Conversation::create_encrypted(seal, room, self.user, self.device, self.session.clone())
            .unwrap()
    }
}

/// Relay a commit and its welcome through the room, as a real client must.
fn relay(
    client: &Client<HttpTransport>,
    convo: &Conversation,
    output: cairn_crypto::mls::CommitOutput,
) {
    let commit = output.commit.to_bytes().unwrap();
    client.send(convo.room(), &convo.wrap_handshake(&commit, 1_000).unwrap()).unwrap();
    if let Some(welcome) = output.welcome {
        let bytes = welcome.to_bytes().unwrap();
        client.send(convo.room(), &convo.wrap_handshake(&bytes, 1_001).unwrap()).unwrap();
    }
}

#[test]
fn a_joiner_finds_its_welcome_among_traffic_it_cannot_read() {
    // The welcome shares the room with commits and ciphertext addressed to a group the
    // joiner is not in yet. It has to pick out the one envelope that is for it without
    // treating the others as errors.
    let server = start();
    let alice = Peer::new(&server, "alice-join");
    let bob = Peer::new(&server, "bob-join");
    assert_eq!(bob.client.publish_key_packages(2).unwrap(), 2);

    let created = alice.client.create_room(shape()).unwrap();
    let seal = created.seal;
    let room = created.room;
    let mut alice_convo = alice.conversation(seal, room);

    // Traffic before Bob exists in the group: he must not choke on it.
    let noise = alice_convo.send(b"a message bob cannot read", 500).unwrap();
    alice.client.send(room, &noise.envelope).unwrap();

    alice.client.add_room_member(room, bob.user).unwrap();
    let claimed = alice.client.claim_key_packages(bob.user).unwrap();
    let key_package =
        cairn_crypto::mls::parse_message(&hex::decode(&claimed[0].key_package).unwrap()).unwrap();
    let output = alice_convo.group_mut().unwrap().add_member(key_package).unwrap();
    relay(&alice.client, &alice_convo, output);

    // Bob polls the room and looks for a welcome.
    let fetched = bob.client.fetch_since(room, 0).unwrap();
    assert!(fetched.len() >= 3, "ciphertext, commit and welcome are all in the room");

    let mut joined = None;
    for message in &fetched {
        match accept_welcome(&bob.session, &message.envelope) {
            Ok(Some(group)) => {
                joined = Some(group);
                break;
            }
            Ok(None) => {}
            Err(e) => panic!("a message bob cannot use must not be an error: {e}"),
        }
    }

    let group = joined.expect("bob must find his welcome in the room");
    let mut bob_convo =
        Conversation::join_encrypted(seal, room, bob.user, bob.device, bob.session.clone(), group)
            .unwrap();

    // And the group works from both ends.
    let sent = alice_convo.send(b"hello, you made it", 2_000).unwrap();
    alice.client.send(room, &sent.envelope).unwrap();
    let after = fetched.last().unwrap().server_seq;
    let fetched = bob.client.fetch_since(room, after).unwrap();
    let received = fetched
        .iter()
        .find_map(|m| bob_convo.receive(&m.envelope).ok().and_then(TimelineEvent::message))
        .expect("bob decrypts a message sent after he joined");
    assert_eq!(received.body, b"hello, you made it");
}

#[test]
fn a_member_added_later_shows_up_in_the_timeline() {
    // The wiretap case. Bob is already in the room; Alice adds Carol. Bob must be told,
    // by name and with Carol's key, rather than silently advancing an epoch.
    let server = start();
    let alice = Peer::new(&server, "alice-third");
    let bob = Peer::new(&server, "bob-third");
    let carol = Peer::new(&server, "carol-third");
    bob.client.publish_key_packages(2).unwrap();
    carol.client.publish_key_packages(2).unwrap();

    let created = alice.client.create_room(shape()).unwrap();
    let (seal, room) = (created.seal, created.room);
    let mut alice_convo = alice.conversation(seal, room);

    // Bob joins.
    alice.client.add_room_member(room, bob.user).unwrap();
    let claimed = alice.client.claim_key_packages(bob.user).unwrap();
    let kp =
        cairn_crypto::mls::parse_message(&hex::decode(&claimed[0].key_package).unwrap()).unwrap();
    let output = alice_convo.group_mut().unwrap().add_member(kp).unwrap();
    relay(&alice.client, &alice_convo, output);

    let fetched = bob.client.fetch_since(room, 0).unwrap();
    let group = fetched
        .iter()
        .find_map(|m| accept_welcome(&bob.session, &m.envelope).ok().flatten())
        .expect("a welcome for bob");
    let mut bob_convo =
        Conversation::join_encrypted(seal, room, bob.user, bob.device, bob.session.clone(), group)
            .unwrap();
    let mut cursor = fetched.last().unwrap().server_seq;

    // Now Carol is added. Bob did not ask for this and must see it.
    alice.client.add_room_member(room, carol.user).unwrap();
    let claimed = alice.client.claim_key_packages(carol.user).unwrap();
    let kp =
        cairn_crypto::mls::parse_message(&hex::decode(&claimed[0].key_package).unwrap()).unwrap();
    let output = alice_convo.group_mut().unwrap().add_member(kp).unwrap();
    relay(&alice.client, &alice_convo, output);

    let mut announced = None;
    for message in bob.client.fetch_since(room, cursor).unwrap() {
        cursor = cursor.max(message.server_seq);
        if let Ok(TimelineEvent::Membership { added, .. }) = bob_convo.receive(&message.envelope) {
            if !added.is_empty() {
                announced = Some(added);
            }
        }
    }

    let added = announced.expect("bob must be told that someone joined his conversation");
    assert_eq!(added.len(), 1);
    assert_eq!(added[0].identity, b"carol-third");
    assert_eq!(
        added[0].signature_key,
        carol.session.public_key(),
        "the event carries the key that joined, so its safety number can be shown"
    );

    // And Bob can now compute a comparable number for the member he never invited.
    let number = bob_convo.safety_number_with(&added[0]).unwrap();
    assert_eq!(number.digits().len(), 60);
}

#[test]
fn a_removed_member_stops_being_able_to_read_and_everyone_is_told() {
    let server = start();
    let alice = Peer::new(&server, "alice-remove");
    let bob = Peer::new(&server, "bob-remove");
    bob.client.publish_key_packages(2).unwrap();

    let created = alice.client.create_room(shape()).unwrap();
    let (seal, room) = (created.seal, created.room);
    let mut alice_convo = alice.conversation(seal, room);

    alice.client.add_room_member(room, bob.user).unwrap();
    let claimed = alice.client.claim_key_packages(bob.user).unwrap();
    let kp =
        cairn_crypto::mls::parse_message(&hex::decode(&claimed[0].key_package).unwrap()).unwrap();
    let output = alice_convo.group_mut().unwrap().add_member(kp).unwrap();
    relay(&alice.client, &alice_convo, output);

    let fetched = bob.client.fetch_since(room, 0).unwrap();
    let group = fetched
        .iter()
        .find_map(|m| accept_welcome(&bob.session, &m.envelope).ok().flatten())
        .expect("a welcome for bob");
    let mut bob_convo =
        Conversation::join_encrypted(seal, room, bob.user, bob.device, bob.session.clone(), group)
            .unwrap();
    let mut cursor = fetched.last().unwrap().server_seq;

    // Alice removes Bob from the MLS group, then from the room.
    let bob_leaf = alice_convo
        .members()
        .into_iter()
        .find(|m| m.identity == b"bob-remove")
        .expect("bob is in the roster")
        .index;
    let output = alice_convo.group_mut().unwrap().remove_member(bob_leaf).unwrap();
    relay(&alice.client, &alice_convo, output);

    // Bob sees his own removal before losing read access, which is the honest ordering:
    // it is the last thing the group tells him.
    // Bob is told he was removed — by a different route than a third party's removal,
    // because mls-rs does not advance a group its local client was ejected from, so a
    // roster diff sees nothing change. Found by running this over HTTP and printing what
    // the removed member actually received.
    let mut told = false;
    for message in bob.client.fetch_since(room, cursor).unwrap() {
        cursor = cursor.max(message.server_seq);
        if let Ok(TimelineEvent::RemovedFromRoom { by }) = bob_convo.receive(&message.envelope) {
            told = true;
            assert_eq!(by, Some(0), "and by whom");
        }
    }
    assert!(told, "a removed member must be told, or their client shows a room they are out of");

    alice.client.remove_room_member(room, bob.user).unwrap();
    let err = bob.client.fetch_since(room, 0).expect_err("a removed member must lose read access");
    assert!(format!("{err}").contains("not a member"), "unexpected error: {err}");

    // And the messages Alice sends afterwards are unreadable to him even if he keeps
    // fetching through some other route.
    let after = alice_convo.send(b"after bob left", 9_000).unwrap();
    assert!(
        bob_convo.receive(&after.envelope).is_err(),
        "post-compromise security must hold: a removed member cannot decrypt later messages"
    );
}
