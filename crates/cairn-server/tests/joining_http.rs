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
use cairn_proto::{DeviceId, DeviceIdentity, RoomSeal, RoomShape, UserId};
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
        axum::serve(listener, router.into_make_service_with_connect_info::<std::net::SocketAddr>())
            .await
            .unwrap();
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
        // The credential is built from the ids, not from `name`. A display-name credential
        // is what let one member present another's label and lock the real person out of
        // the room; `claim_key_packages` now refuses anything it cannot attribute.
        let (user, device) = (UserId::new(), DeviceId::new());
        let identity = DeviceIdentity::new(user, device).to_credential();
        let session = Arc::new(Session::open(scratch(name), &identity).unwrap());
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
    // Asserted as an *account*, which is what the credential now carries. Under the old
    // display-name form this comparison could only ever be against a string the joining
    // client chose for itself.
    assert_eq!(
        DeviceIdentity::parse(&added[0].identity).expect("a Cairn credential").user(),
        carol.user,
        "the event must name the account that joined, not a label it picked"
    );
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
        // Found by account id rather than by label — the mapping from MLS roster to server
        // member that the old credential made impossible.
        .find(|m| DeviceIdentity::parse(&m.identity).is_ok_and(|id| id.belongs_to(bob.user)))
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

#[test]
fn a_link_card_reaches_the_recipient_and_the_server_never_sees_the_url() {
    // The whole claim of `docs/05-embeds.md`: the sender renders the card, it travels
    // inside the encrypted body, the server relays bytes it cannot read, and the recipient
    // displays it without contacting the site.
    let server = start();
    let alice = Peer::new(&server, "alice-embed");
    let bob = Peer::new(&server, "bob-embed");
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
    let cursor = fetched.last().unwrap().server_seq;

    const SECRET_URL: &str = "https://example.test/a-very-distinctive-path-99213";
    let card = cairn_client_core::Card {
        url: SECRET_URL.to_string(),
        title: Some("A headline".into()),
        description: Some("What the page says.".into()),
        site_name: Some("Example News".into()),
        ..cairn_client_core::Card::default()
    };

    let sent = alice_convo.send_with_card(b"look at this", Some(card), 5_000).unwrap();

    // Nothing the server receives may contain the URL. Checked against the serialized
    // envelope, which is exactly what goes over the wire and into its storage.
    let on_the_wire = serde_json::to_string(&sent.envelope).unwrap();
    assert!(
        !on_the_wire.contains("example.test"),
        "the server must never learn the URL — that is the entire point of a sender-side unfurl"
    );
    assert!(!on_the_wire.contains("A headline"));

    alice.client.send(room, &sent.envelope).unwrap();

    let received = bob
        .client
        .fetch_since(room, cursor)
        .unwrap()
        .iter()
        .find_map(|m| bob_convo.receive(&m.envelope).ok().and_then(TimelineEvent::message))
        .expect("bob receives the message");

    assert_eq!(received.body, b"look at this");
    let card = received.card.expect("the card travelled with it");
    assert_eq!(card.url, SECRET_URL, "and the recipient can see the real link");
    assert_eq!(card.claimed_source(), Some("Example News"));
}

#[test]
fn a_hostile_card_is_clamped_before_a_recipient_renders_it() {
    // Card fields are sender-controlled. A recipient must not accept a megabyte of title.
    let card = cairn_client_core::Card {
        url: "https://example.test/".into(),
        title: Some("t".repeat(50_000)),
        description: Some("d".repeat(50_000)),
        ..cairn_client_core::Card::default()
    }
    .clamp();
    assert!(card.title.unwrap().chars().count() <= 201);
    assert!(card.description.unwrap().chars().count() <= 501);
}

#[test]
fn an_invite_joiner_can_be_admitted_without_anyone_pasting_a_uuid() {
    // M2's exit condition, end to end. The joiner redeems a link and appears in the
    // instance's member list; the existing member's client works out who is *in the room but
    // not in the group* by comparing account ids, and admits them.
    //
    // That comparison is only possible because every MLS leaf now names its account. Under
    // the display-name credential the roster carried labels a client chose for itself, so
    // there was nothing to match the server's list against and a human had to carry a uuid
    // across by hand.
    let server = start();
    let alice = Peer::new(&server, "admit-alice");
    let bob = Peer::new(&server, "admit-bob");
    bob.client.publish_key_packages(3).unwrap();

    let created = alice.client.create_room(shape()).unwrap();
    let room = created.room;
    let seal = created.seal;
    let mut alice_convo = alice.conversation(seal, room);

    // Bob joins by invite. He is a member of the room and cannot read a word of it.
    let token = alice.client.create_room_invite(room, 1, None).unwrap();
    assert_eq!(bob.client.redeem_room_invite(&token).unwrap(), room);

    // What alice's client can now compute, which it could not before.
    let in_group: Vec<_> = alice_convo
        .members()
        .iter()
        .filter_map(|m| DeviceIdentity::parse(&m.identity).ok().map(|id| id.user()))
        .collect();
    let waiting: Vec<_> = alice
        .client
        .room_members(room)
        .unwrap()
        .into_iter()
        .map(|(user, _)| user)
        .filter(|u| !in_group.contains(u))
        .collect();
    assert_eq!(waiting, vec![bob.user], "bob must be identifiable as waiting, by account id");

    // Admitting him is then the ordinary MLS add.
    let claimed = alice.client.claim_key_packages(bob.user).unwrap();
    let key_package =
        cairn_crypto::mls::parse_message(&hex::decode(&claimed[0].key_package).unwrap()).unwrap();
    let commit = alice_convo.group_mut().unwrap().add_member(key_package).unwrap();
    let bob_group = bob.session.join(&commit.welcome.expect("a welcome for bob")).unwrap();
    let mut bob_convo = Conversation::join_encrypted(
        seal,
        room,
        bob.user,
        bob.device,
        bob.session.clone(),
        bob_group,
    )
    .unwrap();

    // And he can read what follows.
    let sent = alice_convo.send(b"admitted without a uuid", 1_000).unwrap();
    alice.client.send(room, &sent.envelope).unwrap();
    let fetched = bob.client.fetch_since(room, 0).unwrap();
    let body = fetched
        .iter()
        .find_map(|m| bob_convo.receive(&m.envelope).ok().and_then(|e| e.message()))
        .expect("bob must be able to read the room he was admitted to");
    assert_eq!(body.body, b"admitted without a uuid");

    // Nobody is waiting any more — the counterfactual, without which a comparison that
    // always reported everyone would pass the assertion above.
    let in_group: Vec<_> = alice_convo
        .members()
        .iter()
        .filter_map(|m| DeviceIdentity::parse(&m.identity).ok().map(|id| id.user()))
        .collect();
    let still_waiting: Vec<_> = alice
        .client
        .room_members(room)
        .unwrap()
        .into_iter()
        .map(|(user, _)| user)
        .filter(|u| !in_group.contains(u))
        .collect();
    assert!(still_waiting.is_empty(), "after admission nobody should be listed as waiting");
}
