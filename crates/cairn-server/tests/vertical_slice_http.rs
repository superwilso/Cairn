//! M1's exit condition, over a real network client and a real socket.
//!
//! Two independent clients — separate sessions, separate on-disk stores, no shared state
//! except the server — claim accounts, exchange key packages, build an MLS group, send and
//! receive an encrypted message, both restart, resume, and file a report the server
//! verifies.
//!
//! Everything goes through `cairn_client_core::Client` and `HttpTransport`, so the signing
//! paths exercised here are the ones a real client uses rather than a parallel test
//! implementation that could drift from them.

use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::sync::Arc;

use cairn_client_core::client::Client;
use cairn_client_core::transport::HttpTransport;
use cairn_client_core::{Conversation, ConversationIndex};
use cairn_crypto::mls::Session;
use cairn_proto::{DeviceId, DeviceIdentity, RoomSeal, RoomShape, UserId};
use cairn_server::state::{Instance, RegistrationPolicy};

fn dm_shape() -> RoomShape {
    RoomShape { is_direct: true, is_publicly_discoverable: false, member_ceiling: 2 }
}

fn scratch(name: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join("cairn-slice").join(format!("{name}-{}", std::process::id()));
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

/// One participant: a persistent session plus a client pointed at the instance.
struct Peer {
    dir: PathBuf,
    session: Arc<Session>,
    client: Client<HttpTransport>,
    user: UserId,
    device: DeviceId,
}

impl Peer {
    fn new(server: &Server, dir: PathBuf, _identity: &[u8]) -> Self {
        // Ids first: the MLS credential is built from them now, not from a display name.
        // The instance refuses a key package whose credential names a different account,
        // and a claiming client refuses one that does not match what it asked for.
        let (user, device) = (UserId::new(), DeviceId::new());
        let session = Arc::new(
            Session::open(&dir, &DeviceIdentity::new(user, device).to_credential()).unwrap(),
        );
        let client = Client::new(
            HttpTransport::new(format!("http://{}", server.addr)),
            session.clone(),
            user,
            device,
        );
        Self { dir, session, client, user, device }
    }

    /// Reopen from disk alone, as a restarted process would.
    fn restart(self, server: &Server, _identity: &[u8]) -> Self {
        let Peer { dir, user, device, .. } = self;
        // The same credential the directory was created under — a session that reopened
        // with different bytes would be refused by the device-key store.
        let session = Arc::new(
            Session::open(&dir, &DeviceIdentity::new(user, device).to_credential()).unwrap(),
        );
        let client = Client::new(
            HttpTransport::new(format!("http://{}", server.addr)),
            session.clone(),
            user,
            device,
        );
        Self { dir, session, client, user, device }
    }
}

#[test]
fn two_clients_hold_an_e2ee_conversation_over_http_and_both_resume() {
    let server = start();

    let alice = Peer::new(&server, scratch("alice"), b"alice@instance");
    let bob = Peer::new(&server, scratch("bob"), b"bob@instance");

    alice.client.claim_account(None).unwrap();
    bob.client.claim_account(None).unwrap();

    // Bob publishes key packages so he can be added to a group. Without this, Alice's add
    // fails — which is the honest behaviour, not a silent half-add.
    assert_eq!(bob.client.publish_key_packages(3).unwrap(), 3);

    // --- Alice creates the room and adds Bob. ---
    let created = alice.client.create_room(dm_shape()).unwrap();
    assert_eq!(created.tier_label(), "T1", "a two-person direct room is T1");
    assert!(created.seal.tier().is_e2ee());
    let room = created.room;

    alice.client.add_room_member(room, bob.user).unwrap();

    let seal = RoomSeal::new(dm_shape()).unwrap();
    let mut alice_convo =
        Conversation::create_encrypted(seal, room, alice.user, alice.device, alice.session.clone())
            .unwrap();

    // The MLS add: claim Bob's key package from the server and commit it.
    let claimed = alice.client.claim_key_packages(bob.user).unwrap();
    assert_eq!(claimed.len(), 1, "bob has one device");
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

    // Both remember which MLS group backs this room, or neither can resume.
    let group_id = alice_convo.group_id().unwrap().to_vec();
    for dir in [&alice.dir, &bob.dir] {
        ConversationIndex::open(dir).unwrap().record(room, &seal, Some(&group_id)).unwrap();
    }

    // --- A message, over the wire. ---
    let sent = alice_convo.send(b"hello over http", 1_000).unwrap();
    let receipt = alice.client.send(room, &sent.envelope).unwrap();
    assert!(receipt.franking_tag.is_some(), "an E2EE message must come back franked");

    let fetched = bob.client.fetch_since(room, 0).unwrap();
    assert_eq!(fetched.len(), 1);
    let received =
        bob_convo.receive(&fetched[0].envelope).unwrap().message().expect("an application message");
    assert_eq!(received.body, b"hello over http");

    // Bob keeps what he needs to report this message later.
    let franking = received.franking.expect("E2EE messages carry franking material");
    let first_tag = fetched[0].franking_tag.clone().unwrap();
    let first_seq = fetched[0].server_seq;

    // --- Both ends restart. Only the directories survive. ---
    let alice_user = alice.user;
    let (alice_dir, bob_dir) = (alice.dir.clone(), bob.dir.clone());
    drop(alice_convo);
    drop(bob_convo);
    let alice = alice.restart(&server, b"alice@instance");
    let bob = bob.restart(&server, b"bob@instance");

    let alice_index = ConversationIndex::open(&alice_dir).unwrap();
    let bob_index = ConversationIndex::open(&bob_dir).unwrap();
    let mut alice_convo = Conversation::resume_encrypted(
        seal,
        room,
        alice.user,
        alice.device,
        alice.session.clone(),
        &alice_index.group_id(&room).unwrap().unwrap(),
    )
    .unwrap();
    let mut bob_convo = Conversation::resume_encrypted(
        seal,
        room,
        bob.user,
        bob.device,
        bob.session.clone(),
        &bob_index.group_id(&room).unwrap().unwrap(),
    )
    .unwrap();

    let sent2 = alice_convo.send(b"still here after a restart", 2_000).unwrap();
    let receipt2 = alice.client.send(room, &sent2.envelope).unwrap();

    let fetched = bob.client.fetch_since(room, first_seq).unwrap();
    assert_eq!(fetched.len(), 1, "only messages after the last one seen");
    let received2 =
        bob_convo.receive(&fetched[0].envelope).unwrap().message().expect("an application message");
    assert_eq!(received2.body, b"still here after a restart");

    // --- Bob reports the transcript, and the server verifies it. ---
    let franking2 = received2.franking.expect("franking material");
    let report = cairn_crypto::TranscriptReport {
        messages: vec![
            cairn_crypto::ReportedMessage {
                plaintext: b"hello over http".to_vec(),
                opening: franking.opening,
                context: cairn_crypto::FrankingContext {
                    commitment: franking.commitment,
                    room,
                    sender: alice_user,
                    sender_device: alice.device,
                    server_seq: first_seq,
                    prev_commitment: None,
                },
                tag: cairn_crypto::Tag(hex::decode(first_tag).unwrap().try_into().unwrap()),
            },
            cairn_crypto::ReportedMessage {
                plaintext: b"still here after a restart".to_vec(),
                opening: franking2.opening,
                context: cairn_crypto::FrankingContext {
                    commitment: franking2.commitment,
                    room,
                    sender: alice_user,
                    sender_device: alice.device,
                    server_seq: receipt2.server_seq,
                    prev_commitment: Some(franking.commitment),
                },
                tag: cairn_crypto::Tag(
                    hex::decode(fetched[0].franking_tag.clone().unwrap())
                        .unwrap()
                        .try_into()
                        .unwrap(),
                ),
            },
        ],
    };

    let verdict = bob.client.report(&report).unwrap();
    assert!(verdict.verified, "an honest report must verify: {:?}", verdict.reason);
    assert_eq!(verdict.message_count, 2);

    // And a tampered one must not, or the mechanism proves nothing.
    let mut tampered = report;
    tampered.messages[0].plaintext = b"something alice never said".to_vec();
    let verdict = bob.client.report(&tampered).unwrap();
    assert!(!verdict.verified, "a tampered transcript must be rejected");
}

#[test]
fn a_non_member_cannot_read_a_room_over_http() {
    // The room-access vulnerability this project shipped once, checked at the layer it
    // was actually exploitable from.
    let server = start();
    let alice = Peer::new(&server, scratch("member"), b"alice");
    let mallory = Peer::new(&server, scratch("outsider"), b"mallory");

    alice.client.claim_account(None).unwrap();
    mallory.client.claim_account(None).unwrap();

    let room = alice.client.create_room(dm_shape()).unwrap().room;

    let err = mallory
        .client
        .fetch_since(room, 0)
        .expect_err("a non-member must not read a room it merely knows the id of");
    assert!(format!("{err}").contains("not a member"), "unexpected error: {err}");
}

#[test]
fn an_account_with_no_key_packages_reports_that_clearly() {
    // The caller who tried to add them needs to know why, since the failure belongs to
    // the account that ran out, not to them.
    let server = start();
    let alice = Peer::new(&server, scratch("adder"), b"alice");
    let bob = Peer::new(&server, scratch("empty"), b"bob");

    alice.client.claim_account(None).unwrap();
    bob.client.claim_account(None).unwrap();

    let err = alice.client.claim_key_packages(bob.user).expect_err("bob published none");
    assert!(
        matches!(err, cairn_client_core::ClientError::NoKeyPackages(_)),
        "unexpected error: {err}"
    );
}
