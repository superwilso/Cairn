//! A signed envelope is accepted once.
//!
//! Found by a probe: a member fetched someone else's message and posted the same envelope
//! back, and the instance stored it again — under the original sender's name, at a later
//! sequence number, with a fresh franking tag chained after whatever came just before it.
//! The signature covers who, where and what, but not *when in the room*, so nothing stopped
//! it. In a public room that is putting words in someone's mouth; in any room it lets a
//! reporter assemble a transcript that verifies, in which the victim's old message answers
//! a question they never saw.

use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;

use cairn_client_core::client::{Client, ClientError};
use cairn_client_core::transport::{HttpTransport, TransportError};
use cairn_client_core::Conversation;
use cairn_crypto::mls::Session;
use cairn_proto::{DeviceId, DeviceIdentity, RoomSeal, RoomShape, UserId};
use cairn_server::state::{Instance, RegistrationPolicy};

fn start() -> SocketAddr {
    let instance = Arc::new(Instance::in_memory());
    instance.set_registration_policy(RegistrationPolicy::Open).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();
    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
    let router = cairn_server::http::router(instance);
    runtime.spawn(async move {
        let listener = tokio::net::TcpListener::from_std(listener).unwrap();
        axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>())
            .await
            .unwrap();
    });
    // The runtime must outlive the clients; the test process ends first.
    std::mem::forget(runtime);
    addr
}

struct Peer {
    session: Arc<Session>,
    client: Client<HttpTransport>,
    user: UserId,
    device: DeviceId,
}

fn peer(addr: SocketAddr, name: &str) -> Peer {
    let dir = std::env::temp_dir().join(format!("cairn-replay-{name}-{}", uuid::Uuid::new_v4()));
    let (user, device) = (UserId::new(), DeviceId::new());
    let session =
        Arc::new(Session::open(&dir, &DeviceIdentity::new(user, device).to_credential()).unwrap());
    let client =
        Client::new(HttpTransport::new(format!("http://{addr}")), session.clone(), user, device);
    client.claim_account(None).unwrap();
    Peer { session, client, user, device }
}

fn public_shape() -> RoomShape {
    RoomShape { is_direct: false, is_publicly_discoverable: true, member_ceiling: 5000 }
}

/// Alice owns a public room Bob is in, and has said one thing in it.
fn room_with_one_message() -> (Peer, Peer, cairn_proto::RoomId, cairn_proto::Envelope) {
    let addr = start();
    let alice = peer(addr, "alice");
    let bob = peer(addr, "bob");
    let room = alice.client.create_room(public_shape()).unwrap().room;
    let token = alice.client.create_room_invite(room, 1, None).unwrap();
    bob.client.redeem_room_invite(&token).unwrap();
    let mut convo = Conversation::create_public(
        RoomSeal::new(public_shape()).unwrap(),
        room,
        alice.user,
        alice.device,
        alice.session.clone(),
    )
    .unwrap();
    let said = convo.send_plaintext("yes, I agree", 1).unwrap();
    alice.client.send(room, &said).unwrap();
    (alice, bob, room, said)
}

#[test]
fn a_member_cannot_post_someone_elses_message_again() {
    let (_alice, bob, room, _said) = room_with_one_message();

    let theirs = bob.client.fetch_since(room, 0).unwrap().remove(0).envelope;
    // Byte-identical to what Alice sent, so it is answered as her own retry would be: with
    // the original receipt, and nothing new in the room — no second copy, no new position,
    // no fresh franking tag to build a transcript from.
    let replay = bob.client.send(room, &theirs).unwrap();
    assert_eq!(replay.server_seq, 1, "the original position, not a new one");
    assert_eq!(bob.client.fetch_since(room, 0).unwrap().len(), 1, "alice said it once");
}

#[test]
fn a_sender_retrying_a_lost_answer_gets_the_original_receipt() {
    let (alice, _bob, room, said) = room_with_one_message();

    // The first send's answer is what a lost connection would have taken away.
    let again = alice.client.send(room, &said).unwrap();
    assert_eq!(again.server_seq, 1, "the retry is the same message, not a second one");
    assert_eq!(alice.client.fetch_since(room, 0).unwrap().len(), 1);
}

#[test]
fn an_envelope_id_cannot_be_reused_for_different_content() {
    let (alice, _bob, room, said) = room_with_one_message();

    // Alice's own device, same id, different words: still not a second message under an id
    // the room already holds.
    let mut convo = Conversation::create_public(
        RoomSeal::new(public_shape()).unwrap(),
        room,
        alice.user,
        alice.device,
        alice.session.clone(),
    )
    .unwrap();
    let mut other = convo.send_plaintext("no, I do not", 2).unwrap();
    other.id = said.id;
    let signature = hex::encode(alice.session.sign(&other.signing_bytes()).unwrap());
    let other = other.with_signature(signature);
    let reused = alice.client.send(room, &other);
    assert!(
        matches!(reused, Err(ClientError::Transport(TransportError::Status { status: 409, .. }))),
        "got {reused:?}"
    );
}
