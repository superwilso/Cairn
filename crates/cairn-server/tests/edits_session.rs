//! Edits and delete-for-everyone, through a real instance and the session layer the desktop
//! client delegates to — and against a member whose client is not honest.
//!
//! The folding rules are unit-tested in `cairn_client_core::thread` and the wire rules in
//! `cairn_client_core::conversation`. What is tested here is the whole trip: what a recipient
//! sees, what is left on its disk, what a timer does to an edit, and what happens when a real
//! member of the group hand-builds edits, deletes and replies an honest client would never
//! send. Each hostile case is named after the property it defends.

use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use cairn_client_core::client::Client;
use cairn_client_core::conversation::MessageRef;
use cairn_client_core::session::{Event, MessageView, Revised, Session, SessionError};
use cairn_client_core::transport::HttpTransport;
use cairn_client_core::Conversation;
use cairn_crypto::franking::{self, Opening};
use cairn_proto::{DeviceId, DeviceIdentity, Envelope, EnvelopePayload, RoomShape, UserId};
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
        axum::serve(listener, router.into_make_service_with_connect_info::<std::net::SocketAddr>())
            .await
            .unwrap();
    });
    Server { addr, _runtime: runtime }
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("cairn-edit-{name}-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn session_in(server: &Server, name: &str, dir: &Path) -> Session {
    let mut s = Session::open(name, &format!("http://{}", server.addr), Some(dir)).unwrap();
    s.set_timer_recheck_ms(0);
    s
}

/// Alice and bob in one encrypted group. Returns bob's state directory too, so a test can
/// look at what is actually on his disk.
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

fn drain(session: &mut Session) -> Vec<Event> {
    let mut all = Vec::new();
    for _ in 0..6 {
        all.extend(session.poll().unwrap());
    }
    all
}

fn hear(session: &mut Session, body: &str) -> MessageView {
    drain(session)
        .into_iter()
        .find_map(|e| match e {
            Event::Message(m) if m.body == body => Some(m),
            _ => None,
        })
        .unwrap_or_else(|| panic!("never heard {body:?}"))
}

fn updates(events: Vec<Event>) -> Vec<Revised> {
    events
        .into_iter()
        .filter_map(|e| match e {
            Event::Updated(r) => Some(r),
            _ => None,
        })
        .collect()
}

/// Everything in a state directory's transcripts, as raw bytes.
fn transcript_bytes(dir: &Path) -> Vec<u8> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir.join("history")).unwrap() {
        out.extend(std::fs::read(entry.unwrap().path()).unwrap());
    }
    out
}

/// How a transcript stores a body: a JSON array of byte values.
fn stored(text: &str) -> Vec<u8> {
    serde_json::to_vec(text.as_bytes()).unwrap()
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn an_edit_reaches_the_other_member_marked_and_with_its_history() {
    let server = start();
    let (mut alice, mut bob, room, _) = two_in_a_group(&server);
    let id = alice.send("meet at the station").unwrap().id.unwrap();
    hear(&mut bob, "meet at the station");
    // A reply written before the edit, so its quote has something to follow.
    bob.reply("on my way", &alice.user_id(), &id).unwrap();
    hear(&mut alice, "on my way");

    let mine = alice.edit(&id, "meet at the library").unwrap();
    assert_eq!(mine.message.body, "meet at the library");
    assert!(mine.message.edited_at_ms.is_some());

    let got = updates(drain(&mut bob));
    assert_eq!(got.len(), 1, "exactly one update for one edit");
    let seen = &got[0].message;
    assert_eq!(seen.id.as_deref(), Some(id.as_str()), "the same message, not a new one");
    assert_eq!(seen.sender, alice.user_id());
    assert_eq!(seen.body, "meet at the library");
    assert!(seen.edited_at_ms.is_some(), "an edited message must say it was edited");
    assert_eq!(seen.revisions.len(), 1);
    assert_eq!(seen.revisions[0].body, "meet at the station", "and what it said before");
    assert!(!seen.can_edit && !seen.can_delete, "bob may not change alice's message");
    assert_eq!(got[0].quote.snippet.as_deref(), Some("meet at the library"));
    assert!(got[0].quote.edited);

    // It survives reopening the room, and so does the quote of it.
    let reopened = bob.open_room(&room).unwrap();
    assert_eq!(reopened.len(), 2, "the edit is not a message of its own: {reopened:?}");
    assert_eq!(reopened[0].body, "meet at the library");
    assert_eq!(reopened[0].revisions[0].body, "meet at the station");
    let quote = reopened[1].reply_to.as_ref().unwrap();
    assert_eq!(quote.snippet.as_deref(), Some("meet at the library"));
}

#[test]
fn the_desktop_api_refuses_to_edit_or_delete_someone_elses_message() {
    let server = start();
    let (mut alice, mut bob, _room, _) = two_in_a_group(&server);
    let id = alice.send("mine").unwrap().id.unwrap();
    let heard = hear(&mut bob, "mine");
    assert!(!heard.can_edit && !heard.can_delete);
    assert!(matches!(bob.edit(&id, "now mine"), Err(SessionError::NotEditable)));
    assert!(matches!(bob.delete(&id), Err(SessionError::UnknownMessage)));
    assert!(matches!(alice.edit(&id, ""), Err(SessionError::EmptyEdit)));
}

#[test]
fn a_deleted_message_leaves_every_honest_disk_not_just_the_screen() {
    let server = start();
    let (mut alice, mut bob, room, bob_dir) = two_in_a_group(&server);
    let id = alice.send("the code is 4417").unwrap().id.unwrap();
    hear(&mut bob, "the code is 4417");
    bob.reply("got it", &alice.user_id(), &id).unwrap();
    assert!(contains(&transcript_bytes(&bob_dir), &stored("the code is 4417")));

    let mine = alice.delete(&id).unwrap();
    assert!(mine.message.deleted && mine.message.body.is_empty());

    let got = updates(drain(&mut bob));
    assert_eq!(got.len(), 1);
    assert!(got[0].message.deleted);
    assert!(got[0].message.body.is_empty());
    assert!(got[0].quote.deleted && got[0].quote.snippet.is_none());
    assert!(
        !contains(&transcript_bytes(&bob_dir), &stored("the code is 4417")),
        "the text must be gone from bob's transcript file, not hidden"
    );

    let reopened = bob.open_room(&room).unwrap();
    assert!(reopened[0].deleted, "a marker stays so the reply can say what it answered");
    assert!(reopened[1].reply_to.as_ref().unwrap().deleted);
    assert!(matches!(alice.edit(&id, "undeleted"), Err(SessionError::NotEditable)));
}

#[test]
fn an_edit_does_not_keep_a_disappearing_message_alive() {
    // An edit sent late in a message's life must go when the original does — on screen and
    // on disk — or editing would be a way to restart a disappearing message's timer.
    let server = start();
    let (mut alice, mut bob, room, bob_dir) = two_in_a_group(&server);
    alice.set_room_timer(Some(4_000)).unwrap();
    drain(&mut bob);

    let id = alice.send("first draft").unwrap().id.unwrap();
    hear(&mut bob, "first draft");
    std::thread::sleep(Duration::from_millis(2_000));
    alice.edit(&id, "second draft").unwrap();
    assert_eq!(updates(drain(&mut bob)).len(), 1);

    // Past the original's timer, well inside the edit's.
    std::thread::sleep(Duration::from_millis(2_300));
    let left = bob.open_room(&room).unwrap();
    assert!(left.is_empty(), "nothing of the message may remain: {left:?}");
    let disk = transcript_bytes(&bob_dir);
    assert!(!contains(&disk, &stored("first draft")));
    assert!(!contains(&disk, &stored("second draft")), "the edit expired with its original");
}

// ---- a member whose client is not honest -----------------------------------------------

/// Mallory: a real member of the group, with keys, whose client builds whatever it likes.
/// She creates the room and admits bob's honest `Session`.
struct Mallory {
    client: Client<HttpTransport>,
    mls: Arc<cairn_crypto::mls::Session>,
    convo: Conversation,
    user: UserId,
}

impl Mallory {
    fn send_raw(&mut self, inner: serde_json::Value, franked: &[u8], opening: &Opening) {
        let commitment = franking::commit_with_opening(franked, opening);
        let bytes = serde_json::to_vec(&inner).unwrap();
        let ciphertext =
            self.convo.group_mut().unwrap().encrypt(&bytes).unwrap().to_bytes().unwrap();
        let envelope = Envelope::new(
            self.convo.tier(),
            self.convo.room(),
            self.user,
            self.client.device(),
            now_ms(),
            EnvelopePayload::MlsApplication { ciphertext },
        )
        .unwrap()
        .with_franking_commitment(commitment.to_hex());
        let signature = self.mls.sign(&envelope.signing_bytes()).unwrap();
        let envelope = envelope.with_signature(hex::encode(signature));
        self.client.send(self.convo.room(), &envelope).unwrap();
    }

    /// Read everything new, so her group keeps up with what bob sends.
    fn catch_up(&mut self, after: &mut u64) -> Vec<(UserId, String, Vec<u8>)> {
        let mut heard = Vec::new();
        for m in self.client.fetch_since(self.convo.room(), *after).unwrap() {
            *after = (*after).max(m.server_seq);
            if let Ok(event) = self.convo.receive(&m.envelope) {
                if let Some(msg) = event.message() {
                    let id = msg.franking.as_ref().unwrap().commitment.to_hex();
                    heard.push((m.envelope.sender, id, msg.body));
                }
            }
        }
        heard
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64
}

fn mallory_and_bob(server: &Server) -> (Mallory, Session, String) {
    let (user, device) = (UserId::new(), DeviceId::new());
    let mls = Arc::new(
        cairn_crypto::mls::Session::open(
            scratch("mallory"),
            &DeviceIdentity::new(user, device).to_credential(),
        )
        .unwrap(),
    );
    let client = Client::new(
        HttpTransport::new(format!("http://{}", server.addr)),
        mls.clone(),
        user,
        device,
    );
    client.claim_account(None).unwrap();

    let mut bob = session_in(server, "bob", &scratch("bob"));
    bob.publish_key_packages(3).unwrap();
    let bob_user: UserId = bob.user_id().parse().unwrap();

    let shape = RoomShape { is_direct: false, is_publicly_discoverable: false, member_ceiling: 10 };
    let created = client.create_room(shape).unwrap();
    let room = created.room;
    client.add_room_member(room, bob_user).unwrap();
    let mut convo =
        Conversation::create_encrypted(created.seal, room, user, device, mls.clone()).unwrap();
    let claimed = client.claim_key_packages(bob_user).unwrap();
    let package =
        cairn_crypto::mls::parse_message(&hex::decode(&claimed[0].key_package).unwrap()).unwrap();
    let output = convo.group_mut().unwrap().add_member(package).unwrap();
    let commit = convo.wrap_handshake(&output.commit.to_bytes().unwrap(), now_ms()).unwrap();
    client.send(room, &commit).unwrap();
    let welcome =
        convo.wrap_handshake(&output.welcome.unwrap().to_bytes().unwrap(), now_ms()).unwrap();
    client.send(room, &welcome).unwrap();

    bob.open_room(&room.to_string()).unwrap();
    drain(&mut bob);
    (Mallory { client, mls, convo, user }, bob, room.to_string())
}

fn inner(body: &[u8], opening: &Opening) -> serde_json::Value {
    serde_json::json!({ "body": body, "opening": opening })
}

#[test]
fn a_member_cannot_edit_or_delete_someone_elses_message() {
    // Probe: mallory names bob's real message — its real id, bob as its sender — in an edit
    // and then a delete, signed with her own valid keys. Bob's own words must stand.
    let server = start();
    let (mut mallory, mut bob, room) = mallory_and_bob(&server);
    let mut cursor = 0;
    mallory.catch_up(&mut cursor);
    let id = bob.send("I will not pay").unwrap().id.unwrap();
    let heard = mallory.catch_up(&mut cursor);
    assert!(heard.iter().any(|(_, i, _)| *i == id), "mallory must hold the message to name it");

    let target = MessageRef { sender: bob.user_id().parse().unwrap(), id: id.clone() };
    let opening = Opening::generate();
    let commitment: [u8; 32] = hex::decode(&id).unwrap().try_into().unwrap();
    let frame = cairn_proto::franked::edit_bytes(target.sender, &commitment, b"I will pay");
    let mut edit = inner(b"I will pay", &opening);
    edit["edit"] = serde_json::to_value(&target).unwrap();
    mallory.send_raw(edit, &frame, &opening);

    let opening = Opening::generate();
    let mut delete = inner(b"", &opening);
    delete["delete"] = serde_json::to_value(&target).unwrap();
    mallory.send_raw(delete, b"", &opening);

    let events = drain(&mut bob);
    assert!(updates(events).is_empty(), "neither may change bob's message");
    let shown = bob.open_room(&room).unwrap();
    assert_eq!(shown.len(), 1, "{shown:?}");
    assert_eq!(shown[0].body, "I will not pay");
    assert!(shown[0].edited_at_ms.is_none() && !shown[0].deleted);
}

#[test]
fn a_delete_sent_ahead_of_its_message_arms_nothing() {
    // Probe: mallory knows her next message's commitment before sending it, because she
    // chooses its opening. She sends the delete first. If bob remembered it, a message could
    // sit on the instance that no honest member is ever shown.
    let server = start();
    let (mut mallory, mut bob, room) = mallory_and_bob(&server);
    let opening = Opening::generate();
    let text = b"arrives second";
    let commitment = franking::commit_with_opening(text, &opening);
    let target = MessageRef { sender: mallory.user, id: commitment.to_hex() };

    let delete_opening = Opening::generate();
    let mut delete = inner(b"", &delete_opening);
    delete["delete"] = serde_json::to_value(&target).unwrap();
    mallory.send_raw(delete, b"", &delete_opening);
    mallory.send_raw(inner(text, &opening), text, &opening);

    let events = drain(&mut bob);
    assert!(updates(events).is_empty());
    let shown = bob.open_room(&room).unwrap();
    assert_eq!(shown.len(), 1);
    assert_eq!(shown[0].body, "arrives second");
    assert!(!shown[0].deleted, "the early delete must not have been held and applied");
}

#[test]
fn a_reply_cannot_put_words_in_the_quote() {
    // Probe: mallory replies to bob and stuffs a quote of her own choosing into the body,
    // under every name a quote field might plausibly have. Bob's screen shows what *his*
    // transcript says he wrote.
    let server = start();
    let (mut mallory, mut bob, room) = mallory_and_bob(&server);
    let mut cursor = 0;
    mallory.catch_up(&mut cursor);
    let id = bob.send("no").unwrap().id.unwrap();
    mallory.catch_up(&mut cursor);

    let opening = Opening::generate();
    let mut reply = inner(b"thanks for agreeing", &opening);
    reply["reply_to"] =
        serde_json::json!({ "sender": bob.user_id().parse::<UserId>().unwrap(), "id": id });
    for field in ["quote", "snippet", "quoted", "quote_text"] {
        reply[field] = serde_json::json!("yes, I agree to everything");
    }
    mallory.send_raw(reply, b"thanks for agreeing", &opening);

    let got = hear(&mut bob, "thanks for agreeing");
    assert_eq!(got.reply_to.unwrap().snippet.as_deref(), Some("no"));
    let shown = bob.open_room(&room).unwrap();
    assert_eq!(shown[1].reply_to.as_ref().unwrap().snippet.as_deref(), Some("no"));
}

#[test]
fn an_edit_and_its_original_each_verify_when_reported_to_the_instance() {
    // Over the wire, with the instance's real franking key: the original and the edit each
    // verify as reports, and the edit's disclosed bytes name the original — so a moderator
    // reads "this replaced that", from the cryptography rather than from the reporter.
    let server = start();
    let (mut mallory, _bob, _room) = mallory_and_bob(&server);
    let original = mallory.convo.send(b"you are welcome here", now_ms()).unwrap();
    let first = mallory.client.send(mallory.convo.room(), &original.envelope).unwrap();
    let target = MessageRef { sender: mallory.user, id: original.commitment.to_hex() };
    let edit = mallory.convo.send_edit(target, b"you are not welcome here", now_ms()).unwrap();
    let second = mallory.client.send(mallory.convo.room(), &edit.envelope).unwrap();

    // The chain as the instance attested it: each franked message's predecessor.
    let all = mallory.client.fetch_since(mallory.convo.room(), 0).unwrap();
    let prev_of = |seq: u64| {
        all.iter()
            .filter(|m| m.server_seq < seq)
            .filter_map(|m| m.envelope.franking_commitment.as_deref())
            .next_back()
            .map(|h| {
                cairn_crypto::franking::Commitment(hex::decode(h).unwrap().try_into().unwrap())
            })
    };
    let report_of = |sent: &cairn_client_core::conversation::OutboundMessage,
                     receipt: &cairn_client_core::client::SendReceipt,
                     plaintext: Vec<u8>| cairn_crypto::TranscriptReport {
        messages: vec![cairn_crypto::ReportedMessage {
            plaintext,
            opening: sent.opening.clone(),
            context: cairn_crypto::FrankingContext {
                commitment: sent.commitment,
                room: sent.envelope.room,
                sender: sent.envelope.sender,
                sender_device: sent.envelope.sender_device,
                server_seq: receipt.server_seq,
                prev_commitment: prev_of(receipt.server_seq),
            },
            tag: cairn_crypto::Tag(
                hex::decode(receipt.franking_tag.as_ref().unwrap()).unwrap().try_into().unwrap(),
            ),
        }],
    };

    let verdict = mallory
        .client
        .report(&report_of(&original, &first, b"you are welcome here".to_vec()))
        .unwrap();
    assert!(verdict.verified, "the original stays reportable: {:?}", verdict.reason);

    let frame = cairn_proto::franked::edit_bytes(
        mallory.user,
        &original.commitment.0,
        b"you are not welcome here",
    );
    let verdict = mallory.client.report(&report_of(&edit, &second, frame.clone())).unwrap();
    assert!(verdict.verified, "the edit is reportable as an edit: {:?}", verdict.reason);
    match cairn_proto::franked::parse(&frame) {
        cairn_proto::franked::Franked::Edit { target_sender, target_commitment, .. } => {
            assert_eq!(target_sender, mallory.user);
            assert_eq!(target_commitment, original.commitment.0);
        }
        other => panic!("{other:?}"),
    }

    // Reported as though it were a standalone message, it does not verify.
    let verdict = mallory
        .client
        .report(&report_of(&edit, &second, b"you are not welcome here".to_vec()))
        .unwrap();
    assert!(!verdict.verified);
}
