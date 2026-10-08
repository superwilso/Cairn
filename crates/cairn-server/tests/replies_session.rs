//! Replies and reactions, through a real instance and the session layer the desktop client
//! delegates to.
//!
//! The folding rules are unit-tested in `cairn_client_core::thread`. What is tested here is
//! that they survive the trip: a reply sent on one device shows the right quote on another,
//! a reaction reaches every member and can be taken back, both survive a restart — and a
//! quote does not keep a disappearing message alive.

use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use cairn_client_core::session::{Event, MessageView, Session, SessionError};
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
    let dir = std::env::temp_dir().join(format!("cairn-reply-{name}-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn session_in(server: &Server, name: &str, dir: &Path) -> Session {
    let mut s = Session::open(name, &format!("http://{}", server.addr), Some(dir)).unwrap();
    s.set_timer_recheck_ms(0);
    s
}

/// Alice and bob in one encrypted group, bob having fetched his welcome.
fn two_in_a_group(server: &Server) -> (Session, Session, String) {
    let mut alice = session_in(server, "alice", &scratch("alice"));
    let mut bob = session_in(server, "bob", &scratch("bob"));
    bob.publish_key_packages(3).unwrap();
    let room = alice.create_group(10).unwrap();
    let token = alice.create_invite(1, 24).unwrap();
    bob.redeem_invite(&token).unwrap();
    alice.admit_waiting().unwrap();
    bob.open_room(&room).unwrap();
    bob.poll().unwrap();
    (alice, bob, room)
}

fn drain(session: &mut Session) -> Vec<Event> {
    let mut all = Vec::new();
    for _ in 0..6 {
        all.extend(session.poll().unwrap());
    }
    all
}

/// The first message `session` hears with this body.
fn hear(session: &mut Session, body: &str) -> MessageView {
    drain(session)
        .into_iter()
        .find_map(|e| match e {
            Event::Message(m) if m.body == body => Some(m),
            _ => None,
        })
        .unwrap_or_else(|| panic!("never heard {body:?}"))
}

#[test]
fn a_reply_arrives_quoting_the_message_it_answers() {
    let server = start();
    let (mut alice, mut bob, _room) = two_in_a_group(&server);

    let sent = alice.send("lunch at noon?").unwrap();
    let id = sent.id.clone().expect("a sent message must be answerable at once");
    let heard = hear(&mut bob, "lunch at noon?");
    assert_eq!(heard.id.as_deref(), Some(id.as_str()), "both sides must name it the same way");

    let reply = bob.reply("yes", &heard.sender, &id).unwrap();
    let quote = reply.reply_to.expect("the sender's own view shows the quote too");
    assert_eq!(quote.snippet.as_deref(), Some("lunch at noon?"));

    let got = hear(&mut alice, "yes");
    let quote = got.reply_to.expect("the recipient sees what it answers");
    assert_eq!(quote.sender, alice.user_id());
    assert_eq!(quote.snippet.as_deref(), Some("lunch at noon?"));
}

#[test]
fn a_reply_to_a_message_this_device_does_not_hold_is_refused() {
    // The UI names a message by (sender, id). Pairing a real id with the wrong sender is
    // the shape of a misattributed quote, and must not be sendable from here.
    let server = start();
    let (mut alice, mut bob, _room) = two_in_a_group(&server);
    let id = alice.send("mine").unwrap().id.unwrap();
    hear(&mut bob, "mine");

    let bob_id = bob.user_id();
    assert!(matches!(bob.reply("x", &bob_id, &id), Err(SessionError::UnknownMessage)));
    assert!(matches!(
        bob.reply("x", &alice.user_id(), &"0".repeat(64)),
        Err(SessionError::UnknownMessage)
    ));
}

#[test]
fn a_reaction_reaches_the_other_member_and_can_be_withdrawn() {
    let server = start();
    let (mut alice, mut bob, room) = two_in_a_group(&server);
    let id = alice.send("shipped it").unwrap().id.unwrap();
    hear(&mut bob, "shipped it");
    let me = alice.user_id();

    let mine = bob.react(&me, &id, Some("🎉")).unwrap();
    assert_eq!(mine.len(), 1);
    assert_eq!(mine[0].by, vec![bob.user_id()]);

    let seen = drain(&mut alice)
        .into_iter()
        .find_map(|e| match e {
            Event::Reactions { id: target, reactions, .. } if target == id => Some(reactions),
            _ => None,
        })
        .expect("alice must be told about the reaction, not left to reopen the room");
    assert_eq!(seen[0].emoji, "🎉");
    assert_eq!(seen[0].by, vec![bob.user_id()], "attributed to whoever sent it");

    // A reaction is not a message: it must not appear in the transcript as a blank line.
    let reopened = alice.open_room(&room).unwrap();
    assert_eq!(reopened.len(), 1, "{reopened:?}");
    assert_eq!(reopened[0].reactions[0].emoji, "🎉", "and it survives reopening the room");

    bob.react(&me, &id, None).unwrap();
    let cleared = drain(&mut alice).into_iter().any(|e| {
        matches!(e, Event::Reactions { id: ref target, ref reactions, .. }
            if *target == id && reactions.is_empty())
    });
    assert!(cleared, "withdrawing a reaction is a change members must see too");
}

#[test]
fn text_is_not_a_reaction() {
    let server = start();
    let (mut alice, mut bob, _room) = two_in_a_group(&server);
    let id = alice.send("hi").unwrap().id.unwrap();
    hear(&mut bob, "hi");
    let me = alice.user_id();
    for bad in ["lol", "", "👍 👍", "you are a fraud"] {
        assert!(
            matches!(bob.react(&me, &id, Some(bad)), Err(SessionError::BadReaction)),
            "{bad:?} must be refused"
        );
    }
}

#[test]
fn a_quote_does_not_outlive_the_message_it_quotes() {
    // If a reply carried a copy of the text it answered, that copy would expire on the
    // reply's clock rather than the original's — a disappearing message kept alive by
    // anyone who answered it. The quote is looked up instead, so it goes when the original
    // does.
    let server = start();
    let (mut alice, mut bob, room) = two_in_a_group(&server);
    alice.set_room_timer(Some(4_000)).unwrap();
    drain(&mut bob);

    let id = alice.send("this goes first").unwrap().id.unwrap();
    hear(&mut bob, "this goes first");
    std::thread::sleep(Duration::from_millis(2_000));
    bob.reply("and this later", &alice.user_id(), &id).unwrap();
    hear(&mut alice, "and this later");

    // Past the original's timer, well inside the reply's.
    std::thread::sleep(Duration::from_millis(2_300));
    let left = alice.open_room(&room).unwrap();
    let reply = left
        .iter()
        .find(|m| m.body == "and this later")
        .expect("the reply itself has not expired yet");
    assert!(left.iter().all(|m| m.body != "this goes first"), "the original has: {left:?}");
    let quote = reply.reply_to.as_ref().expect("it is still a reply");
    assert_eq!(quote.snippet, None, "and its quote must have gone with the original");
}
