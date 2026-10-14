//! Profiles, through a real instance and the session layer the desktop client delegates to.
//!
//! The rules — lengths, forbidden characters, lookalike folding — are unit-tested in
//! `cairn_client_core::profile`. What is tested here is the trip: that a profile reaches the
//! other members and labels what they see, that its images arrive as encrypted attachments
//! the instance cannot open, that someone who joins later still learns who everyone is — and
//! the attacks: an instance relabelling one member's profile as another's, and a member
//! choosing somebody else's name.

use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use cairn_client_core::session::{
    Event, ImageSlot, ProfileEdit, ProfileView, Session, SessionError,
};
use cairn_proto::{RoomId, UserId};
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
    let router = cairn_server::http::router(instance.clone());
    runtime.spawn(async move {
        let listener = tokio::net::TcpListener::from_std(listener).unwrap();
        axum::serve(listener, router.into_make_service_with_connect_info::<std::net::SocketAddr>())
            .await
            .unwrap();
    });
    Server { addr, instance, _runtime: runtime }
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("cairn-profile-{name}-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn session_at(url: &str, name: &str, dir: &Path) -> Session {
    let mut s = Session::open(name, url, Some(dir)).unwrap();
    s.set_timer_recheck_ms(0);
    s
}

fn session_in(server: &Server, name: &str) -> Session {
    session_at(&format!("http://{}", server.addr), name, &scratch(name))
}

/// Alice and bob in one encrypted group, bob having fetched his welcome.
fn two_in_a_group(server: &Server) -> (Session, Session, String) {
    let mut alice = session_in(server, "alice");
    let mut bob = session_in(server, "bob");
    let room = alice.create_group(10).unwrap();
    add(&mut alice, &mut bob, &room);
    (alice, bob, room)
}

/// `admin` admits `joiner` to `room`, and the joiner fetches the welcome.
fn add(admin: &mut Session, joiner: &mut Session, room: &str) {
    joiner.publish_key_packages(3).unwrap();
    let token = admin.create_invite(1, 24).unwrap();
    joiner.redeem_invite(&token).unwrap();
    admin.admit_waiting().unwrap();
    joiner.open_room(room).unwrap();
    joiner.poll().unwrap();
}

fn drain(session: &mut Session) -> Vec<Event> {
    let mut all = Vec::new();
    for _ in 0..6 {
        all.extend(session.poll().unwrap());
    }
    all
}

fn edit(name: &str) -> ProfileEdit {
    ProfileEdit { display_name: Some(name.into()), ..ProfileEdit::default() }
}

/// `who`'s profile as `viewer` currently holds it in the open room.
fn seen(viewer: &Session, who: &str) -> ProfileView {
    viewer
        .profiles()
        .unwrap()
        .into_iter()
        .find(|p| p.user == who)
        .unwrap_or_else(|| panic!("no profile for {who}"))
}

/// The smallest valid PNG: one transparent pixel.
const PNG: &[u8] = &[
    0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1F, 0x15, 0xC4,
    0x89, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9C, 0x63, 0x00, 0x01, 0x00, 0x00,
    0x05, 0x00, 0x01, 0x0D, 0x0A, 0x2D, 0xB4, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE,
    0x42, 0x60, 0x82,
];

#[test]
fn a_profile_reaches_the_other_member_and_names_their_messages() {
    let server = start();
    let (mut alice, mut bob, _room) = two_in_a_group(&server);

    let mine = alice
        .set_profile(ProfileEdit {
            display_name: Some("Alice Liddell".into()),
            pronouns: Some("she/her".into()),
            about: Some("  Curiouser and curiouser.\nAlso: tea.  ".into()),
            colors: Some(["#5865f2".into(), "#eb459e".into()]),
            status_emoji: Some("🫖".into()),
            status_text: Some("at a tea party".into()),
            status_expires_at_ms: None,
        })
        .unwrap();
    assert_eq!(mine.label, "Alice Liddell");
    assert_eq!(mine.about.as_deref(), Some("Curiouser and curiouser.\nAlso: tea."), "trimmed");

    let told = drain(&mut bob).into_iter().any(|e| matches!(e, Event::Profiles { .. }));
    assert!(told, "bob must be told, not left to reopen the room");
    let got = seen(&bob, &alice.user_id());
    assert_eq!(got.label, "Alice Liddell");
    assert_eq!(got.pronouns.as_deref(), Some("she/her"));
    assert_eq!(got.colors, Some(["#5865f2".to_string(), "#eb459e".to_string()]));
    assert_eq!(got.status.as_ref().unwrap().emoji.as_deref(), Some("🫖"));
    assert!(!got.ambiguous);
    assert!(!got.is_me);

    alice.send("hello").unwrap();
    let heard = drain(&mut bob)
        .into_iter()
        .find_map(|e| match e {
            Event::Message(m) if m.body == "hello" => Some(m),
            _ => None,
        })
        .unwrap();
    assert_eq!(heard.sender, alice.user_id(), "the id is still who sent it");
    assert_eq!(heard.sender_label, "Alice Liddell");

    // And the member list carries it, beside the id rather than instead of it.
    let members = bob.members().unwrap();
    let a = members.iter().find(|m| m.user == alice.user_id()).unwrap();
    assert_eq!(a.profile.as_ref().unwrap().label, "Alice Liddell");
}

#[test]
fn a_profile_survives_a_restart_and_is_not_a_message() {
    let server = start();
    let url = format!("http://{}", server.addr);
    let alice_dir = scratch("alice");
    let bob_dir = scratch("bob");
    let mut alice = session_at(&url, "alice", &alice_dir);
    let mut bob = session_at(&url, "bob", &bob_dir);
    let room = alice.create_group(10).unwrap();
    add(&mut alice, &mut bob, &room);

    alice.set_profile(edit("Alice")).unwrap();
    drain(&mut bob);
    drop(bob);

    let mut bob = session_at(&url, "bob", &bob_dir);
    let history = bob.open_room(&room).unwrap();
    assert!(history.is_empty(), "a profile must not appear in the transcript: {history:?}");
    assert_eq!(seen(&bob, &alice.user_id()).label, "Alice");
}

#[test]
fn an_avatar_is_an_encrypted_attachment_the_instance_cannot_read() {
    let server = start();
    let (mut alice, mut bob, room) = two_in_a_group(&server);
    alice.set_profile(edit("Alice Liddell")).unwrap();
    alice.set_profile_image(ImageSlot::Avatar, Some((PNG, "image/png"))).unwrap();
    drain(&mut bob);

    let got = seen(&bob, &alice.user_id());
    let avatar = got.avatar.expect("bob must know alice has an avatar");
    assert_eq!(avatar.mime, "image/png");
    let bytes = bob.fetch_profile_image(&alice.user_id(), ImageSlot::Avatar).unwrap();
    assert_eq!(bytes, PNG, "the bytes that come out are the bytes that went in");

    // Now look at what the instance holds. The blob is ciphertext; the profile record is in
    // no message the instance can read.
    let actor: UserId = alice.user_id().parse().unwrap();
    let blob = server.instance.fetch_blob(actor, avatar.id.parse().unwrap()).unwrap();
    assert_ne!(blob, PNG);
    assert!(
        !blob.windows(8).any(|w| w == &PNG[..8]),
        "no PNG signature in what the instance stores"
    );

    let room: RoomId = room.parse().unwrap();
    let stored = server.instance.messages_since(room, actor, 0, i64::MAX / 2).unwrap();
    let wire =
        serde_json::to_string(&stored.iter().map(|m| &m.envelope).collect::<Vec<_>>()).unwrap();
    for needle in ["Alice Liddell", "image/png", &hex::encode("Alice Liddell")] {
        assert!(!wire.contains(needle), "the instance must not see {needle:?}");
    }
}

#[test]
fn someone_who_joins_later_learns_everyones_profile() {
    // A joiner cannot read anything sent before the welcome, so a profile sent once at
    // change time would leave every later member looking at bare ids.
    let server = start();
    let (mut alice, mut bob, room) = two_in_a_group(&server);
    alice.set_profile(edit("Alice")).unwrap();
    bob.set_profile(edit("Bob")).unwrap();
    alice.set_profile_image(ImageSlot::Avatar, Some((PNG, "image/png"))).unwrap();
    drain(&mut alice);
    drain(&mut bob);

    let mut carol = session_in(&server, "carol");
    add(&mut alice, &mut carol, &room);
    // Alice re-sends after admitting; bob after seeing the commit.
    drain(&mut alice);
    drain(&mut bob);
    drain(&mut carol);

    assert_eq!(seen(&carol, &alice.user_id()).label, "Alice");
    assert_eq!(seen(&carol, &bob.user_id()).label, "Bob");
    // The avatar was uploaded once, before carol joined, and she can still open it: the
    // room's blob store serves members, and the key came in the re-sent record.
    assert_eq!(carol.fetch_profile_image(&alice.user_id(), ImageSlot::Avatar).unwrap(), PNG);
}

#[test]
fn a_nickname_is_only_sent_to_its_own_room() {
    let server = start();
    let (mut alice, mut bob, first) = two_in_a_group(&server);
    alice.set_profile(edit("Alice")).unwrap();
    alice.set_nickname(Some("Al")).unwrap();
    drain(&mut bob);
    assert_eq!(seen(&bob, &alice.user_id()).label, "Al");

    let second = alice.create_group(10).unwrap();
    add(&mut alice, &mut bob, &second);
    drain(&mut alice);
    drain(&mut bob);
    let other = seen(&bob, &alice.user_id());
    assert_eq!(other.label, "Alice", "a nickname in one room is not the name in another");
    assert_eq!(other.nickname, None);
    bob.open_room(&first).unwrap();
    assert_eq!(seen(&bob, &alice.user_id()).label, "Al");
}

#[test]
fn a_name_that_breaks_the_rules_is_refused_before_it_is_sent() {
    let server = start();
    let (mut alice, _bob, _room) = two_in_a_group(&server);
    for bad in ["\u{202E}ecilA", "Ali\u{200B}ce", "\u{0410}lice", &"x".repeat(40), "1a2b3c4d"] {
        assert!(
            matches!(alice.set_profile(edit(bad)), Err(SessionError::Profile(_))),
            "{bad:?} must be refused"
        );
    }
    assert!(matches!(
        alice.set_profile_image(ImageSlot::Avatar, Some((b"<svg/>", "image/svg+xml"))),
        Err(SessionError::Profile(_))
    ));
    let huge = vec![0u8; cairn_client_core::profile::MAX_PROFILE_IMAGE_BYTES + 1];
    assert!(matches!(
        alice.set_profile_image(ImageSlot::Avatar, Some((&huge, "image/png"))),
        Err(SessionError::Profile(_))
    ));
}

#[test]
fn a_member_who_takes_someone_elses_name_does_not_become_them() {
    // Mallory cannot publish a profile *for* alice — the record names nobody, and is filed
    // under whoever sent it. What she can do is call herself "Alice". She gets the name;
    // she does not get to be indistinguishable.
    let server = start();
    let (mut alice, mut bob, room) = two_in_a_group(&server);
    let mut mallory = session_in(&server, "mallory");
    add(&mut alice, &mut mallory, &room);
    drain(&mut alice);
    drain(&mut bob);
    drain(&mut mallory);

    alice.set_profile(edit("Alice")).unwrap();
    mallory.set_profile(edit("AIice")).unwrap(); // capital I for l
    drain(&mut bob);

    let real = seen(&bob, &alice.user_id());
    let fake = seen(&bob, &mallory.user_id());
    assert_eq!(real.label, "Alice");
    assert_eq!(fake.label, "AIice");
    assert!(real.ambiguous && fake.ambiguous, "both must show their ids: {real:?} {fake:?}");
    assert_ne!(real.tag, fake.tag);

    // Security UI is about keys, and keys have ids, not names.
    let numbers = bob.safety_numbers(&mallory.user_id()).unwrap();
    assert!(numbers.iter().all(|n| n.user == mallory.user_id()));
    let members = bob.members().unwrap();
    let m = members.iter().find(|m| m.user == mallory.user_id()).unwrap();
    assert!(m.profile.as_ref().unwrap().ambiguous);

    // Mallory's messages are still hers.
    mallory.send("it's me, alice").unwrap();
    let heard = drain(&mut bob)
        .into_iter()
        .find_map(|e| match e {
            Event::Message(m) if m.body == "it's me, alice" => Some(m),
            _ => None,
        })
        .unwrap();
    assert_eq!(heard.sender, mallory.user_id());
    assert!(heard.sender_ambiguous);
}

#[test]
fn an_instance_cannot_relabel_one_members_profile_as_anothers() {
    // The probe that found the gap: an instance that rewrites `sender` on the envelopes it
    // relays could make mallory's profile — her name, her avatar — alice's, and her words
    // alice's words, for every member who fetched through it. Bob reads through a proxy
    // that does exactly that.
    let server = start();
    let url = format!("http://{}", server.addr);
    let bob_dir = scratch("bob");
    let mut alice = session_in(&server, "alice");
    let mut bob = session_at(&url, "bob", &bob_dir);
    let mut mallory = session_in(&server, "mallory");
    let room = alice.create_group(10).unwrap();
    add(&mut alice, &mut bob, &room);
    add(&mut alice, &mut mallory, &room);
    drain(&mut alice);
    drain(&mut mallory);

    alice.set_profile(edit("Alice")).unwrap();
    drain(&mut bob);
    assert_eq!(seen(&bob, &alice.user_id()).label, "Alice");
    drop(bob);

    let proxy = hostile_proxy(server.addr, uuid_of(&mallory.user_id()), uuid_of(&alice.user_id()));
    mallory.set_profile(edit("Not Alice")).unwrap();
    mallory.send("mallory speaking").unwrap();

    // Same bob, same keys and state — now reading through the hostile instance.
    let mut bob = session_at(&format!("http://{proxy}"), "bob", &bob_dir);
    bob.open_room(&room).unwrap();
    let events = drain(&mut bob);
    assert_eq!(
        seen(&bob, &alice.user_id()).label,
        "Alice",
        "alice's profile must not have been replaced by mallory's"
    );
    let misattributed = events.iter().any(|e| {
        matches!(e, Event::Message(m) if m.body == "mallory speaking" && m.sender == alice.user_id())
    });
    assert!(!misattributed, "and mallory's words must not arrive under alice's id: {events:?}");
}

fn uuid_of(user: &str) -> String {
    user.parse::<UserId>().unwrap().as_uuid().to_string()
}

/// Forward HTTP to `upstream`, replacing `from` with `to` in every message fetch response —
/// an instance attributing one member's envelopes to another.
fn hostile_proxy(upstream: SocketAddr, from: String, to: String) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for client in listener.incoming().flatten() {
            let (from, to) = (from.clone(), to.clone());
            std::thread::spawn(move || {
                let _ = relay(client, upstream, &from, &to);
            });
        }
    });
    addr
}

fn read_head(stream: &mut TcpStream) -> std::io::Result<(Vec<u8>, Vec<u8>)> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    while !buf.ends_with(b"\r\n\r\n") {
        if stream.read(&mut byte)? == 0 {
            break;
        }
        buf.push(byte[0]);
    }
    let head = String::from_utf8_lossy(&buf).to_string();
    let len = head
        .lines()
        .find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.eq_ignore_ascii_case("content-length").then(|| v.trim().parse::<usize>().ok())?
        })
        .unwrap_or(0);
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body)?;
    Ok((buf, body))
}

fn relay(mut client: TcpStream, upstream: SocketAddr, from: &str, to: &str) -> std::io::Result<()> {
    loop {
        let (head, body) = read_head(&mut client)?;
        if head.is_empty() {
            return Ok(());
        }
        let text = String::from_utf8_lossy(&head).to_string();
        let is_fetch = text.lines().next().is_some_and(|l| l.contains("/messages?after="));
        let mut up = TcpStream::connect(upstream)?;
        up.write_all(&head)?;
        up.write_all(&body)?;
        let (rhead, rbody) = read_head(&mut up)?;
        let rbody = if is_fetch {
            String::from_utf8_lossy(&rbody).replace(from, to).into_bytes()
        } else {
            rbody
        };
        let rtext = String::from_utf8_lossy(&rhead).to_string();
        let mut out = String::new();
        for line in rtext.split("\r\n").filter(|l| !l.is_empty()) {
            if line.to_ascii_lowercase().starts_with("content-length:") {
                out.push_str(&format!("content-length: {}\r\n", rbody.len()));
            } else {
                out.push_str(line);
                out.push_str("\r\n");
            }
        }
        out.push_str("\r\n");
        client.write_all(out.as_bytes())?;
        client.write_all(&rbody)?;
    }
}
