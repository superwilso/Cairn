//! Custom emoji, stickers and soundboard clips, through a real instance and the session layer
//! the desktop client delegates to.
//!
//! The rules — names, sizes, types, clip length — are unit-tested in
//! `cairn_client_core::custom`. What is tested here is the property the design exists for
//! (`docs/13-customisation.md` §3): the instance never sees a name or an image, a set is
//! downloaded whole when it changes, and **drawing a custom emoji makes no request at all** —
//! plus the attack the instance cannot stop for us, a plain member trying to change the set.

use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use cairn_client_core::custom::{CustomError, Kind};
use cairn_client_core::session::{CustomSetView, Event, Session, SessionError};
use cairn_proto::{RoomId, UserId};
use cairn_server::state::{Instance, RegistrationPolicy, RoomRole};

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
    let dir = std::env::temp_dir().join(format!("cairn-custom-{name}-{}", uuid::Uuid::new_v4()));
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

fn names(set: &CustomSetView, kind: Kind) -> Vec<String> {
    let mut n: Vec<String> =
        set.items.iter().filter(|i| i.kind == kind).map(|i| i.name.clone()).collect();
    n.sort();
    n
}

fn id_of(set: &CustomSetView, kind: Kind, name: &str) -> String {
    set.items.iter().find(|i| i.kind == kind && i.name == name).unwrap().id.clone()
}

/// A 1×1 PNG, with a marker in a private chunk so each test image is distinguishable.
fn png(marker: &[u8]) -> Vec<u8> {
    let mut b = vec![
        0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44,
        0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1F,
        0x15, 0xC4, 0x89,
    ];
    b.extend_from_slice(&(marker.len() as u32).to_be_bytes());
    b.extend_from_slice(b"teXt");
    b.extend_from_slice(marker);
    b.extend_from_slice(&[0, 0, 0, 0]);
    b
}

/// One second of 8 kHz, 8-bit silence.
fn wav() -> Vec<u8> {
    let rate = 8_000u32;
    let mut b = Vec::new();
    b.extend_from_slice(b"RIFF");
    b.extend_from_slice(&(36 + rate).to_le_bytes());
    b.extend_from_slice(b"WAVEfmt ");
    b.extend_from_slice(&16u32.to_le_bytes());
    b.extend_from_slice(&1u16.to_le_bytes());
    b.extend_from_slice(&1u16.to_le_bytes());
    b.extend_from_slice(&rate.to_le_bytes());
    b.extend_from_slice(&rate.to_le_bytes());
    b.extend_from_slice(&1u16.to_le_bytes());
    b.extend_from_slice(&8u16.to_le_bytes());
    b.extend_from_slice(b"data");
    b.extend_from_slice(&rate.to_le_bytes());
    b.resize(b.len() + rate as usize, 128);
    b
}

/// Alice owns a room bob is in, and has given it an emoji, a sticker and a sound.
fn furnished(server: &Server, bob_url: Option<&str>) -> (Session, Session, String) {
    let mut alice = session_in(server, "alice");
    let mut bob = match bob_url {
        Some(url) => session_at(url, "bob", &scratch("bob")),
        None => session_in(server, "bob"),
    };
    let room = alice.create_group(10).unwrap();
    add(&mut alice, &mut bob, &room);
    drain(&mut alice);
    alice.add_custom(Kind::Emoji, "Party Parrot.png", &png(b"parrot")).unwrap();
    alice.add_custom(Kind::Sticker, "wave", &png(b"wave sticker")).unwrap();
    alice.add_custom(Kind::Sound, "airhorn", &wav()).unwrap();
    (alice, bob, room)
}

#[test]
fn a_rooms_set_reaches_every_member_and_is_downloaded_whole() {
    let server = start();
    let (alice, mut bob, _room) = furnished(&server, None);
    let told = drain(&mut bob).into_iter().any(|e| matches!(e, Event::Custom { .. }));
    assert!(told, "bob must be told the set changed");

    let set = bob.custom_set().unwrap();
    assert_eq!(names(&set, Kind::Emoji), ["party_parrot"], "the name was sanitised");
    assert_eq!(names(&set, Kind::Sticker), ["wave"]);
    assert_eq!(names(&set, Kind::Sound), ["airhorn"]);
    assert_eq!(set.author.as_deref(), Some(alice.user_id().as_str()));
    assert!(!set.can_edit, "bob is a plain member");
    assert!(set.items.iter().all(|i| !i.ready), "nothing is fetched until the sync step");

    // Every asset, used or not: a lazily fetched new emoji is the leak §3 describes.
    assert_eq!(bob.sync_custom().unwrap(), 3);
    let set = bob.custom_set().unwrap();
    assert!(set.items.iter().all(|i| i.ready));
    let parrot = bob.custom_asset(&id_of(&set, Kind::Emoji, "party_parrot")).unwrap();
    assert_eq!(parrot, png(b"parrot"), "the bytes that come out are the bytes that went in");
    assert_eq!(bob.custom_asset(&id_of(&set, Kind::Sound, "airhorn")).unwrap(), wav());
    assert_eq!(set.items.iter().find(|i| i.kind == Kind::Sound).unwrap().mime, "audio/wav");
    assert_eq!(bob.sync_custom().unwrap(), 0, "a second sync fetches nothing");
}

#[test]
fn the_instance_stores_no_emoji_name_or_image_in_plaintext() {
    let server = start();
    let (alice, mut bob, room) = furnished(&server, None);
    drain(&mut bob);
    bob.sync_custom().unwrap();
    bob.send("look :party_parrot:").unwrap();

    let actor: UserId = alice.user_id().parse().unwrap();
    let room: RoomId = room.parse().unwrap();
    let stored = server.instance.messages_since(room, actor, 0, i64::MAX / 2).unwrap();
    let wire =
        serde_json::to_string(&stored.iter().map(|m| &m.envelope).collect::<Vec<_>>()).unwrap();
    for needle in ["party_parrot", "airhorn", "wave", "image/png", "audio/wav", "custom_set"] {
        assert!(!wire.contains(needle), "the instance must not see {needle:?}");
        assert!(!wire.contains(&hex::encode(needle)), "nor {needle:?} in hex");
    }
    for item in alice.custom_set().unwrap().items {
        let blob = server.instance.fetch_blob(actor, item.id.parse().unwrap()).unwrap();
        assert!(!blob.windows(4).any(|w| w == b"\x89PNG"), "no PNG signature in a stored blob");
        assert!(!blob.windows(4).any(|w| w == b"RIFF"), "no WAV header in a stored blob");
        assert!(!blob.windows(6).any(|w| w == b"parrot"));
    }
}

#[test]
fn drawing_a_custom_emoji_makes_no_request() {
    // Bob talks to the instance through a proxy that counts requests. Once his set is
    // synced, everything a frontend does to draw a message containing `:party_parrot:` —
    // read the set, read the image, read it again — must leave the count where it was.
    let server = start();
    let (count, proxy) = counting_proxy(server.addr);
    let (mut alice, mut bob, _room) = furnished(&server, Some(&format!("http://{proxy}")));
    drain(&mut bob);
    bob.sync_custom().unwrap();

    alice.send("so festive :party_parrot:").unwrap();
    let heard = drain(&mut bob)
        .into_iter()
        .find_map(|e| match e {
            Event::Message(m) if m.body.contains(":party_parrot:") => Some(m),
            _ => None,
        })
        .unwrap();
    // A reaction naming it arrives the same way: in the poll every open room makes anyway.
    alice.react(&alice.user_id(), heard.id.as_deref().unwrap(), Some(":party_parrot:")).unwrap();
    let reacted = drain(&mut bob).into_iter().any(|e| match e {
        Event::Reactions { reactions, .. } => reactions.iter().any(|r| r.emoji == ":party_parrot:"),
        _ => false,
    });
    assert!(reacted);

    let before = count.load(Ordering::SeqCst);
    assert!(before > 0, "the proxy is in the path");
    for _ in 0..5 {
        let set = bob.custom_set().unwrap();
        for item in &set.items {
            bob.custom_asset(&item.id).unwrap();
        }
    }
    assert_eq!(count.load(Ordering::SeqCst), before, "rendering must not touch the network");
}

#[test]
fn a_plain_members_set_is_ignored_by_everyone_else() {
    // The instance cannot read a set, so it cannot refuse one: every recipient must. Mallory
    // is a plain member whose client has been told — by a lying proxy, the shape of a
    // modified client or a colluding instance — that she is the owner, so it lets her build
    // and send a set. Bob asks the real instance, and ignores it.
    let server = start();
    let (mut alice, mut bob, room) = furnished(&server, None);
    let proxy = promoting_proxy(server.addr);
    let mut mallory = session_at(&format!("http://{proxy}"), "mallory", &scratch("mallory"));
    add(&mut alice, &mut mallory, &room);
    drain(&mut alice);
    drain(&mut bob);
    drain(&mut mallory);
    mallory.members().unwrap();
    assert!(mallory.custom_set().unwrap().can_edit, "the probe: her client believes it may");

    mallory.add_custom(Kind::Emoji, "gotcha", &png(b"gotcha")).unwrap();
    mallory.remove_custom(Kind::Emoji, "party_parrot").unwrap();
    let events = drain(&mut bob);
    bob.members().unwrap();
    drain(&mut bob);
    assert!(!events.iter().any(|e| matches!(e, Event::Custom { .. })), "{events:?}");
    let set = bob.custom_set().unwrap();
    assert_eq!(names(&set, Kind::Emoji), ["party_parrot"], "mallory's set must not apply");
    assert_eq!(set.author.as_deref(), Some(alice.user_id().as_str()));

    // Promoting her later does not bring the ignored set into force: it was dropped, not
    // parked. Her next one, sent as a moderator, is accepted.
    let owner: UserId = alice.user_id().parse().unwrap();
    let target: UserId = mallory.user_id().parse().unwrap();
    let rid: RoomId = room.parse().unwrap();
    server.instance.set_room_role(rid, owner, target, RoomRole::Moderator).unwrap();
    drain(&mut bob);
    assert_eq!(names(&bob.custom_set().unwrap(), Kind::Emoji), ["party_parrot"]);
    mallory.add_custom(Kind::Emoji, "legit", &png(b"legit")).unwrap();
    drain(&mut bob);
    let set = bob.custom_set().unwrap();
    assert_eq!(set.author.as_deref(), Some(mallory.user_id().as_str()));
    assert!(names(&set, Kind::Emoji).contains(&"legit".to_string()));
}

#[test]
fn a_member_cannot_change_the_set_and_is_told_so() {
    let server = start();
    let (_alice, mut bob, _room) = furnished(&server, None);
    drain(&mut bob);
    bob.members().unwrap();
    assert!(matches!(
        bob.add_custom(Kind::Emoji, "mine", &png(b"mine")),
        Err(SessionError::Custom(CustomError::NotPermitted))
    ));
    assert!(matches!(
        bob.remove_custom(Kind::Emoji, "party_parrot"),
        Err(SessionError::Custom(CustomError::NotPermitted))
    ));
}

#[test]
fn an_asset_that_breaks_the_rules_is_refused_before_upload() {
    let server = start();
    let mut alice = session_in(&server, "alice");
    alice.create_group(10).unwrap();
    alice.members().unwrap();
    for (kind, name, bytes) in [
        (Kind::Emoji, "svg", b"<svg onload=alert(1)>".to_vec()),
        (Kind::Emoji, "big", {
            let mut b = png(b"x");
            b.resize(cairn_client_core::custom::MAX_EMOJI_BYTES + 1, 0);
            b
        }),
        (Kind::Sound, "image", png(b"x")),
        (Kind::Emoji, "!!", png(b"x")),
    ] {
        assert!(alice.add_custom(kind, name, &bytes).is_err(), "{name} must be refused");
    }
    alice.add_custom(Kind::Emoji, "ok", &png(b"ok")).unwrap();
    assert!(matches!(
        alice.add_custom(Kind::Emoji, "ok", &png(b"ok2")),
        Err(SessionError::Custom(CustomError::Taken(_)))
    ));
}

#[test]
fn someone_who_joins_later_receives_the_set() {
    let server = start();
    let (mut alice, mut bob, room) = furnished(&server, None);
    drain(&mut bob);
    let mut carol = session_in(&server, "carol");
    add(&mut alice, &mut carol, &room);
    drain(&mut alice);
    drain(&mut bob);
    drain(&mut carol);
    let set = carol.custom_set().unwrap();
    assert_eq!(names(&set, Kind::Emoji), ["party_parrot"]);
    assert_eq!(carol.sync_custom().unwrap(), 3, "the blobs uploaded before she joined open for her");
}

#[test]
fn a_sticker_is_sent_by_name_and_drawn_from_the_cache() {
    let server = start();
    let (mut alice, mut bob, room) = furnished(&server, None);
    drain(&mut bob);
    bob.sync_custom().unwrap();
    let sent = alice.send_sticker("wave").unwrap();
    assert_eq!(sent.sticker.as_deref(), Some("wave"));
    let got = drain(&mut bob)
        .into_iter()
        .find_map(|e| match e {
            Event::Message(m) if m.sticker.is_some() => Some(m),
            _ => None,
        })
        .unwrap();
    assert_eq!(got.body, ":wave:");
    let set = bob.custom_set().unwrap();
    assert_eq!(bob.custom_asset(&id_of(&set, Kind::Sticker, "wave")).unwrap(), png(b"wave sticker"));
    assert!(alice.send_sticker("nope").is_err(), "only a sticker in the room's set");

    // It survives a reopen as a sticker, not as text.
    let history = bob.open_room(&room).unwrap();
    assert!(history.iter().any(|m| m.sticker.as_deref() == Some("wave")));
}

#[test]
fn a_set_survives_a_restart_and_needs_no_new_download() {
    let server = start();
    let url = format!("http://{}", server.addr);
    let dir = scratch("bob");
    let mut alice = session_in(&server, "alice");
    let mut bob = session_at(&url, "bob", &dir);
    let room = alice.create_group(10).unwrap();
    add(&mut alice, &mut bob, &room);
    drain(&mut alice);
    alice.add_custom(Kind::Emoji, "kept", &png(b"kept")).unwrap();
    drain(&mut bob);
    bob.sync_custom().unwrap();
    drop(bob);
    let mut bob = session_at(&url, "bob", &dir);
    bob.open_room(&room).unwrap();
    let set = bob.custom_set().unwrap();
    assert!(set.items.iter().all(|i| i.ready));
    assert_eq!(bob.sync_custom().unwrap(), 0);
}

// ---- proxies ---------------------------------------------------------------

/// Forward HTTP to `upstream`, counting every request.
fn counting_proxy(upstream: SocketAddr) -> (Arc<AtomicUsize>, SocketAddr) {
    let count = Arc::new(AtomicUsize::new(0));
    let c = count.clone();
    let addr = proxy(upstream, move |_head: &str, body: Vec<u8>| {
        c.fetch_add(1, Ordering::SeqCst);
        body
    });
    (count, addr)
}

/// Forward HTTP to `upstream`, telling the client every member of every room is its owner.
fn promoting_proxy(upstream: SocketAddr) -> SocketAddr {
    proxy(upstream, |head: &str, body: Vec<u8>| {
        if head.lines().next().is_some_and(|l| l.contains("/members")) {
            String::from_utf8_lossy(&body)
                .replace("\"role\":\"member\"", "\"role\":\"owner\"")
                .into_bytes()
        } else {
            body
        }
    })
}

fn proxy(
    upstream: SocketAddr,
    rewrite: impl Fn(&str, Vec<u8>) -> Vec<u8> + Send + Sync + 'static,
) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let rewrite = Arc::new(rewrite);
    std::thread::spawn(move || {
        for client in listener.incoming().flatten() {
            let rewrite = rewrite.clone();
            std::thread::spawn(move || {
                let _ = relay(client, upstream, &*rewrite);
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

fn relay(
    mut client: TcpStream,
    upstream: SocketAddr,
    rewrite: &(dyn Fn(&str, Vec<u8>) -> Vec<u8> + Send + Sync),
) -> std::io::Result<()> {
    loop {
        let (head, body) = read_head(&mut client)?;
        if head.is_empty() {
            return Ok(());
        }
        let text = String::from_utf8_lossy(&head).to_string();
        let mut up = TcpStream::connect(upstream)?;
        up.write_all(&head)?;
        up.write_all(&body)?;
        let (rhead, rbody) = read_head(&mut up)?;
        let rbody = rewrite(&text, rbody);
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
