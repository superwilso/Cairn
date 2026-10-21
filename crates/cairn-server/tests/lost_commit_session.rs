//! A membership commit lost on its way to the instance, or on its way back.
//!
//! Found by a probe that dropped one upload between the client and a real instance. The
//! client used to move to the commit's epoch before the instance had it, so a lost upload
//! left the owner alone in an epoch nobody else reached: the members could no longer read
//! them, and the person being admitted was never welcomed and no longer listed as waiting.
//! Both directions are tested, because they need opposite outcomes — a commit that never
//! arrived must be forgotten, and one that arrived unacknowledged must be kept.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;

use cairn_client_core::session::{Event, Session};
use cairn_server::state::{Instance, RegistrationPolicy};

/// What the proxy does to the next message upload.
const PASS: u8 = 0;
/// The instance never sees it: the connection drops on the way there.
const LOSE_REQUEST: u8 = 1;
/// The instance stores it, and the answer is lost on the way back.
const LOSE_RESPONSE: u8 = 2;

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
        axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>())
            .await
            .unwrap();
    });
    Server { addr, _runtime: runtime }
}

/// A one-request-per-connection proxy in front of `upstream` that spoils the next message
/// upload as `mode` says, then goes back to passing everything.
fn proxy(upstream: SocketAddr, mode: Arc<AtomicU8>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(client) = conn else { continue };
            let mode = mode.clone();
            std::thread::spawn(move || relay(client, upstream, &mode));
        }
    });
    addr
}

fn relay(mut client: TcpStream, upstream: SocketAddr, mode: &AtomicU8) {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 65536];
    let head_end = loop {
        match client.read(&mut chunk) {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break p + 4;
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let length: usize = head
        .lines()
        .find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(str::to_owned))
        .map_or(0, |v| v.trim().parse().unwrap());
    while buf.len() < head_end + length {
        match client.read(&mut chunk) {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
    let first = head.lines().next().unwrap_or_default();
    let upload = first.starts_with("POST /v1/rooms/") && first.contains("/messages ");
    let spoil = if upload { mode.swap(PASS, Ordering::SeqCst) } else { PASS };
    if spoil == LOSE_REQUEST {
        return;
    }
    // One request per connection, so the response ends where the upstream closes.
    let head = head.replacen("\r\n\r\n", "\r\nConnection: close\r\n\r\n", 1);
    let mut up = TcpStream::connect(upstream).unwrap();
    up.write_all(head.as_bytes()).unwrap();
    up.write_all(&buf[head_end..]).unwrap();
    let mut response = Vec::new();
    let _ = up.read_to_end(&mut response);
    if spoil == LOSE_RESPONSE {
        return;
    }
    let _ = client.write_all(&response);
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("cairn-lost-{name}-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn person(url: &str, name: &str) -> Session {
    let s = Session::open(name, url, Some(&scratch(name))).unwrap();
    s.publish_key_packages(3).unwrap();
    s
}

/// Whether `s` reads a message saying `text` within a few polls.
fn hears(s: &mut Session, text: &str) -> bool {
    (0..6).any(|_| {
        s.poll()
            .unwrap_or_default()
            .into_iter()
            .any(|e| matches!(e, Event::Message(m) if m.body == text))
    })
}

/// Alice owns a group, through the proxy; Bob is in it; Carol has redeemed an invite and is
/// waiting to be admitted.
fn waiting_room(mode: &Arc<AtomicU8>) -> (Session, Session, Session, String) {
    let server = start();
    let direct = format!("http://{}", server.addr);
    let proxied = format!("http://{}", proxy(server.addr, mode.clone()));
    // The runtime must outlive the sessions; the test process ends first.
    std::mem::forget(server);
    let mut alice = person(&proxied, "alice");
    let mut bob = person(&direct, "bob");
    let mut carol = person(&direct, "carol");
    let room = alice.create_group(10).unwrap();
    bob.redeem_invite(&alice.create_invite(1, 24).unwrap()).unwrap();
    alice.admit_waiting().unwrap();
    bob.open_room(&room).unwrap();
    alice.send("before").unwrap();
    assert!(hears(&mut bob, "before"));
    carol.redeem_invite(&alice.create_invite(1, 24).unwrap()).unwrap();
    carol.open_room(&room).unwrap();
    (alice, bob, carol, room)
}

#[test]
fn a_commit_that_never_reached_the_instance_does_not_cut_its_sender_off() {
    let mode = Arc::new(AtomicU8::new(PASS));
    let (mut alice, mut bob, mut carol, _room) = waiting_room(&mode);

    mode.store(LOSE_REQUEST, Ordering::SeqCst);
    assert!(alice.admit_waiting().unwrap().is_empty(), "the upload failed, so nobody was admitted");
    assert!(alice.send("too soon").is_err(), "nothing is sent while the commit is unsettled");

    // The poll finds the log without it and forgets it: Alice stays in Bob's epoch.
    alice.poll().unwrap();
    alice.send("still here").unwrap();
    assert!(hears(&mut bob, "still here"), "bob must still read alice after a lost commit");
    bob.send("and back").unwrap();
    assert!(hears(&mut alice, "and back"), "alice must still read bob after a lost commit");

    // Carol is still waiting, and admitting her again works.
    assert_eq!(alice.waiting().unwrap().len(), 1, "carol was never added, so she still waits");
    assert_eq!(alice.admit_waiting().unwrap().len(), 1);
    alice.send("welcome carol").unwrap();
    assert!(hears(&mut carol, "welcome carol"), "carol must be admitted on the second try");
    assert!(hears(&mut bob, "welcome carol"));
}

#[test]
fn a_commit_whose_answer_was_lost_still_admits_the_newcomer() {
    let mode = Arc::new(AtomicU8::new(PASS));
    let (mut alice, mut bob, mut carol, _room) = waiting_room(&mode);

    mode.store(LOSE_RESPONSE, Ordering::SeqCst);
    assert!(alice.admit_waiting().unwrap().is_empty(), "the answer was lost, so alice cannot know");

    // The commit is in the log. Alice's poll finds it there, follows it into the new epoch,
    // and only then sends Carol the welcome she was holding.
    alice.poll().unwrap();
    assert!(alice.waiting().unwrap().is_empty(), "carol is in the group now");
    alice.send("after the lost answer").unwrap();
    assert!(hears(&mut bob, "after the lost answer"), "bob must follow the commit alice made");
    assert!(hears(&mut carol, "after the lost answer"), "carol must get the held welcome");
    carol.send("hello both").unwrap();
    assert!(hears(&mut alice, "hello both"));
}
