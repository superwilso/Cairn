//! A space, end to end, through the session layer the desktop client delegates to.
//!
//! Real sessions, real MLS, a real socket. The flow is the one a Discord-shaped community
//! needs and that nothing could do before: a space with a channel, someone invited in and
//! admitted to the channel's encrypted group, a conversation, a kick — and the two halves of
//! the kick, the instance's and the cryptographic one, checked separately because they are
//! different guarantees (ADR-011).

use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::sync::Arc;

use cairn_client_core::session::{Event, Session};
use cairn_server::state::{Instance, RegistrationPolicy};

struct Server {
    addr: SocketAddr,
    _instance: Arc<Instance>,
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
    Server { addr, _instance: instance, _runtime: runtime }
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("cairn-space-{name}-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn session(server: &Server, name: &str) -> Session {
    Session::open(name, &format!("http://{}", server.addr), Some(&scratch(name))).unwrap()
}

fn hear(who: &mut Session) -> Vec<String> {
    let mut out = Vec::new();
    for _ in 0..8 {
        for event in who.poll().unwrap() {
            if let Event::Message(m) = event {
                out.push(m.body);
            }
        }
        if !out.is_empty() {
            break;
        }
    }
    out
}

#[test]
fn a_space_channel_works_end_to_end_and_a_kick_ends_it_on_both_layers() {
    let server = start();
    let mut alice = session(&server, "alice");
    let mut bob = session(&server, "bob");
    let mut carol = session(&server, "carol");
    bob.publish_key_packages(3).unwrap();
    carol.publish_key_packages(3).unwrap();

    let space = alice.create_space("Trailhead", None).unwrap();
    let channel = alice.create_channel(&space, "general").unwrap();
    assert_eq!(alice.open_room_tier().as_deref(), Some("T2"), "a private channel is E2EE");
    assert!(alice.rooms().is_empty(), "a channel is listed under its space, not among DMs");

    let token = alice.create_space_invite(&space, 5, 24).unwrap();
    assert_eq!(bob.redeem_space_invite(&token).unwrap(), space);
    carol.redeem_space_invite(&token).unwrap();

    // Bob sees the channel, and that he does not yet hold its keys.
    let seen = bob.space(&space).unwrap();
    assert_eq!(seen.channels.len(), 1);
    assert_eq!(seen.channels[0].id, channel);
    assert_eq!(seen.channels[0].tier, "T2");
    assert!(!seen.channels[0].joined, "joining the space grants no keys");
    assert!(seen.my_permissions.contains(&"send") && !seen.my_permissions.contains(&"kick"));

    // Alice admits the waiting members to the channel's group — the same explicit action as
    // a group chat, against the list the space computes.
    let mut waiting = alice.waiting().unwrap();
    waiting.sort();
    assert_eq!(waiting.len(), 2, "bob and carol wait: {waiting:?}");
    assert_eq!(alice.admit_waiting().unwrap().len(), 2);

    bob.open_room(&channel).unwrap();
    bob.poll().unwrap();
    carol.open_room(&channel).unwrap();
    carol.poll().unwrap();
    alice.send("welcome to the trailhead").unwrap();
    assert_eq!(hear(&mut bob), vec!["welcome to the trailhead"]);
    assert_eq!(hear(&mut carol), vec!["welcome to the trailhead"]);
    assert!(bob.space(&space).unwrap().channels[0].joined);

    // Bob cannot kick anyone. The UI would not offer it; the instance is what refuses.
    let carol_id = carol.user_id();
    assert!(bob.kick(&space, &carol_id).is_err());

    // The instance's half of the kick: bob is refused everything at once.
    let bob_id = bob.user_id();
    alice.kick(&space, &bob_id).unwrap();
    assert!(bob.poll().is_err(), "a kicked device can no longer fetch the channel");
    assert!(bob.space(&space).is_err());
    assert!(bob.redeem_space_invite(&token).is_err(), "nor walk back in with the link");

    // The cryptographic half. Until a member commits the removal, bob's leaf is still in the
    // group — the client says so, as "unlisted", rather than hiding it.
    let members = alice.members().unwrap();
    let ghost = members.iter().find(|m| m.user == bob_id).expect("still in the roster");
    assert_eq!(ghost.role, "unlisted");
    assert_eq!(alice.remove_departed().unwrap(), vec![bob_id.clone()]);
    assert!(alice.members().unwrap().iter().all(|m| m.user != bob_id), "leaf removed");

    // Carol sees the removal as a membership change, and the conversation carries on.
    let mut left = Vec::new();
    for _ in 0..8 {
        for event in carol.poll().unwrap() {
            if let Event::Membership { left: l, .. } = event {
                left.extend(l);
            }
        }
        if !left.is_empty() {
            break;
        }
    }
    assert!(left.iter().any(|l| l.contains(&bob_id[4..12])), "carol is told bob left: {left:?}");
    alice.send("after bob").unwrap();
    assert_eq!(hear(&mut carol), vec!["after bob"]);
}

#[test]
fn a_space_too_big_for_encryption_is_refused_rather_than_made_public() {
    let server = start();
    let mut alice = session(&server, "big");
    assert!(alice.create_space("Huge", Some(cairn_proto::tier::T2_MAX_MEMBERS + 1)).is_err());
}
