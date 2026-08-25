//! The desktop client's session layer, against a real instance over HTTP.
//!
//! `cairn_client_core::session::Session` is what the Tauri commands delegate to, so this is
//! the seam the whole desktop client stands on. Proving it here means the GUI is only ever
//! presentation — and it can be proven without a display, which is the point.
//!
//! The flow is the one a group chat actually needs and that no client could do before:
//! create a **group** (not a DM), invite, redeem, admit, and talk.

use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::sync::Arc;

use cairn_client_core::session::{Event, Session, SessionError};
use cairn_server::state::{Instance, RegistrationPolicy};

struct Server {
    addr: SocketAddr,
    /// Held so a test can read what the instance *stored*, not only what it serves.
    instance: Arc<Instance>,
    _runtime: tokio::runtime::Runtime,
}

fn start() -> Server {
    start_with(RegistrationPolicy::Open, &[])
}

fn start_with(policy: RegistrationPolicy, invites: &[&str]) -> Server {
    let instance = Arc::new(Instance::in_memory());
    instance.set_registration_policy(policy).unwrap();
    for token in invites {
        instance.create_invite(token, None).unwrap();
    }
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();
    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
    let router = cairn_server::http::router(Arc::clone(&instance));
    runtime.spawn(async move {
        let listener = tokio::net::TcpListener::from_std(listener).unwrap();
        axum::serve(listener, router).await.unwrap();
    });
    Server { addr, instance, _runtime: runtime }
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("cairn-sess-{name}-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn session(server: &Server, name: &str) -> Session {
    Session::open(name, &format!("http://{}", server.addr), Some(&scratch(name))).unwrap()
}

/// Registration against an instance that requires an invite.
///
/// **The configuration nearly every instance will actually run.** `InviteOnly` is the
/// server's default and what `docs/11-self-hosting.md` recommends, and until this landed the
/// desktop client could only pass `None` — so the only instance it could sign in to was one
/// whose operator had opened registration to the entire internet.
#[test]
fn a_client_can_register_against_an_invite_only_instance() {
    let server = start_with(RegistrationPolicy::InviteOnly, &["let-me-in"]);
    let dir = scratch("invited");
    let session = Session::open_with_invite(
        "invited",
        &format!("http://{}", server.addr),
        Some(&dir),
        Some("let-me-in"),
    )
    .expect("a valid invite must get an account onto the instance");
    assert!(session.user_id().starts_with("usr_"));
}

/// Assert a sign-in was refused **by the instance**, not by anything local.
///
/// The two tests below assert a failure, and for one CI run that made them the only tests in
/// this file that passed — every other one died on a state directory the runner would not let
/// the process chmod, and `is_err()` is satisfied by that too. A negative test that accepts
/// any error certifies a client which cannot start at all.
fn refused_by_the_instance(result: Result<Session, SessionError>) {
    match result {
        Ok(_) => panic!("the instance must not have admitted this account"),
        Err(SessionError::Client(_)) => {}
        Err(other) => panic!("expected a refusal from the instance, got a local failure: {other}"),
    }
}

#[test]
fn registration_without_an_invite_is_refused_when_the_instance_requires_one() {
    // Counterfactual, and the one that matters: if the invite were being ignored rather than
    // honoured, the test above would pass on an instance that admits anybody.
    let server = start_with(RegistrationPolicy::InviteOnly, &["let-me-in"]);
    let dir = scratch("uninvited");
    refused_by_the_instance(Session::open(
        "uninvited",
        &format!("http://{}", server.addr),
        Some(&dir),
    ));
}

#[test]
fn a_wrong_invite_is_refused() {
    let server = start_with(RegistrationPolicy::InviteOnly, &["let-me-in"]);
    let dir = scratch("guesser");
    refused_by_the_instance(Session::open_with_invite(
        "guesser",
        &format!("http://{}", server.addr),
        Some(&dir),
        Some("let-me-in-too"),
    ));
}

#[test]
fn a_registered_client_reopens_without_its_invite() {
    // The gap this walked into once already: the instance checks the invite *before* it
    // notices the account exists, so a returning user presenting a spent token is refused —
    // locked out of their own account. The claim is recorded locally and not repeated.
    let server = start_with(RegistrationPolicy::InviteOnly, &["one-use"]);
    let dir = scratch("returning");
    let url = format!("http://{}", server.addr);
    let first = Session::open_with_invite("returning", &url, Some(&dir), Some("one-use")).unwrap();
    let user = first.user_id();
    drop(first);

    let again = Session::open("returning", &url, Some(&dir))
        .expect("reopening a registered profile must not need the invite again");
    assert_eq!(again.user_id(), user, "and it must be the same account");
}

#[test]
fn a_group_chat_works_end_to_end_through_the_session_layer() {
    let server = start();
    let mut alice = session(&server, "alice");
    let mut bob = session(&server, "bob");

    // Without published key packages nobody can be admitted to a group, and the failure
    // surfaces much later as "my friend cannot add me".
    bob.publish_key_packages(3).unwrap();

    // A group, not a DM. This is the case no client could reach before: `cairn-cli`
    // hardcoded is_direct/ceiling 2, so every room was two people.
    let room = alice.create_group(50).unwrap();
    assert_eq!(
        alice.open_room_tier().as_deref(),
        Some("T2"),
        "a private group must seal as T2 — end-to-end encrypted, not merely transport"
    );

    // Bob joins by invite. No user id crosses between them.
    let token = alice.create_invite(1, 24).unwrap();
    let joined = bob.redeem_invite(&token).unwrap();
    assert_eq!(joined, room, "the invite must land bob in alice's room");

    // Redeeming joins the room; it does not hand over the keys. Bob is present and cannot
    // read anything, which is the property the UI has to show rather than hide.
    let waiting = alice.waiting().unwrap();
    assert_eq!(waiting.len(), 1, "bob must show as waiting, identified by account");

    let admitted = alice.admit_waiting().unwrap();
    assert_eq!(admitted.len(), 1, "admitting must let exactly bob in");
    assert!(
        alice.waiting().unwrap().is_empty(),
        "after admission nobody is left waiting — without this a check that always \
         reported everyone would pass the assertion above"
    );

    // Bob picks up the welcome and the message that follows it.
    bob.open_room(&room).unwrap();
    bob.poll().unwrap();

    alice.send("first thing said in a group").unwrap();

    let mut heard = None;
    for _ in 0..8 {
        for event in bob.poll().unwrap() {
            if let Event::Message(m) = event {
                heard = Some(m.body);
            }
        }
        if heard.is_some() {
            break;
        }
    }
    assert_eq!(
        heard.as_deref(),
        Some("first thing said in a group"),
        "bob must be able to read the group he was admitted to"
    );

    // And the member view keeps the two lists distinct rather than flattening them.
    let members = alice.members().unwrap();
    assert_eq!(members.len(), 2);
    assert!(members.iter().all(|m| m.in_group), "both are in the encrypted group now");
}

#[test]
fn a_group_is_still_end_to_end_encrypted_not_merely_transport() {
    // The property most likely to be quietly lost when "group" is added to a product: a
    // bigger room drifting to a server-readable tier. Only discoverability should do that.
    let server = start();
    let mut alice = session(&server, "tier");
    alice.create_group(500).unwrap();
    assert_eq!(alice.open_room_tier().as_deref(), Some("T2"));
}

#[test]
fn a_group_larger_than_the_private_ceiling_is_refused_rather_than_downgraded() {
    // Asking for more members than T2 allows does not get a bigger private room — it would
    // get a public, server-readable one. Refusing beats silently handing back something
    // weaker than was asked for.
    let server = start();
    let mut alice = session(&server, "toobig");
    assert!(alice.create_group(cairn_proto::tier::T2_MAX_MEMBERS + 1).is_err());
}

#[test]
fn a_member_who_has_not_been_admitted_cannot_send() {
    // Bob is in the room and has no group. Sending must fail loudly rather than appear to
    // work and vanish.
    let server = start();
    let mut alice = session(&server, "nosend-a");
    let mut bob = session(&server, "nosend-b");
    let room = alice.create_group(10).unwrap();
    let token = alice.create_invite(1, 24).unwrap();
    bob.redeem_invite(&token).unwrap();
    bob.open_room(&room).unwrap();

    assert!(bob.send("can anyone hear me").is_err(), "an unadmitted member cannot send");
}

/// Call signalling, which is the only part of a call that can be tested without a device.
///
/// Media cannot be exercised here — there is no microphone, no camera and no display — so
/// what is proven is the seam WebRTC sits on: that an offer reaches the peer it was
/// addressed to, that it does not reach anyone else, and that the instance never sees it.
mod calls {
    use super::*;
    use cairn_client_core::call::{CallSignal, SignalKind};

    fn two_in_a_group() -> (Server, Session, Session, String) {
        let server = start();
        let mut alice = session(&server, "call-alice");
        let mut bob = session(&server, "call-bob");
        bob.publish_key_packages(3).unwrap();

        let room = alice.create_group(10).unwrap();
        let token = alice.create_invite(1, 24).unwrap();
        bob.redeem_invite(&token).unwrap();
        alice.admit_waiting().unwrap();
        bob.open_room(&room).unwrap();
        bob.poll().unwrap();
        (server, alice, bob, room)
    }

    /// Alice starts a call; bob is told, and joins it.
    ///
    /// This is the flow the product has: one person presses the button, the other is *rung*
    /// and accepts. It is here as a helper because getting it wrong is invisible — before
    /// `ringing` existed, bob had no way to learn a call was happening and joining meant
    /// starting a second one.
    fn ring_then_join() -> (Server, Session, Session, String, String) {
        let (server, mut alice, mut bob, room) = two_in_a_group();
        let call = alice.call_join().unwrap();

        let mut rang = false;
        for _ in 0..8 {
            for event in bob.poll().unwrap() {
                if let Event::Signal { signal, .. } = event {
                    if signal.kind == SignalKind::Join {
                        rang = true;
                    }
                }
            }
        }
        assert!(rang, "bob must be told a call started — otherwise he cannot join it");

        let joined = bob.call_join().unwrap();
        assert_eq!(joined, call, "accepting a ring joins that call, it does not start another");
        for _ in 0..4 {
            alice.poll().unwrap();
            bob.poll().unwrap();
        }
        (server, alice, bob, room, call)
    }

    #[test]
    fn an_offer_reaches_the_peer_it_was_addressed_to() {
        let (_server, mut alice, mut bob, _room, call) = ring_then_join();

        alice
            .signal(CallSignal {
                call: call.clone(),
                kind: SignalKind::Offer,
                to: Some(bob.user_id()),
                payload: "v=0 fake sdp".into(),
            })
            .unwrap();

        let mut got = None;
        for _ in 0..8 {
            for event in bob.poll().unwrap() {
                if let Event::Signal { signal, .. } = event {
                    if signal.kind == SignalKind::Offer {
                        got = Some(signal);
                    }
                }
            }
            if got.is_some() {
                break;
            }
        }
        let got = got.expect("bob must receive the offer addressed to him");
        assert_eq!(got.payload, "v=0 fake sdp");
        assert_eq!(got.call, call, "and it must name the call it belongs to");
    }

    #[test]
    fn a_signal_addressed_to_someone_else_is_not_delivered() {
        // Every signal rides the room, so every participant receives the envelope. The
        // filtering has to happen before a frontend sees it — applying another pair's offer
        // would replace a working peer connection with a broken one, and it would look like
        // a network fault rather than a bug.
        let (_server, mut alice, mut bob, _room, call) = ring_then_join();

        alice
            .signal(CallSignal {
                call: call.clone(),
                kind: SignalKind::Offer,
                to: Some("usr_00000000000000000000000000000000".into()),
                payload: "not for bob".into(),
            })
            .unwrap();

        // A second signal, this one addressed to bob, sent after the misdirected one. Without
        // it the test would pass just as happily if bob's polling were broken and he
        // received nothing at all — which is how a filtering test becomes a test of nothing.
        alice
            .signal(CallSignal {
                call: call.clone(),
                kind: SignalKind::Offer,
                to: Some(bob.user_id()),
                payload: "this one is for bob".into(),
            })
            .unwrap();

        let mut delivery_works = false;
        for _ in 0..8 {
            for event in bob.poll().unwrap() {
                if let Event::Signal { signal, .. } = event {
                    assert_ne!(
                        signal.payload, "not for bob",
                        "a signal addressed to a third party must not reach bob"
                    );
                    if signal.payload == "this one is for bob" {
                        delivery_works = true;
                    }
                }
            }
        }
        assert!(
            delivery_works,
            "bob's signal delivery must be working for the check above to mean anything"
        );
    }

    #[test]
    fn a_join_announcement_reaches_everyone() {
        // Counterfactual for the test above: if filtering dropped unaddressed signals too,
        // nobody would ever learn that a participant had arrived and no call could start.
        let (_server, mut alice, mut bob, _room) = two_in_a_group();
        alice.call_join().unwrap();

        let mut announced = false;
        for _ in 0..8 {
            for event in bob.poll().unwrap() {
                if let Event::Signal { signal, .. } = event {
                    if signal.kind == SignalKind::Join {
                        announced = true;
                    }
                }
            }
            if announced {
                break;
            }
        }
        assert!(announced, "bob must learn that alice joined the call");
    }

    #[test]
    fn signalling_does_not_appear_in_the_timeline_as_a_message() {
        // An SDP blob rendered as chat is the obvious failure, and the empty body makes it
        // worse: participants would see a blank line for every ICE candidate.
        let (_server, mut alice, mut bob, _room, call) = ring_then_join();
        alice
            .signal(CallSignal {
                call,
                kind: SignalKind::Ice,
                to: Some(bob.user_id()),
                payload: "candidate:1 1 UDP".into(),
            })
            .unwrap();

        let mut saw_the_candidate = false;
        for _ in 0..8 {
            for event in bob.poll().unwrap() {
                match event {
                    Event::Message(_) => panic!("signalling must never surface as a chat message"),
                    Event::Signal { signal, .. } if signal.kind == SignalKind::Ice => {
                        saw_the_candidate = true;
                    }
                    _ => {}
                }
            }
        }
        // Same trap as above: "no message appeared" is trivially true if nothing appeared.
        assert!(
            saw_the_candidate,
            "the candidate must have arrived, as a signal rather than a message"
        );
    }

    #[test]
    fn two_people_starting_a_call_at_the_same_moment_end_up_in_one_call() {
        // Found by a test of the frontend mesh, never by reading either side. Every
        // participant minted its own call id on joining and discarded every signal that did
        // not carry *its* id, so two people pressing "call" within the same second sat in
        // two calls of one person each — both showing a connecting spinner, neither ever
        // connecting, and indistinguishable from a network fault.
        let (_server, mut alice, mut bob, _room) = two_in_a_group();
        let a_call = alice.call_join().unwrap();
        let b_call = bob.call_join().unwrap();
        assert_ne!(a_call, b_call, "each side really does mint its own id to begin with");

        for _ in 0..8 {
            alice.poll().unwrap();
            bob.poll().unwrap();
        }
        assert_eq!(alice.call_id(), bob.call_id(), "both must converge on one call");

        // Convergence that does not carry signalling would be a matching pair of strings and
        // nothing else. An offer sent after it has to actually arrive.
        alice
            .signal(CallSignal {
                call: String::from("whatever the frontend last saw"),
                kind: SignalKind::Offer,
                to: Some(bob.user_id()),
                payload: "v=0 after converging".into(),
            })
            .unwrap();

        let mut got = None;
        for _ in 0..8 {
            for event in bob.poll().unwrap() {
                if let Event::Signal { signal, .. } = event {
                    if signal.kind == SignalKind::Offer {
                        got = Some(signal);
                    }
                }
            }
        }
        let got = got.expect("the offer must reach bob once both are in the same call");
        assert_eq!(got.payload, "v=0 after converging");
        assert_eq!(
            Some(got.call),
            alice.call_id(),
            "and it must be stamped with the agreed id, not the one the frontend passed in"
        );
    }

    #[test]
    fn only_arrival_and_departure_reach_a_device_that_is_not_in_the_call() {
        // Counterfactual for the ring, and the reason it is narrow. A device has to be able
        // to learn that a call started, and that it stopped — but only that. Delivering an
        // offer to somebody who never joined would have their client build a peer connection
        // for a call its user has not accepted, which is a camera light coming on without
        // being asked.
        let (_server, mut alice, mut bob, _room) = two_in_a_group();
        let call = alice.call_join().unwrap();
        alice
            .signal(CallSignal {
                call,
                kind: SignalKind::Offer,
                to: Some(bob.user_id()),
                payload: "unsolicited".into(),
            })
            .unwrap();

        let mut rang = false;
        for _ in 0..8 {
            for event in bob.poll().unwrap() {
                if let Event::Signal { signal, .. } = event {
                    assert_ne!(
                        signal.payload, "unsolicited",
                        "an offer must not reach a device that has not joined the call"
                    );
                    if signal.kind == SignalKind::Join {
                        rang = true;
                    }
                }
            }
        }
        assert!(rang, "the arrival announcement itself must still get through");
        assert!(bob.call_id().is_none(), "and being rung is not the same as being in a call");

        // A ring that cannot stop is worse than no ring: the caller gives up and the callee
        // is left with a banner for a call nobody is in.
        alice.call_leave().unwrap();
        let mut stopped = false;
        for _ in 0..8 {
            for event in bob.poll().unwrap() {
                if let Event::Signal { signal, .. } = event {
                    if signal.kind == SignalKind::Leave {
                        stopped = true;
                    }
                }
            }
        }
        assert!(stopped, "bob must be told the caller hung up");
    }

    #[test]
    fn the_instance_never_sees_the_sdp() {
        // The reason signalling rides inside the encrypted body. An offer names the sender's
        // codecs, candidates and IP addresses; beside the ciphertext all of it would be the
        // instance's to read.
        let (server, mut alice, mut _bob, room, call) = ring_then_join();
        let secret = "v=0 SDP-THE-SERVER-MUST-NOT-SEE";
        alice
            .signal(CallSignal {
                call,
                kind: SignalKind::Offer,
                to: Some(_bob.user_id()),
                payload: secret.into(),
            })
            .unwrap();

        // Read the stored records themselves — envelope included — rather than trusting
        // that a serving endpoint would have redacted anything.
        let stored = server
            .instance
            .messages_since(room.parse().unwrap(), alice.user_id().parse().unwrap(), 0, 0)
            .unwrap();
        assert!(!stored.is_empty(), "the signal must have reached the instance at all");
        let raw = serde_json::to_string(&stored).unwrap();
        assert!(
            !raw.contains(secret),
            "the SDP must not appear anywhere in what the instance holds"
        );
    }
}
