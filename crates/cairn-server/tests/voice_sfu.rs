#![cfg(feature = "sfu")]
//! Voice channels, attacked over real HTTP and real WebRTC.
//!
//! Each test started as a probe — an attempt at the attack, printing what happened — per
//! the project's rule that security code here is not trusted until something has tried to
//! break it. The clients are `str0m` peers speaking ICE, DTLS-SRTP and RTP to the SFU on a
//! UDP socket, joined through `cairn-client-core`'s `Session` exactly as the desktop app
//! joins, so a rule enforced anywhere but `state.rs` and the SFU would not hold here.
//!
//! What the probes showed: three of the four attacks failed against the code as first
//! written. One succeeded — a member removed from the room kept their voice seat — and that
//! one is now `a_member_removed_from_the_room_stops_hearing_its_voice_channel` here and
//! `a_member_removed_from_the_room_loses_their_voice_seat` in `state.rs`.

use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use cairn_client_core::session::{Session, SessionError};
use cairn_server::sfu::{SfuConfig, RECEIVE_SLOTS};
use cairn_server::state::{Instance, RegistrationPolicy};
use str0m::change::SdpAnswer;
use str0m::media::{Direction, Frequency, MediaKind, MediaTime};
use str0m::net::{Protocol, Receive};
use str0m::{Candidate, Event, Input, Output, RtcConfig};

struct Server {
    addr: SocketAddr,
    instance: Arc<Instance>,
    _runtime: tokio::runtime::Runtime,
}

fn start() -> Server {
    let instance = Arc::new(Instance::in_memory());
    instance.set_registration_policy(RegistrationPolicy::Open).unwrap();
    let local: SocketAddr = "127.0.0.1:0".parse().unwrap();
    instance.start_sfu(SfuConfig { bind: local, advertise: local }).unwrap();
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
    Server { addr, instance, _runtime: runtime }
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("cairn-voice-{name}-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn person(server: &Server, name: &str) -> Session {
    let s = Session::open(name, &format!("http://{}", server.addr), Some(&scratch(name))).unwrap();
    s.publish_key_packages(3).unwrap();
    s
}

/// A room with `owner` and `others` all in its MLS group and all with it open.
fn room(owner: &mut Session, others: &mut [&mut Session]) -> String {
    let room = owner.create_group(20).unwrap();
    for s in others.iter_mut() {
        let token = owner.create_invite(1, 24).unwrap();
        s.redeem_invite(&token).unwrap();
        owner.admit_waiting().unwrap();
        s.open_room(&room).unwrap();
        for _ in 0..3 {
            s.poll().unwrap();
        }
    }
    owner.poll().unwrap();
    room
}

/// A headless WebRTC client on the SFU, sending `label` as a frame every 20 ms and recording
/// every payload it receives.
struct Peer {
    received: Arc<Mutex<Vec<Vec<u8>>>>,
    connected: Arc<AtomicBool>,
    alive: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    answer: String,
}

impl Drop for Peer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

fn connect(session: &mut Session, label: &str) -> Result<Peer, SessionError> {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut rtc = RtcConfig::new()
        .set_crypto_provider(Arc::new(str0m::crypto::from_feature_flags()))
        .clear_codecs()
        .enable_opus(true, false)
        .build(Instant::now());
    rtc.add_local_candidate(Candidate::host(socket.local_addr().unwrap(), "udp").unwrap());
    let mut api = rtc.sdp_api();
    let mic = api.add_media(MediaKind::Audio, Direction::SendOnly, Some("me".into()), None, None);
    for _ in 0..RECEIVE_SLOTS {
        api.add_media(MediaKind::Audio, Direction::RecvOnly, None, None, None);
    }
    let (offer, pending) = api.apply().unwrap();
    let joined = session.voice_join(&offer.to_sdp_string(), true)?;
    rtc.sdp_api()
        .accept_answer(pending, SdpAnswer::from_sdp_string(&joined.answer).unwrap())
        .unwrap();

    let peer = Peer {
        received: Arc::default(),
        connected: Arc::default(),
        alive: Arc::new(AtomicBool::new(true)),
        stop: Arc::default(),
        answer: joined.answer,
    };
    let (received, connected, alive, stop) =
        (peer.received.clone(), peer.connected.clone(), peer.alive.clone(), peer.stop.clone());
    let label = label.as_bytes().to_vec();
    std::thread::spawn(move || {
        let mut buf = vec![0u8; 2000];
        let mut next_send = Instant::now();
        let mut ts: u64 = 0;
        while !stop.load(Ordering::Relaxed) && rtc.is_alive() {
            let timeout = loop {
                match rtc.poll_output() {
                    Ok(Output::Timeout(t)) => break t,
                    Ok(Output::Transmit(t)) => {
                        let _ = socket.send_to(&t.contents, t.destination);
                    }
                    Ok(Output::Event(Event::Connected)) => connected.store(true, Ordering::Relaxed),
                    Ok(Output::Event(Event::MediaData(d))) => {
                        received.lock().unwrap().push(d.data.to_vec())
                    }
                    Ok(Output::Event(_)) => {}
                    Err(_) => {
                        rtc.disconnect();
                        break Instant::now();
                    }
                }
            };
            if connected.load(Ordering::Relaxed) && Instant::now() >= next_send {
                if let Some(writer) = rtc.writer(mic) {
                    let pt = writer.payload_params().next().map(|p| p.pt());
                    if let Some(pt) = pt {
                        let _ = writer.write(
                            pt,
                            Instant::now(),
                            MediaTime::new(ts, Frequency::FORTY_EIGHT_KHZ),
                            label.clone(),
                        );
                    }
                }
                ts += 960;
                next_send += Duration::from_millis(20);
            }
            let wait = timeout
                .min(next_send)
                .saturating_duration_since(Instant::now())
                .max(Duration::from_millis(1));
            let _ = socket.set_read_timeout(Some(wait.min(Duration::from_millis(20))));
            if let Ok((n, source)) = socket.recv_from(&mut buf) {
                if let Ok(contents) = buf[..n].try_into() {
                    let input = Input::Receive(
                        Instant::now(),
                        Receive {
                            proto: Protocol::Udp,
                            source,
                            destination: socket.local_addr().unwrap(),
                            contents,
                        },
                    );
                    let _ = rtc.handle_input(input);
                }
            }
            let _ = rtc.handle_input(Input::Timeout(Instant::now()));
        }
        alive.store(false, Ordering::Relaxed);
    });
    Ok(peer)
}

fn wait_for(what: &str, mut f: impl FnMut() -> bool) {
    let end = Instant::now() + Duration::from_secs(15);
    while Instant::now() < end {
        if f() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("timed out waiting for {what}");
}

fn heard(peer: &Peer, label: &str) -> usize {
    peer.received.lock().unwrap().iter().filter(|p| p.as_slice() == label.as_bytes()).count()
}

#[test]
fn a_member_of_another_room_cannot_join_this_rooms_voice_channel() {
    let server = start();
    let mut alice = person(&server, "alice");
    let mut bob = person(&server, "bob");
    let mut carol = person(&server, "carol");
    let a = room(&mut alice, &mut [&mut bob]);
    let _b = room(&mut carol, &mut []);

    // Carol is a real, authenticated account in a room of her own. Point her session at
    // alice's room and ask for a seat.
    let opened = carol.open_room(&a);
    let attempt = match opened {
        Ok(_) => connect(&mut carol, "carol").map(|_| ()),
        Err(e) => Err(e),
    };
    let refused = format!("{:?}", attempt.expect_err("a non-member must not get a seat"));
    println!("PROBE non-member join: {refused}");
    assert!(refused.contains("403") || refused.contains("not a member"), "{refused}");
    assert!(server
        .instance
        .voice_roster(a.parse().unwrap(), alice.user_id().parse().unwrap())
        .unwrap()
        .is_empty());
}

#[test]
fn media_from_one_rooms_voice_channel_never_reaches_another() {
    let server = start();
    let mut alice = person(&server, "alice");
    let mut bob = person(&server, "bob");
    let mut carol = person(&server, "carol");
    let mut dave = person(&server, "dave");
    let _a = room(&mut alice, &mut [&mut bob]);
    let _b = room(&mut carol, &mut [&mut dave]);

    let pa = connect(&mut alice, "room-a:alice").unwrap();
    let pb = connect(&mut bob, "room-a:bob").unwrap();
    let pc = connect(&mut carol, "room-b:carol").unwrap();
    let pd = connect(&mut dave, "room-b:dave").unwrap();
    wait_for("everyone connected", || {
        [&pa, &pb, &pc, &pd].iter().all(|p| p.connected.load(Ordering::Relaxed))
    });
    wait_for("each room hearing itself", || {
        heard(&pb, "room-a:alice") > 20 && heard(&pd, "room-b:carol") > 20
    });

    let crossed: Vec<(&str, usize)> = [
        ("carol heard alice", heard(&pc, "room-a:alice")),
        ("dave heard bob", heard(&pd, "room-a:bob")),
        ("alice heard carol", heard(&pa, "room-b:carol")),
        ("bob heard dave", heard(&pb, "room-b:dave")),
    ]
    .into_iter()
    .collect();
    println!("PROBE cross-room: {crossed:?}");
    for (what, n) in crossed {
        assert_eq!(n, 0, "{what}: media crossed between rooms");
    }
}

#[test]
fn a_member_removed_from_the_room_stops_hearing_its_voice_channel() {
    // **This one was a probe that succeeded.** As first written, removal from the room left
    // the voice seat in place and the SFU went on forwarding to it. Fixed in
    // `Instance::remove_room_member`.
    let server = start();
    let mut alice = person(&server, "alice");
    let mut bob = person(&server, "bob");
    let mut carol = person(&server, "carol");
    let a = room(&mut alice, &mut [&mut bob, &mut carol]);

    let pa = connect(&mut alice, "alice").unwrap();
    let pb = connect(&mut bob, "bob").unwrap();
    let pc = connect(&mut carol, "carol").unwrap();
    wait_for("carol hears alice", || heard(&pc, "alice") > 20);

    let room_id = a.parse().unwrap();
    server
        .instance
        .remove_room_member(
            room_id,
            alice.user_id().parse().unwrap(),
            carol.user_id().parse().unwrap(),
        )
        .unwrap();
    // One forwarding decision is enough; leave generous room for packets already in flight.
    std::thread::sleep(Duration::from_millis(300));
    let before = (heard(&pc, "alice"), heard(&pb, "carol"));
    std::thread::sleep(Duration::from_secs(1));
    let after = (heard(&pc, "alice"), heard(&pb, "carol"));
    println!("PROBE after removal: carol heard alice {before:?} -> {after:?} (alice frames, carol frames at bob)");
    assert_eq!(before.0, after.0, "the removed member kept receiving the room's audio");
    assert_eq!(before.1, after.1, "the removed member's audio kept reaching the room");
    assert!(heard(&pb, "alice") > 0, "the people still in the room still hear each other");
    let roster = server.instance.voice_roster(room_id, alice.user_id().parse().unwrap()).unwrap();
    assert!(roster.iter().all(|p| p.user.to_string() != carol.user_id()));
    // And the SFU closed the connection rather than just going quiet on it.
    wait_for("the SFU to close carol's connection", || {
        !pc.alive.load(Ordering::Relaxed) || {
            let n = heard(&pc, "bob");
            std::thread::sleep(Duration::from_millis(200));
            n == heard(&pc, "bob")
        }
    });
    drop(pa);
}

#[test]
fn the_sfu_does_not_negotiate_the_clear_audio_level_header() {
    // Browsers put a per-packet loudness value in an RTP header extension *outside* any
    // frame encryption. If the SFU agreed to it, it would hold a voice-activity meter for
    // every participant for free. The str0m client offers it, as Chromium does.
    let server = start();
    let mut alice = person(&server, "alice");
    let _a = room(&mut alice, &mut []);
    let peer = connect(&mut alice, "alice").unwrap();
    println!("PROBE audio-level in answer: {}", peer.answer.contains("ssrc-audio-level"));
    assert!(!peer.answer.contains("ssrc-audio-level"), "{}", peer.answer);
}
