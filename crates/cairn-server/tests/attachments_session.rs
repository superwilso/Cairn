//! Attachments through the session layer the desktop client stands on, over a real socket.
//!
//! `attachments_http.rs` proves the blob store's rules against hand-built requests. This
//! proves the other half: that `Session` — what the Tauri commands delegate to — seals,
//! uploads, carries the key inside the encrypted message, and opens what comes back, and
//! that a frontend driving it cannot get anything it should not.
//!
//! Several of these began as probes, per `CLAUDE.md`: an attack written down and run, kept
//! because of what it showed. Each says what it found.

use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::sync::Arc;

use cairn_client_core::session::{
    AttachmentKind, AttachmentView, Event, Session, SessionError, MAX_ATTACHMENT_BYTES,
    SEAL_OVERHEAD,
};
use cairn_server::state::{Instance, RegistrationPolicy, MAX_BLOB_BYTES};

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
    let router = cairn_server::http::router(Arc::clone(&instance));
    runtime.spawn(async move {
        let listener = tokio::net::TcpListener::from_std(listener).unwrap();
        axum::serve(listener, router).await.unwrap();
    });
    Server { addr, instance, _runtime: runtime }
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("cairn-att-{name}-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn open_at(server: &Server, name: &str, dir: &std::path::Path) -> Session {
    Session::open(name, &format!("http://{}", server.addr), Some(dir)).unwrap()
}

/// Alice and Bob in one encrypted group, Bob admitted and caught up. Returns Bob's state
/// directory so a test can reopen him.
fn two_in_a_group(server: &Server, tag: &str) -> (Session, Session, String, PathBuf) {
    let mut alice = open_at(server, &format!("{tag}-alice"), &scratch(&format!("{tag}-a")));
    let bob_dir = scratch(&format!("{tag}-b"));
    let mut bob = open_at(server, &format!("{tag}-bob"), &bob_dir);
    bob.publish_key_packages(3).unwrap();

    let room = alice.create_group(10).unwrap();
    let token = alice.create_invite(1, 24).unwrap();
    bob.redeem_invite(&token).unwrap();
    alice.admit_waiting().unwrap();
    bob.open_room(&room).unwrap();
    bob.poll().unwrap();
    (alice, bob, room, bob_dir)
}

/// Poll until a message with an attachment arrives.
fn receive_attachment(session: &mut Session) -> AttachmentView {
    for _ in 0..10 {
        for event in session.poll().unwrap() {
            if let Event::Message(m) = event {
                if let Some(a) = m.attachment {
                    return a;
                }
            }
        }
    }
    panic!("no attachment arrived");
}

/// A small but real PNG header followed by noise — the type is what matters, not the pixels.
fn photo() -> Vec<u8> {
    let mut bytes = b"\x89PNG\r\n\x1a\n".to_vec();
    bytes.extend((0..4096u32).map(|i| (i.wrapping_mul(2_654_435_761) >> 24) as u8));
    bytes
}

#[test]
fn a_photo_sent_through_the_session_arrives_and_opens() {
    let server = start();
    let (mut alice, mut bob, _room, _) = two_in_a_group(&server, "photo");
    let bytes = photo();

    let sent = alice.send_file("beach.png", "image/png", &bytes).unwrap();
    let mine = sent.attachment.expect("the sender's own view must carry the attachment");
    assert_eq!(mine.kind, AttachmentKind::Image);

    let got = receive_attachment(&mut bob);
    assert_eq!(got.name, "beach.png");
    assert_eq!(got.size, bytes.len());
    assert_eq!(got.kind, AttachmentKind::Image, "a PNG is shown inline");
    assert_eq!(got.id, mine.id, "both sides must name the same blob");

    assert_eq!(bob.fetch_attachment(&got.id).unwrap(), bytes, "the recipient opens it");
    assert_eq!(alice.fetch_attachment(&mine.id).unwrap(), bytes, "and so does the sender");

    // The sender's copy comes from `send_file`'s return value, not the poll — MLS does not
    // decrypt a device's own message back to it. If that ever changed, a frontend rendering
    // both would show every file twice.
    let echoed = alice.poll().unwrap().into_iter().any(|e| matches!(e, Event::Message(_)));
    assert!(!echoed, "the sender must not also receive its own attachment from the poll");
}

#[test]
fn the_instance_holds_only_ciphertext_for_a_session_attachment() {
    // Read straight out of the instance rather than trusting the session's account of what
    // it uploaded.
    let server = start();
    let (mut alice, _bob, _room, _) = two_in_a_group(&server, "opaque");
    let bytes = b"a sentence the instance must never be able to read, padded out".repeat(20);
    let sent = alice.send_file("letter.txt", "text/plain", &bytes).unwrap();
    let id: cairn_proto::BlobId = sent.attachment.unwrap().id.parse().unwrap();

    let alice_user: cairn_proto::UserId = alice.user_id().parse().unwrap();
    let stored = server.instance.fetch_blob(alice_user, id).unwrap();
    assert_eq!(stored.len(), bytes.len() + SEAL_OVERHEAD);
    let needle = &bytes[..32];
    assert!(
        !stored.windows(needle.len()).any(|w| w == needle),
        "the instance must hold ciphertext, not the file"
    );
}

#[test]
fn a_voice_note_arrives_as_playable_audio() {
    let server = start();
    let (mut alice, mut bob, _room, _) = two_in_a_group(&server, "voice");
    // What Chromium's MediaRecorder reports, parameters included.
    alice
        .send_file("voice-note.webm", "audio/webm;codecs=opus", b"\x1aE\xdf\xa3 not really opus")
        .unwrap();
    let got = receive_attachment(&mut bob);
    assert_eq!(got.kind, AttachmentKind::Audio);
    assert_eq!(got.mime, "audio/webm;codecs=opus", "the codec parameter is needed to play it");
}

#[test]
fn a_senders_claim_that_a_document_is_an_image_is_not_acted_on() {
    // The type travels inside the encrypted body, so only a room member can lie — but a
    // member can. An SVG is a document with a scripting model; it arrives as a file.
    let server = start();
    let (mut alice, mut bob, _room, _) = two_in_a_group(&server, "svg");
    alice.send_file("x.svg", "image/svg+xml", b"<svg onload=alert(1)/>").unwrap();
    assert_eq!(receive_attachment(&mut bob).kind, AttachmentKind::File);
}

#[test]
fn an_attachment_is_still_openable_after_a_restart() {
    // MLS will not decrypt a message twice, so the key has to have been remembered. Without
    // that a photo received yesterday is a grey box today.
    let server = start();
    let (mut alice, mut bob, room, bob_dir) = two_in_a_group(&server, "restart");
    let bytes = photo();
    alice.send_file("kept.png", "image/png", &bytes).unwrap();
    let got = receive_attachment(&mut bob);
    drop(bob);

    let mut bob = open_at(&server, "restart-bob", &bob_dir);
    let history = bob.open_room(&room).unwrap();
    let replayed = history
        .iter()
        .find_map(|m| m.attachment.clone())
        .expect("the attachment must be in the replayed transcript");
    assert_eq!(replayed.id, got.id);
    assert_eq!(bob.fetch_attachment(&replayed.id).unwrap(), bytes);
}

#[test]
fn a_transcript_written_before_attachments_existed_still_opens() {
    // `serde(default)` on the new history field is load-bearing: without it every existing
    // user's transcript becomes "corrupt" the moment this ships. Written by hand in the old
    // shape — including an old CLI entry that recorded only a filename.
    let server = start();
    let (_alice, mut bob, room, bob_dir) = two_in_a_group(&server, "oldhist");
    let room_id: cairn_proto::RoomId = room.parse().unwrap();
    let path = bob_dir.join("history").join(format!("{}.jsonl", room_id.as_uuid()));
    let sender = cairn_proto::UserId::new();
    let old = format!(
        "{}\n{}\n",
        serde_json::json!({"sender": sender, "sent_at_ms": 1, "body": b"before".to_vec()}),
        serde_json::json!({
            "sender": sender, "sent_at_ms": 2, "body": b"x.pdf".to_vec(), "attachment_name": "x.pdf"
        }),
    );
    std::fs::write(&path, old).unwrap();

    let replayed = bob.open_room(&room).unwrap();
    assert_eq!(replayed.len(), 2);
    assert_eq!(replayed[0].body, "before");
    assert!(replayed.iter().all(|m| m.attachment.is_none()), "no descriptor, so nothing to fetch");
}

// ---- probes ------------------------------------------------------------------------------

#[test]
fn a_device_cannot_fetch_an_attachment_from_a_room_it_is_not_in() {
    // Probe: Carol learns a blob id from Alice and Bob's room — ids are not secret — and
    // asks her own session for it. Showed: refused locally, because her session never saw
    // a message carrying it and so has no key; the request never leaves the device. The
    // instance-side rule (non-members get nothing) is covered in `attachments_http.rs`.
    let server = start();
    let (mut alice, _bob, _room, _) = two_in_a_group(&server, "otherroom");
    let id = alice.send_file("private.png", "image/png", &photo()).unwrap().attachment.unwrap().id;

    let mut carol = open_at(&server, "otherroom-carol", &scratch("otherroom-c"));
    carol.create_group(5).unwrap();
    assert!(matches!(carol.fetch_attachment(&id), Err(SessionError::UnknownAttachment)));
}

#[test]
fn an_attachment_is_not_fetchable_once_its_room_is_closed() {
    // Probe: a frontend holding an id from a room it has navigated away from. The session
    // scopes known attachments to the open room, so the id stops resolving.
    let server = start();
    let (mut alice, _bob, room, _) = two_in_a_group(&server, "scope");
    let id = alice.send_file("a.png", "image/png", &photo()).unwrap().attachment.unwrap().id;
    alice.create_group(5).unwrap();
    assert!(matches!(alice.fetch_attachment(&id), Err(SessionError::UnknownAttachment)));
    alice.open_room(&room).unwrap();
    assert!(alice.fetch_attachment(&id).is_ok(), "reopening the room brings it back");
}

#[test]
fn a_tampered_key_fails_to_open_rather_than_returning_bytes() {
    // Probe: flip one hex digit of the stored key in the recipient's transcript and fetch.
    // Showed: the authentication tag refuses it and the session reports an error — no
    // partial or garbage plaintext reaches a frontend. Same outcome as an instance serving
    // substituted bytes, which `cairn_crypto::attachment` tests directly.
    let server = start();
    let (mut alice, mut bob, room, bob_dir) = two_in_a_group(&server, "tamper");
    alice.send_file("t.png", "image/png", &photo()).unwrap();
    let got = receive_attachment(&mut bob);
    drop(bob);

    let room_id: cairn_proto::RoomId = room.parse().unwrap();
    let path = bob_dir.join("history").join(format!("{}.jsonl", room_id.as_uuid()));
    let mut lines: Vec<serde_json::Value> = std::fs::read_to_string(&path)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let entry = lines.iter_mut().find(|v| v.get("attachment").is_some()).unwrap();
    let key = entry["attachment"]["key"].as_str().unwrap().to_string();
    let flipped = format!("{}{}", if key.starts_with('0') { '1' } else { '0' }, &key[1..]);
    entry["attachment"]["key"] = serde_json::Value::String(flipped);
    let rewritten: String = lines.iter().map(|v| format!("{v}\n")).collect();
    std::fs::write(&path, rewritten).unwrap();

    let mut bob = open_at(&server, "tamper-bob", &bob_dir);
    bob.open_room(&room).unwrap();
    assert!(matches!(
        bob.fetch_attachment(&got.id),
        Err(SessionError::Attachment(cairn_crypto::attachment::AttachmentError::NotAuthentic))
    ));
}

#[test]
fn the_clients_ceiling_is_the_instances_ceiling_less_the_seal() {
    // Two constants in two crates describing one limit. If they drift, a file the client
    // accepts is one the instance refuses, after the upload.
    assert_eq!(MAX_ATTACHMENT_BYTES + SEAL_OVERHEAD, MAX_BLOB_BYTES);
}

#[test]
fn an_oversized_file_is_refused_before_anything_is_uploaded() {
    // Probe: one byte over through the session path. Showed: refused locally with an error
    // a person can read, before sealing or uploading — the error is the session's own, not
    // a transport failure, which is how this test knows nothing reached the instance.
    let server = start();
    let (mut alice, _bob, _room, _) = two_in_a_group(&server, "toolarge");
    let err = alice.send_file(
        "big.bin",
        "application/octet-stream",
        &vec![7u8; MAX_ATTACHMENT_BYTES + 1],
    );
    match err {
        Err(e @ SessionError::AttachmentTooLarge { .. }) => {
            let said = e.to_string();
            assert!(said.contains("25.0 MiB"), "the message must name the limit: {said}");
        }
        other => panic!("expected a local refusal, got {other:?}"),
    }
}

#[test]
fn an_empty_file_is_refused_before_anything_is_uploaded() {
    let server = start();
    let (mut alice, _bob, _room, _) = two_in_a_group(&server, "empty");
    assert!(matches!(alice.send_file("e", "text/plain", b""), Err(SessionError::EmptyAttachment)));
}

#[test]
fn the_largest_file_the_client_allows_can_be_sent_and_received() {
    // Probe: exactly at the ceiling, end to end. Showed, before the fix: the upload
    // succeeded and the *download* failed — `ureq` caps a response body at 10 MiB by
    // default, so every attachment between 10 and 25 MiB could be sent and never opened by
    // anybody. The failure surfaced as a transport error on the recipient's side only, long
    // after the sender had seen it go.
    let server = start();
    let (mut alice, mut bob, _room, _) = two_in_a_group(&server, "ceiling");
    let bytes: Vec<u8> = (0..MAX_ATTACHMENT_BYTES).map(|i| (i % 251) as u8).collect();
    alice.send_file("max.bin", "application/octet-stream", &bytes).unwrap();
    let got = receive_attachment(&mut bob);
    let fetched = bob.fetch_attachment(&got.id).expect("a file at the ceiling must be openable");
    assert_eq!(fetched.len(), bytes.len());
    assert!(fetched == bytes);
}

#[test]
fn a_device_not_yet_admitted_cannot_park_ciphertext_in_the_room() {
    // A device that joined by invite and has not been admitted is a room member to the
    // instance, which would accept its upload. It holds no group key, so nobody could read
    // what it sent; refusing before the upload stops it spending room storage on nothing.
    let server = start();
    let mut alice = open_at(&server, "stale-a", &scratch("stale-a"));
    let mut bob = open_at(&server, "stale-b", &scratch("stale-b"));
    let room = alice.create_group(10).unwrap();
    let token = alice.create_invite(1, 24).unwrap();
    bob.redeem_invite(&token).unwrap();
    bob.open_room(&room).unwrap();
    assert!(matches!(bob.send_file("x.png", "image/png", &photo()), Err(SessionError::NoGroupYet)));
}

#[test]
fn saving_writes_under_a_safe_name_and_never_overwrites() {
    let server = start();
    let (mut alice, mut bob, _room, _) = two_in_a_group(&server, "save");
    alice.send_file("../../escape.txt", "text/plain", b"contents").unwrap();
    let got = receive_attachment(&mut bob);

    let downloads = scratch("save-dl");
    let first = bob.save_attachment(&got.id, &downloads).unwrap();
    let second = bob.save_attachment(&got.id, &downloads).unwrap();
    assert_eq!(first, downloads.join("escape.txt"), "the traversal must be stripped");
    assert_eq!(second, downloads.join("escape (1).txt"), "a second save must not overwrite");
    assert_eq!(std::fs::read(&first).unwrap(), b"contents");
    assert!(!downloads.parent().unwrap().join("escape.txt").exists());
}
