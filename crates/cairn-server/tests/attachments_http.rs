//! Attachments, exercised over a real socket.
//!
//! `CLAUDE.md` requires this rather than only in-process tests, and attachments are exactly
//! the shape of feature where that matters: the access rule is membership, and both of this
//! project's shipped room vulnerabilities were membership bugs that passed unit tests
//! written against the same wrong mental model as the code.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;

use cairn_crypto::mls::Session;
use cairn_proto::{DeviceId, ResourceRef, RoomId, RoomShape, UserId};
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
    let router = cairn_server::http::router(instance.clone());
    runtime.spawn(async move {
        let listener = tokio::net::TcpListener::from_std(listener).unwrap();
        axum::serve(listener, router.into_make_service_with_connect_info::<std::net::SocketAddr>())
            .await
            .unwrap();
    });

    Server { addr, instance, _runtime: runtime }
}

struct Response {
    status: u16,
    body: Vec<u8>,
}

/// Hand-rolled HTTP/1.1, matching the other test files, but byte-oriented: attachments are
/// binary, and a `String` body would corrupt exactly what these tests are checking.
fn request(
    addr: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, String)],
    body: Option<&[u8]>,
) -> Response {
    let mut stream = TcpStream::connect(addr).unwrap();
    let body = body.unwrap_or(&[]);

    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n");
    for (name, value) in headers {
        req.push_str(&format!("{name}: {value}\r\n"));
    }
    if method == "POST" {
        req.push_str("Content-Type: application/octet-stream\r\n");
        req.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    req.push_str("\r\n");

    let mut raw_req = req.into_bytes();
    raw_req.extend_from_slice(body);
    stream.write_all(&raw_req).unwrap();
    stream.flush().unwrap();

    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).unwrap();

    let head_end = raw.windows(4).position(|w| w == b"\r\n\r\n").expect("headers");
    let head = String::from_utf8_lossy(&raw[..head_end]).into_owned();
    let status = head.split_whitespace().nth(1).and_then(|s| s.parse().ok()).expect("status");
    Response { status, body: raw[head_end + 4..].to_vec() }
}

struct Account {
    session: Session,
    user: UserId,
    device: DeviceId,
}

impl Account {
    fn register(server: &Server) -> Self {
        let account = Self {
            session: Session::new(b"tester").unwrap(),
            user: UserId::new(),
            device: DeviceId::new(),
        };
        server
            .instance
            .claim_account(account.user, account.device, account.session.public_key(), None, 0)
            .unwrap();
        account
    }

    fn headers(&self, action: &str, resource: ResourceRef) -> Vec<(&'static str, String)> {
        let issued_at = now_ms();
        let bytes = cairn_proto::request_signing_bytes(action, Some(resource), issued_at);
        let signature = self.session.sign(&bytes).unwrap();
        vec![
            ("x-cairn-device", self.device.as_uuid().to_string()),
            ("x-cairn-timestamp", issued_at.to_string()),
            ("x-cairn-signature", hex::encode(signature)),
        ]
    }
}

fn now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as i64
}

fn dm_shape() -> RoomShape {
    RoomShape { is_direct: true, is_publicly_discoverable: false, member_ceiling: 8 }
}

fn upload(server: &Server, by: &Account, room: RoomId, bytes: &[u8]) -> Response {
    request(
        server.addr,
        "POST",
        &format!("/v1/rooms/{}/blobs", room.as_uuid()),
        &by.headers("upload_blob", ResourceRef::Room(room)),
        Some(bytes),
    )
}

fn download(server: &Server, by: &Account, blob: &str) -> Response {
    let id: cairn_proto::BlobId = blob.parse().unwrap();
    request(
        server.addr,
        "GET",
        &format!("/v1/blobs/{}", id.as_uuid()),
        &by.headers("download_blob", ResourceRef::Blob(id)),
        None,
    )
}

fn blob_id(response: &Response) -> String {
    let parsed: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
    parsed["blob"].as_str().unwrap().to_string()
}

#[test]
fn a_member_can_store_and_retrieve_an_attachment() {
    let server = start();
    let alice = Account::register(&server);
    let (room, _) = server.instance.create_room(dm_shape(), alice.user).unwrap();

    // What a client would actually send: ciphertext. The key lives inside the encrypted
    // message body, so the server holds bytes it cannot read.
    let ciphertext: Vec<u8> = (0..4096).map(|i| (i % 251) as u8).collect();

    let uploaded = upload(&server, &alice, room, &ciphertext);
    assert_eq!(uploaded.status, 201, "upload failed");

    let fetched = download(&server, &alice, &blob_id(&uploaded));
    assert_eq!(fetched.status, 200);
    assert_eq!(fetched.body, ciphertext, "an attachment must round-trip byte-exact");
}

#[test]
fn a_non_member_cannot_read_an_attachment() {
    // The property that makes attachments safe to add at all. A blob id is a uuid, but ids
    // are guessable in principle and leak in practice, so the id must not be the credential.
    let server = start();
    let alice = Account::register(&server);
    let outsider = Account::register(&server);
    let (room, _) = server.instance.create_room(dm_shape(), alice.user).unwrap();

    let uploaded = upload(&server, &alice, room, b"secret ciphertext");
    let response = download(&server, &outsider, &blob_id(&uploaded));

    assert_eq!(response.status, 403, "a non-member must not read a room's attachments");
    assert!(!response.body.ends_with(b"secret ciphertext"));
}

#[test]
fn a_non_member_cannot_park_storage_in_someone_elses_room() {
    // Without this check any authenticated account could push bytes into any instance, and
    // worse, into a room's attachment space — content aimed at people who never admitted it.
    let server = start();
    let alice = Account::register(&server);
    let outsider = Account::register(&server);
    let (room, _) = server.instance.create_room(dm_shape(), alice.user).unwrap();

    assert_eq!(upload(&server, &outsider, room, b"unwanted").status, 403);
}

#[test]
fn a_removed_member_loses_access_to_the_rooms_attachments() {
    // Membership is evaluated at fetch time, not at upload time. The alternative leaves a
    // removed member with a permanent read channel into a room that ejected them, which is
    // exactly the hole `remove_room_member` exists to close.
    let server = start();
    let alice = Account::register(&server);
    let bob = Account::register(&server);
    let (room, _) = server.instance.create_room(dm_shape(), alice.user).unwrap();
    server.instance.add_room_member(room, alice.user, bob.user).unwrap();

    let uploaded = upload(&server, &alice, room, b"ciphertext bob may read for now");
    assert_eq!(download(&server, &bob, &blob_id(&uploaded)).status, 200);

    server.instance.remove_room_member(room, alice.user, bob.user).unwrap();

    assert_eq!(
        download(&server, &bob, &blob_id(&uploaded)).status,
        403,
        "removal must revoke attachment access, not only future messages"
    );
}

#[test]
fn an_unauthenticated_request_cannot_touch_attachments() {
    let server = start();
    let alice = Account::register(&server);
    let (room, _) = server.instance.create_room(dm_shape(), alice.user).unwrap();
    let uploaded = upload(&server, &alice, room, b"ciphertext");

    let unsigned = request(
        server.addr,
        "GET",
        &format!(
            "/v1/blobs/{}",
            blob_id(&uploaded).parse::<cairn_proto::BlobId>().unwrap().as_uuid()
        ),
        &[],
        None,
    );
    assert_eq!(unsigned.status, 401);
}

#[test]
fn an_oversized_attachment_is_refused_by_the_instance_not_the_framework() {
    // The ceiling is the operator's policy, so it has to be *the instance* that says no.
    // A framework-level body limit sitting in front of it would reject at a different size
    // than the one `MAX_BLOB_BYTES` advertises, and an operator raising the limit would
    // find it had no effect.
    let server = start();
    let alice = Account::register(&server);
    let (room, _) = server.instance.create_room(dm_shape(), alice.user).unwrap();

    let too_big = vec![0u8; MAX_BLOB_BYTES + 1];
    assert_eq!(
        upload(&server, &alice, room, &too_big).status,
        413,
        "the instance's own ceiling must be the thing that rejects"
    );

    // And a large-but-permitted upload must actually succeed, which is the half that
    // catches a framework limit set lower than the instance's.
    let big_but_allowed = vec![7u8; 5 * 1024 * 1024];
    let uploaded = upload(&server, &alice, room, &big_but_allowed);
    assert_eq!(uploaded.status, 201, "5 MiB is under the ceiling and must be accepted");
    assert_eq!(download(&server, &alice, &blob_id(&uploaded)).body.len(), big_but_allowed.len());
}

#[test]
fn an_empty_attachment_is_refused() {
    let server = start();
    let alice = Account::register(&server);
    let (room, _) = server.instance.create_room(dm_shape(), alice.user).unwrap();
    assert_eq!(upload(&server, &alice, room, b"").status, 400);
}

#[test]
fn the_instance_never_holds_a_readable_attachment() {
    // The end-to-end claim, over a socket, with the real encryption rather than a stand-in:
    // seal on the client, upload, and confirm what the server hands back is still opaque —
    // and that only the key from the encrypted message body opens it.
    //
    // Checked against the bytes the *server returns*, not against a local buffer, because
    // the interesting failure is an instance that stores or serves plaintext.
    let server = start();
    let alice = Account::register(&server);
    let bob = Account::register(&server);
    let (room, _) = server.instance.create_room(dm_shape(), alice.user).unwrap();
    server.instance.add_room_member(room, alice.user, bob.user).unwrap();

    let plaintext = b"a private photo, or a leaked document, or anything else".to_vec();
    let (key, sealed) = cairn_crypto::attachment::seal(&plaintext);

    let uploaded = upload(&server, &alice, room, &sealed);
    assert_eq!(uploaded.status, 201);

    let fetched = download(&server, &bob, &blob_id(&uploaded));
    assert_eq!(fetched.status, 200);

    assert!(
        !fetched.body.windows(plaintext.len()).any(|w| w == plaintext.as_slice()),
        "the instance must never hold or serve readable attachment bytes"
    );

    // Only the key, which travelled inside the encrypted message body, opens it.
    assert_eq!(cairn_crypto::attachment::open(&key, &fetched.body).unwrap(), plaintext);

    // And a member without that key gets nothing from the bytes alone.
    let wrong = cairn_crypto::attachment::AttachmentKey::generate();
    assert!(cairn_crypto::attachment::open(&wrong, &fetched.body).is_err());
}
