//! Key package distribution, exercised over a real socket.
//!
//! `CLAUDE.md` requires this rather than only in-process tests: the two room
//! vulnerabilities in this project's history both passed unit tests written against the
//! same wrong mental model as the code, and both were found by making the actual request.
//! So these talk HTTP/1.1 to a listening server.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;

use cairn_crypto::mls::Session;
use cairn_proto::{DeviceId, ResourceRef, UserId};
use cairn_server::state::{Instance, RegistrationPolicy};

/// A running instance, plus the handle to talk to it.
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
        axum::serve(listener, router).await.unwrap();
    });

    Server { addr, instance, _runtime: runtime }
}

struct Response {
    status: u16,
    body: String,
}

/// A minimal HTTP/1.1 client. Deliberately hand-rolled: adding an HTTP client dependency
/// to a security product's test tree to verify its own HTTP surface is a poor trade.
fn request(
    addr: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, String)],
    body: Option<&str>,
) -> Response {
    let mut stream = TcpStream::connect(addr).unwrap();
    let body = body.unwrap_or("");

    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n");
    for (name, value) in headers {
        req.push_str(&format!("{name}: {value}\r\n"));
    }
    if !body.is_empty() || method == "POST" {
        req.push_str("Content-Type: application/json\r\n");
        req.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    req.push_str("\r\n");
    req.push_str(body);

    stream.write_all(req.as_bytes()).unwrap();
    stream.flush().unwrap();

    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).unwrap();
    let raw = String::from_utf8_lossy(&raw).into_owned();

    let status = raw.split_whitespace().nth(1).and_then(|s| s.parse().ok()).expect("a status line");
    let body = raw.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
    // Responses are `Connection: close`, so the body is whatever followed the headers.
    // Chunked encoding would need unpacking; axum sends Content-Length for these.
    Response { status, body }
}

/// A registered account with one device that can sign requests.
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

    /// Signed-request headers for one action against one resource.
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

    fn key_package_hex(&self) -> String {
        hex::encode(self.session.key_package().unwrap().to_bytes().unwrap())
    }
}

fn now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as i64
}

fn publish(server: &Server, by: &Account, for_device: DeviceId, packages: &[String]) -> Response {
    let body = serde_json::json!({ "packages": packages }).to_string();
    request(
        server.addr,
        "POST",
        &format!("/v1/devices/{}/key-packages", for_device.as_uuid()),
        &by.headers("publish_key_packages", ResourceRef::Device(for_device)),
        Some(&body),
    )
}

fn claim(server: &Server, by: &Account, target: UserId) -> Response {
    request(
        server.addr,
        "POST",
        &format!("/v1/users/{}/key-packages", target.as_uuid()),
        &by.headers("claim_key_packages", ResourceRef::User(target)),
        None,
    )
}

#[test]
fn a_published_key_package_can_be_claimed_over_http() {
    let server = start();
    let alice = Account::register(&server);
    let bob = Account::register(&server);

    let published = bob.key_package_hex();
    let response = publish(&server, &bob, bob.device, std::slice::from_ref(&published));
    assert_eq!(response.status, 201, "publish failed: {}", response.body);

    let response = claim(&server, &alice, bob.user);
    assert_eq!(response.status, 200, "claim failed: {}", response.body);

    let claimed: Vec<serde_json::Value> = serde_json::from_str(&response.body).unwrap();
    assert_eq!(claimed.len(), 1, "one device, one package");
    assert_eq!(claimed[0]["key_package"], published);
    assert_eq!(claimed[0]["device"], bob.device.as_uuid().to_string());
}

#[test]
fn a_key_package_is_consumed_by_the_claim_that_took_it() {
    // MLS key packages are single-use: `mls-rs` deletes the secrets on join, so handing
    // one package to two groups would leave the second welcome permanently unopenable.
    let server = start();
    let alice = Account::register(&server);
    let bob = Account::register(&server);

    let first = bob.key_package_hex();
    let second = bob.key_package_hex();
    assert_ne!(first, second, "each generated key package must be distinct");
    assert_eq!(publish(&server, &bob, bob.device, &[first.clone(), second.clone()]).status, 201);

    let one = claim(&server, &alice, bob.user);
    let two = claim(&server, &alice, bob.user);
    let one: Vec<serde_json::Value> = serde_json::from_str(&one.body).unwrap();
    let two: Vec<serde_json::Value> = serde_json::from_str(&two.body).unwrap();
    assert_ne!(
        one[0]["key_package"], two[0]["key_package"],
        "two claims must never hand out the same package"
    );

    // Supply exhausted. 409, not 404 — the account exists and may be addable later.
    let three = claim(&server, &alice, bob.user);
    assert_eq!(three.status, 409, "an exhausted account must say so: {}", three.body);
}

#[test]
fn an_account_cannot_publish_key_packages_for_someone_elses_device() {
    // Otherwise this is key substitution with extra steps: a group creator asking for the
    // victim's key package would get one whose private half the attacker holds, and would
    // add the attacker while believing it added the victim.
    let server = start();
    let mallory = Account::register(&server);
    let victim = Account::register(&server);

    let planted = mallory.key_package_hex();
    let response = publish(&server, &mallory, victim.device, &[planted]);
    assert_eq!(
        response.status, 403,
        "publishing for another account's device must be refused: {}",
        response.body
    );

    // And nothing was stored, so the victim is not now addable as the attacker.
    assert_eq!(server.instance.key_packages_remaining(victim.device), 0);
}

#[test]
fn an_unauthenticated_caller_cannot_drain_an_account() {
    let server = start();
    let bob = Account::register(&server);
    assert_eq!(publish(&server, &bob, bob.device, &[bob.key_package_hex()]).status, 201);

    let response = request(
        server.addr,
        "POST",
        &format!("/v1/users/{}/key-packages", bob.user.as_uuid()),
        &[],
        None,
    );
    assert_eq!(response.status, 401, "claiming must require authentication: {}", response.body);
    assert_eq!(server.instance.key_packages_remaining(bob.device), 1, "nothing may be consumed");
}

#[test]
fn a_claim_that_names_no_target_is_refused() {
    // The reason `ResourceRef` exists, and the test that actually distinguishes.
    //
    // Before it, a signed request could only name a `RoomId`, so a key package claim had
    // to sign "no resource" — authorizing the *action* and nothing else. One legitimately
    // obtained signature would then drain any account on the instance inside the 60s
    // replay window. This signs exactly as such a client would and must be refused.
    //
    // Checked against the counterfactual: reverting the handler to pass `None` makes this
    // test fail (the drain succeeds), which is what makes it worth keeping.
    let server = start();
    let alice = Account::register(&server);
    let carol = Account::register(&server);
    assert_eq!(publish(&server, &carol, carol.device, &[carol.key_package_hex()]).status, 201);

    let issued_at = now_ms();
    let bytes = cairn_proto::request_signing_bytes("claim_key_packages", None, issued_at);
    let signature = alice.session.sign(&bytes).unwrap();
    let headers = vec![
        ("x-cairn-device", alice.device.as_uuid().to_string()),
        ("x-cairn-timestamp", issued_at.to_string()),
        ("x-cairn-signature", hex::encode(signature)),
    ];

    let response = request(
        server.addr,
        "POST",
        &format!("/v1/users/{}/key-packages", carol.user.as_uuid()),
        &headers,
        None,
    );
    assert_eq!(
        response.status, 401,
        "an authorization that names no target must not claim anyone's packages: {}",
        response.body
    );
    assert_eq!(server.instance.key_packages_remaining(carol.device), 1, "nothing consumed");
}

#[test]
fn a_claim_signature_cannot_be_redirected_at_another_account() {
    // Weaker than the test above — it also fails when the client and server merely
    // disagree about what to sign — but it pins the end-to-end behaviour a caller sees.
    let server = start();
    let alice = Account::register(&server);
    let bob = Account::register(&server);
    let carol = Account::register(&server);

    assert_eq!(publish(&server, &carol, carol.device, &[carol.key_package_hex()]).status, 201);

    // Alice signs a claim against Bob, then aims it at Carol.
    let headers = alice.headers("claim_key_packages", ResourceRef::User(bob.user));
    let response = request(
        server.addr,
        "POST",
        &format!("/v1/users/{}/key-packages", carol.user.as_uuid()),
        &headers,
        None,
    );

    assert_eq!(
        response.status, 401,
        "a signature naming one account must not authorize claiming another's: {}",
        response.body
    );
    assert_eq!(server.instance.key_packages_remaining(carol.device), 1, "nothing consumed");
}

#[test]
fn an_account_with_two_devices_yields_a_package_for_each() {
    // Each device holds its own MLS leaf, so adding a user means adding every device.
    // Returning one package would silently add one device and leave the others unable to
    // read the room.
    let server = start();
    let alice = Account::register(&server);
    let bob = Account::register(&server);

    let second_session = Session::new(b"bob-laptop").unwrap();
    let second_device = DeviceId::new();
    server
        .instance
        .link_device(
            bob.user,
            second_device,
            second_session.public_key(),
            bob.device,
            &bob.session
                .sign(&cairn_proto::device_authorization_bytes(
                    bob.user,
                    second_device,
                    second_session.public_key(),
                ))
                .unwrap(),
        )
        .unwrap();

    assert_eq!(publish(&server, &bob, bob.device, &[bob.key_package_hex()]).status, 201);

    // Only one device has published: the claim must fail rather than half-add the account.
    let partial = claim(&server, &alice, bob.user);
    assert_eq!(
        partial.status, 409,
        "a partial set would silently exclude a device: {}",
        partial.body
    );
    assert_eq!(
        server.instance.key_packages_remaining(bob.device),
        1,
        "a failed claim must not burn the packages of devices that did have one"
    );

    // Once both have published, both come back.
    let second_account = Account { session: second_session, user: bob.user, device: second_device };
    assert_eq!(
        publish(&server, &second_account, second_device, &[second_account.key_package_hex()])
            .status,
        201
    );

    let response = claim(&server, &alice, bob.user);
    assert_eq!(response.status, 200, "{}", response.body);
    let claimed: Vec<serde_json::Value> = serde_json::from_str(&response.body).unwrap();
    assert_eq!(claimed.len(), 2, "every device on the account must be represented");
}

#[test]
fn malformed_key_packages_are_refused() {
    let server = start();
    let bob = Account::register(&server);
    assert_eq!(publish(&server, &bob, bob.device, &["not hex".to_string()]).status, 400);
    assert_eq!(publish(&server, &bob, bob.device, &[String::new()]).status, 400);
    assert_eq!(server.instance.key_packages_remaining(bob.device), 0);
}
