//! TURN relay credentials, over real HTTP.
//!
//! The rules are in `state.rs` (`Instance::turn_credentials`); these check the plumbing to
//! them and try the obvious attacks on an endpoint that hands out the operator's bandwidth:
//! asking without signing, asking for a room you are not in, and asking for a room that
//! does not exist. Each must get nothing — no credential, and no hint whether a relay runs.

use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::sync::Arc;

use cairn_client_core::client::Client;
use cairn_client_core::session::Session;
use cairn_client_core::transport::HttpTransport;
use cairn_crypto::mls::Session as MlsSession;
use cairn_proto::{DeviceId, DeviceIdentity, RoomId, UserId};
use cairn_server::state::{Instance, RegistrationPolicy, TurnConfig};

const SECRET: &str = "the-relay-and-the-instance-share-this";

struct Server {
    addr: SocketAddr,
    _runtime: tokio::runtime::Runtime,
}

fn start(relay: bool) -> Server {
    let instance = Arc::new(Instance::in_memory());
    instance.set_registration_policy(RegistrationPolicy::Open).unwrap();
    if relay {
        instance.set_turn(Some(
            TurnConfig::new(
                &["stun:turn.example:3478", "turn:turn.example:3478"],
                SECRET,
                Some(600),
            )
            .unwrap(),
        ));
    }
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

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("cairn-turn-{name}-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn session(server: &Server, name: &str) -> Session {
    Session::open(name, &format!("http://{}", server.addr), Some(&scratch(name))).unwrap()
}

/// A registered account that is in no room: signs its requests properly, and should still
/// get nothing for somebody else's room.
fn outsider(server: &Server) -> Client<HttpTransport> {
    let (user, device) = (UserId::new(), DeviceId::new());
    let identity = DeviceIdentity::new(user, device).to_credential();
    let mls = Arc::new(MlsSession::open(scratch("outsider"), &identity).unwrap());
    let client =
        Client::new(HttpTransport::new(format!("http://{}", server.addr)), mls, user, device);
    client.claim_account(None).unwrap();
    client
}

/// A bare request with no signature headers at all — what a stranger on the internet sends.
fn raw_post(server: &Server, path: &str) -> (u16, String) {
    use std::io::{Read, Write};
    let mut stream = std::net::TcpStream::connect(server.addr).unwrap();
    write!(
        stream,
        "POST {path} HTTP/1.1\r\nHost: {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        server.addr
    )
    .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    let status = response.split(' ').nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    (status, response)
}

fn hmac_sha1_b64(secret: &str, message: &str) -> String {
    // Independent of the server's own helper, so the test is not checking code against
    // itself: the client must be able to hand these straight to a coturn using the secret.
    use base64::Engine as _;
    use hmac::Mac as _;
    let mut mac = hmac::Hmac::<sha1::Sha1>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(message.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes())
}

#[test]
fn a_member_in_a_call_gets_relay_credentials_coturn_would_accept() {
    let server = start(true);
    let mut alice = session(&server, "alice");
    alice.create_direct().unwrap();

    let config = alice.call_config().unwrap();
    assert!(config.has_relay);
    assert!(config.direct, "a DM says so, so a declined call there can end");
    let relay = config
        .ice_servers
        .iter()
        .find(|s| s.urls.iter().any(|u| u.starts_with("turn:")))
        .expect("the instance's relay");
    let username = relay.username.as_deref().unwrap();
    let (expiry, who) = username.split_once(':').unwrap();
    assert_eq!(who, alice.user_id());
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
        as i64;
    let expiry: i64 = expiry.parse().unwrap();
    assert!((now + 590..=now + 610).contains(&expiry), "short-lived: the operator's 600s");
    assert_eq!(relay.credential.as_deref(), Some(hmac_sha1_b64(SECRET, username).as_str()));

    // The operator listed its own STUN, so the public default is not used at all.
    assert!(
        !config.ice_servers.iter().flat_map(|s| &s.urls).any(|u| u.contains("google")),
        "{:?}",
        config.ice_servers
    );
}

#[test]
fn an_unauthenticated_request_gets_no_relay_credentials() {
    let server = start(true);
    let mut alice = session(&server, "alice");
    let room = alice.create_direct().unwrap();
    let uuid = room.trim_start_matches("rom_");

    let (status, body) = raw_post(&server, &format!("/v1/rooms/{uuid}/turn"));
    assert_eq!(status, 401, "{body}");
    assert!(!body.contains("credential") && !body.contains("turn:"), "{body}");
}

#[test]
fn an_account_outside_the_room_gets_no_relay_credentials() {
    let server = start(true);
    let mut alice = session(&server, "alice");
    let room: RoomId = alice.create_direct().unwrap().parse().unwrap();

    let mallory = outsider(&server);
    let err = mallory.turn_credentials(room).expect_err("not a member of that room");
    assert!(err.to_string().contains("403"), "{err}");

    // And a room that does not exist gets the same answer as one that is not yours, so the
    // endpoint cannot be used to test whether a private room id is real.
    let err = mallory.turn_credentials(RoomId::new()).expect_err("no such room");
    assert!(err.to_string().contains("403"), "{err}");
}

#[test]
fn without_a_relay_a_member_is_told_calls_are_stun_only() {
    let server = start(false);
    let mut alice = session(&server, "alice");
    alice.create_group(10).unwrap();
    let config = alice.call_config().unwrap();
    assert!(!config.has_relay);
    assert!(!config.direct);
    assert!(config.ice_servers.iter().all(|s| s.credential.is_none()));
}
