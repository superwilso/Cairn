//! Registration limits, exercised over a real socket.
//!
//! Over HTTP rather than in-process because the property depends on things only the HTTP
//! layer sees — the peer address and the `X-Forwarded-For` header — and on the handler
//! calling the limited path rather than the unlimited one. Before this existed, one
//! address made 2,000 invite guesses in under a second and was never refused.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;

use axum::Router;
use cairn_server::address::TrustedProxies;
use cairn_server::state::{Instance, RegistrationPolicy, MAX_REGISTRATION_ATTEMPTS_PER_ADDRESS};

const INVITE: &str = "a-real-invite-for-a-real-friend";

struct Server {
    addr: SocketAddr,
    _runtime: tokio::runtime::Runtime,
}

fn instance(policy: RegistrationPolicy) -> Arc<Instance> {
    let instance = Arc::new(Instance::in_memory());
    instance.set_registration_policy(policy).unwrap();
    instance.create_invite(INVITE, None).unwrap();
    instance
}

fn serve(router: Router, with_connect_info: bool) -> Server {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();
    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
    runtime.spawn(async move {
        let listener = tokio::net::TcpListener::from_std(listener).unwrap();
        if with_connect_info {
            axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>())
                .await
                .unwrap();
        } else {
            axum::serve(listener, router).await.unwrap();
        }
    });
    Server { addr, _runtime: runtime }
}

/// Attempt a registration, optionally carrying an `X-Forwarded-For`. Returns the status.
fn register(server: &Server, invite: Option<&str>, forwarded_for: Option<&str>) -> u16 {
    let session = cairn_crypto::mls::Session::new(
        &cairn_proto::DeviceIdentity::new(cairn_proto::UserId::new(), cairn_proto::DeviceId::new())
            .to_credential(),
    )
    .unwrap();
    let body = serde_json::json!({
        "user": uuid::Uuid::new_v4(),
        "device": uuid::Uuid::new_v4(),
        "public_key": hex::encode(session.public_key()),
        "invite": invite,
    })
    .to_string();
    let mut extra = String::new();
    if let Some(xff) = forwarded_for {
        extra = format!("X-Forwarded-For: {xff}\r\n");
    }
    let mut stream = TcpStream::connect(server.addr).unwrap();
    let request = format!(
        "POST /v1/accounts HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n{extra}\
         Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).unwrap();
    let mut raw = String::new();
    stream.read_to_string(&mut raw).unwrap();
    raw.split_whitespace().nth(1).and_then(|s| s.parse().ok()).expect("a status line")
}

#[test]
fn invite_guessing_is_limited_per_address_over_http() {
    let server = serve(cairn_server::http::router(instance(RegistrationPolicy::InviteOnly)), true);
    for i in 0..MAX_REGISTRATION_ATTEMPTS_PER_ADDRESS {
        assert_eq!(register(&server, Some(&format!("guess-number-{i:08}")), None), 401);
    }
    assert_eq!(register(&server, Some("one-guess-too-many"), None), 429);
    // Failures spent the budget, so even the right answer is refused until the window
    // rolls. That is the point: a limiter counting only successes lets guessing run free.
    assert_eq!(register(&server, Some(INVITE), None), 429);
}

#[test]
fn open_registration_cannot_mint_accounts_without_bound_from_one_address() {
    let server = serve(cairn_server::http::router(instance(RegistrationPolicy::Open)), true);
    for _ in 0..MAX_REGISTRATION_ATTEMPTS_PER_ADDRESS {
        assert_eq!(register(&server, None, None), 201);
    }
    assert_eq!(register(&server, None, None), 429);
}

#[test]
fn a_forged_forwarded_for_does_not_buy_a_fresh_budget() {
    // No proxy is trusted, so the header is the client's own claim and must change nothing.
    let server = serve(cairn_server::http::router(instance(RegistrationPolicy::Open)), true);
    for i in 0..MAX_REGISTRATION_ATTEMPTS_PER_ADDRESS {
        assert_eq!(register(&server, None, Some(&format!("198.51.100.{i}"))), 201);
    }
    assert_eq!(register(&server, None, Some("203.0.113.250")), 429);
}

#[test]
fn behind_a_trusted_proxy_each_client_gets_its_own_budget() {
    // The test connects from 127.0.0.1, standing in for the proxy.
    let router = cairn_server::http::router_behind(
        instance(RegistrationPolicy::Open),
        TrustedProxies::parse("127.0.0.1").unwrap(),
    );
    let server = serve(router, true);

    for _ in 0..MAX_REGISTRATION_ATTEMPTS_PER_ADDRESS {
        assert_eq!(register(&server, None, Some("198.51.100.1")), 201);
    }
    assert_eq!(register(&server, None, Some("198.51.100.1")), 429);

    // A different client behind the same proxy is unaffected — without trusting the proxy,
    // the first client would have used up the whole instance's registrations.
    assert_eq!(register(&server, None, Some("198.51.100.2")), 201);

    // The limited client prepends a fresh address. The proxy appended the real one on the
    // right, and only that entry is believed.
    assert_eq!(register(&server, None, Some("203.0.113.77, 198.51.100.1")), 429);
}

#[test]
fn registration_without_a_visible_address_fails_closed() {
    // Served without connect info, the handler cannot tell who is asking. It must refuse
    // rather than register without a limit.
    let server = serve(cairn_server::http::router(instance(RegistrationPolicy::Open)), false);
    let status = register(&server, None, None);
    assert!(status >= 500, "registration with no address must not succeed; got {status}");
}
