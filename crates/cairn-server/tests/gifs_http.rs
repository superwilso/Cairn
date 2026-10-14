//! The GIF relay, over real sockets, against a stand-in provider speaking real TLS.
//!
//! `docs/14-gifs.md` is the design: searches tunnel through the instance with TLS running
//! from the client to the provider, and a sent GIF travels as an encrypted attachment. The
//! unit tests in `gif_relay.rs` hold the rules; these hold the plumbing to them, and try the
//! attacks a relay invites — chiefly, using it as an open proxy into the instance's network.
//!
//! The provider here is a TLS server on loopback with a certificate for the real providers'
//! names, issued by a throwaway CA in `fixtures/gif-provider/` that only these tests trust.
//! (The CA and leaf were made with `openssl req`/`x509` for one hundred years; the key is a
//! test fixture and protects nothing.) The instance's `with_upstream_override` sends every
//! approved tunnel to it, while the allowlist still applies to the name the client asked
//! for — so the rules under test are the production ones.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use cairn_client_core::gifs::GifError;
use cairn_client_core::session::{AttachmentKind, Event, Session, SessionError};
use cairn_proto::{DeviceId, UserId};
use cairn_server::gif_relay::{GifProvider, GifRelayConfig};
use cairn_server::state::{Instance, RegistrationPolicy};

const CA: &[u8] = include_bytes!("fixtures/gif-provider/ca.der");
const LEAF: &[u8] = include_bytes!("fixtures/gif-provider/leaf.der");
const LEAF_KEY: &[u8] = include_bytes!("fixtures/gif-provider/leaf.key.der");

const KLIPY_KEY: &str = "klipy-test-key";
const GIPHY_KEY: &str = "giphyTestKey123";

// ---- the stand-in provider ---------------------------------------------------

/// What the provider saw: per request, the TLS server name and the request path.
#[derive(Default)]
struct Seen {
    requests: Mutex<Vec<(String, String)>>,
    connections: AtomicUsize,
}

struct Provider {
    addr: SocketAddr,
    seen: Arc<Seen>,
}

fn webp(tag: &str) -> Vec<u8> {
    let mut b = b"RIFF\0\0\0\0WEBPVP8 ".to_vec();
    b.extend(tag.as_bytes());
    b.extend((0..2048u32).map(|i| (i % 251) as u8));
    b
}

fn gif(tag: &str) -> Vec<u8> {
    let mut b = b"GIF89a".to_vec();
    b.extend(tag.as_bytes());
    b.extend((0..2048u32).map(|i| (i % 241) as u8));
    b
}

fn klipy_item(slug: &str, host: &str) -> serde_json::Value {
    let r = |size: &str, fmt: &str| {
        serde_json::json!({ "url": format!("https://{host}/media/{slug}-{size}.{fmt}?cid=keep"),
                            "width": 220, "height": 160, "size": 4000 })
    };
    serde_json::json!({
        "id": 42, "slug": slug, "title": format!("{slug} wave"), "type": "gif",
        "file": {
            "md": { "gif": r("md", "gif"), "webp": r("md", "webp") },
            "sm": { "gif": r("sm", "gif"), "webp": r("sm", "webp") }
        }
    })
}

fn klipy_page() -> Vec<u8> {
    serde_json::json!({ "result": true, "data": { "data": [
        klipy_item("hello", "static.klipy.com"),
        // An ad, as KLIPY documents them: HTML to render. Must never reach a picker.
        { "type": "ad", "content": "<div onclick=\"track()\">Buy now</div>", "width": 300, "height": 250 },
        // A result whose media sits somewhere the instance does not relay. Dropped by the
        // client; and the instance would refuse the tunnel anyway.
        klipy_item("elsewhere", "evil.example"),
        // Bytes that are not an image. Listed, but neither previewable nor sendable.
        klipy_item("svg", "static1.klipy.com"),
    ], "has_next": false }})
    .to_string()
    .into_bytes()
}

fn giphy_page() -> Vec<u8> {
    serde_json::json!({ "data": [{
        "type": "gif", "id": "cat1", "title": "Cat GIF",
        "images": {
            "fixed_width_small": { "url": "https://media1.giphy.com/media/cat-100w.gif", "width": "100", "height": "75",
                                   "webp": "https://media1.giphy.com/media/cat-100w.webp", "webp_size": "3000" },
            "original": { "url": "https://media2.giphy.com/media/cat.gif", "width": "480", "height": "360",
                          "webp": "https://media2.giphy.com/media/cat.webp", "webp_size": "4000" },
            "downsized": { "url": "https://media2.giphy.com/media/cat-downsized.gif", "size": "4000" }
        }
    }], "meta": { "status": 200 } })
    .to_string()
    .into_bytes()
}

/// What the provider answers. API responses go out chunked and media with a length, so the
/// client's reader is exercised on both framings.
fn answer(path: &str) -> (u16, &'static str, Vec<u8>, bool) {
    let json = "application/json";
    if path.starts_with("/api/v1/") {
        if !path.starts_with(&format!("/api/v1/{KLIPY_KEY}/")) {
            return (401, json, b"{\"result\":false}".to_vec(), true);
        }
        return (200, json, klipy_page(), true);
    }
    if path.starts_with("/v1/gifs/") {
        if !path.contains(&format!("api_key={GIPHY_KEY}&")) {
            return (401, json, b"{\"meta\":{\"status\":401}}".to_vec(), true);
        }
        return (200, json, giphy_page(), true);
    }
    let file = path.split('?').next().unwrap_or("");
    if file.contains("svg") {
        return (
            200,
            "image/webp",
            b"<svg xmlns='http://www.w3.org/2000/svg' onload='alert(1)'/>".to_vec(),
            false,
        );
    }
    if file.ends_with(".webp") {
        return (200, "image/webp", webp(file), false);
    }
    if file.ends_with(".gif") {
        return (200, "image/gif", gif(file), false);
    }
    (404, "text/plain", b"not found".to_vec(), false)
}

fn serve_provider_connection(tcp: TcpStream, config: Arc<rustls::ServerConfig>, seen: Arc<Seen>) {
    tcp.set_read_timeout(Some(std::time::Duration::from_secs(30))).unwrap();
    let conn = rustls::ServerConnection::new(config).unwrap();
    let mut tls = BufReader::new(rustls::StreamOwned::new(conn, tcp));
    loop {
        let mut head = Vec::new();
        loop {
            let before = head.len();
            match tls.read_until(b'\n', &mut head) {
                Ok(0) | Err(_) => return,
                Ok(_) => {}
            }
            if &head[before..] == b"\r\n" {
                break;
            }
        }
        let text = String::from_utf8_lossy(&head).into_owned();
        let path = text.split_whitespace().nth(1).unwrap_or("").to_string();
        let sni = tls.get_ref().conn.server_name().unwrap_or("").to_string();
        seen.requests.lock().unwrap().push((sni, path.clone()));

        let (status, kind, body, chunked) = answer(&path);
        let mut out =
            format!("HTTP/1.1 {status} X\r\nContent-Type: {kind}\r\nConnection: keep-alive\r\n")
                .into_bytes();
        if chunked {
            out.extend(b"Transfer-Encoding: chunked\r\n\r\n");
            for piece in body.chunks(700) {
                out.extend(format!("{:x}\r\n", piece.len()).as_bytes());
                out.extend(piece);
                out.extend(b"\r\n");
            }
            out.extend(b"0\r\n\r\n");
        } else {
            out.extend(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
            out.extend(&body);
        }
        let stream = tls.get_mut();
        if stream.write_all(&out).and_then(|()| stream.flush()).is_err() {
            return;
        }
    }
}

fn start_provider() -> Provider {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![rustls::pki_types::CertificateDer::from(LEAF.to_vec())],
            rustls::pki_types::PrivateKeyDer::Pkcs8(LEAF_KEY.to_vec().into()),
        )
        .unwrap();
    let config = Arc::new(config);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = Arc::new(Seen::default());
    let for_thread = Arc::clone(&seen);
    std::thread::spawn(move || {
        for tcp in listener.incoming().flatten() {
            for_thread.connections.fetch_add(1, Ordering::SeqCst);
            let (config, seen) = (Arc::clone(&config), Arc::clone(&for_thread));
            std::thread::spawn(move || serve_provider_connection(tcp, config, seen));
        }
    });
    Provider { addr, seen }
}

// ---- the instance ------------------------------------------------------------

struct Server {
    addr: SocketAddr,
    instance: Arc<Instance>,
    _runtime: tokio::runtime::Runtime,
}

fn start(gifs: Option<GifRelayConfig>) -> Server {
    let instance = Arc::new(Instance::in_memory());
    instance.set_registration_policy(RegistrationPolicy::Open).unwrap();
    instance.set_gif_relay(gifs);
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

fn both_providers(upstream: SocketAddr) -> GifRelayConfig {
    GifRelayConfig::new()
        .with_provider(GifProvider::Klipy, KLIPY_KEY)
        .unwrap()
        .with_provider(GifProvider::Giphy, GIPHY_KEY)
        .unwrap()
        .with_upstream_override(upstream)
}

fn scratch(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("cairn-gif-{name}-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn session(server: &Server, name: &str) -> Session {
    Session::open(name, &format!("http://{}", server.addr), Some(&scratch(name))).unwrap()
}

fn trusting_test_ca(session: &mut Session) {
    session.gifs().unwrap().trust_provider_roots_for_tests(&[CA.to_vec()]).unwrap();
}

// ---- what a member sees --------------------------------------------------------

#[test]
fn with_no_provider_configured_the_picker_is_told_so() {
    let server = start(None);
    let mut alice = session(&server, "unconfigured");
    let gifs = alice.gifs().unwrap();
    assert!(gifs.providers().unwrap().is_empty(), "no key must mean no providers");
    assert!(matches!(gifs.search("klipy", "cats"), Err(GifError::NotConfigured)));
}

#[test]
fn both_providers_are_offered_with_their_attribution_rules() {
    let provider = start_provider();
    let server = start(Some(both_providers(provider.addr)));
    let mut alice = session(&server, "offered");
    let offered = alice.gifs().unwrap().providers().unwrap();
    let ids: Vec<_> = offered.iter().map(|p| p.id.as_str()).collect();
    assert_eq!(ids, ["klipy", "giphy"]);
    assert_eq!(offered[0].placeholder, "Search KLIPY");
    assert_eq!(offered[1].attribution.as_deref(), Some("Powered by GIPHY"));
}

#[test]
fn a_search_reaches_the_provider_through_the_relay_and_ads_never_arrive() {
    let provider = start_provider();
    let server = start(Some(both_providers(provider.addr)));
    let mut alice = session(&server, "search");
    trusting_test_ca(&mut alice);
    let gifs = alice.gifs().unwrap();

    let results = gifs.search("klipy", "eye roll & sigh").unwrap();
    let titles: Vec<_> = results.iter().map(|r| r.title.as_str()).collect();
    assert_eq!(titles, ["hello wave", "svg wave"], "the ad and the off-list host are gone");

    let requests = provider.seen.requests.lock().unwrap().clone();
    let (sni, path) = &requests[0];
    assert_eq!(sni, "api.klipy.com", "TLS was to the provider's own name, end to end");
    assert!(
        path.starts_with(&format!("/api/v1/{KLIPY_KEY}/gifs/search?q=eye%20roll%20%26%20sigh&")),
        "{path}"
    );

    let preview = gifs.preview(&results[0].id).unwrap();
    assert_eq!(preview.mime, "image/webp");
    assert!(preview.bytes.windows(17).any(|w| w == b"/media/hello-sm.w"), "the small rendition");
    let last = provider.seen.requests.lock().unwrap().last().cloned().unwrap();
    assert_eq!(last.0, "static.klipy.com");
    assert!(last.1.ends_with("?cid=keep"), "the provider's URL is used as given: {}", last.1);

    // A provider that labels non-image bytes an image is not believed.
    assert!(matches!(gifs.preview(&results[1].id), Err(GifError::NotAnImage)));

    // GIPHY, trending (an empty query), through the same relay.
    let trending = gifs.search("giphy", "").unwrap();
    assert_eq!(trending.len(), 1);
    assert_eq!((trending[0].width, trending[0].height), (100, 75));
    let giphy_path = provider.seen.requests.lock().unwrap().last().cloned().unwrap().1;
    assert!(
        giphy_path.starts_with(&format!("/v1/gifs/trending?api_key={GIPHY_KEY}&")),
        "{giphy_path}"
    );
    assert_eq!(gifs.preview(&trending[0].id).unwrap().mime, "image/webp");

    // Ids are this session's own. A frontend cannot name a URL, or a result it never got.
    assert!(matches!(gifs.preview("https://static.klipy.com/x.gif"), Err(GifError::UnknownGif)));
    assert!(matches!(gifs.preview("gif-999999"), Err(GifError::UnknownGif)));
}

#[test]
fn tunnels_are_reused_rather_than_opened_per_image() {
    let provider = start_provider();
    let server = start(Some(both_providers(provider.addr)));
    let mut alice = session(&server, "pool");
    trusting_test_ca(&mut alice);
    let gifs = alice.gifs().unwrap();
    let results = gifs.search("klipy", "").unwrap();
    for _ in 0..5 {
        gifs.preview(&results[0].id).unwrap();
    }
    // One tunnel to the API host and one to the media host, however many requests.
    assert_eq!(provider.seen.connections.load(Ordering::SeqCst), 2);
}

#[test]
fn the_client_checks_the_providers_certificate_through_the_relay() {
    // Without the test CA, the stand-in is just a server with a certificate nobody vouched
    // for — which is what an instance answering in the provider's place would be. The
    // client must refuse it: that check is the whole of "the instance cannot read the
    // search".
    let provider = start_provider();
    let server = start(Some(both_providers(provider.addr)));
    let mut alice = session(&server, "untrusted");
    let err = alice.gifs().unwrap().search("klipy", "cats").unwrap_err();
    assert!(matches!(err, GifError::Tls(_)), "{err}");
    assert!(
        provider.seen.requests.lock().unwrap().is_empty(),
        "no request may cross unverified TLS"
    );
}

#[test]
fn a_wrong_key_is_reported_as_the_operators_problem_not_a_crash() {
    let provider = start_provider();
    let config = GifRelayConfig::new()
        .with_provider(GifProvider::Klipy, "revoked-key")
        .unwrap()
        .with_upstream_override(provider.addr);
    let server = start(Some(config));
    let mut alice = session(&server, "badkey");
    trusting_test_ca(&mut alice);
    let err = alice.gifs().unwrap().search("klipy", "cats").unwrap_err();
    assert!(matches!(err, GifError::Provider { status: 401, .. }), "{err}");
    assert!(err.to_string().contains("API key"), "{err}");
}

#[test]
fn a_sent_gif_reaches_the_recipient_as_an_encrypted_attachment_not_a_link() {
    let provider = start_provider();
    let server = start(Some(both_providers(provider.addr)));
    let mut alice = session(&server, "send-alice");
    let mut bob = session(&server, "send-bob");
    bob.publish_key_packages(3).unwrap();
    let room = alice.create_group(10).unwrap();
    let token = alice.create_invite(1, 24).unwrap();
    bob.redeem_invite(&token).unwrap();
    alice.admit_waiting().unwrap();
    bob.open_room(&room).unwrap();
    bob.poll().unwrap();

    trusting_test_ca(&mut alice);
    let results = alice.gifs().unwrap().search("giphy", "cat").unwrap();
    let sent = alice.send_gif(&results[0].id).unwrap();
    let mine = sent.attachment.expect("a GIF is sent as an attachment");
    assert_eq!(mine.kind, AttachmentKind::Image);
    assert_eq!(mine.mime, "image/webp", "the original rendition's WebP was chosen");
    assert_eq!(mine.name, "Cat GIF.webp");

    let provider_requests_before = provider.seen.requests.lock().unwrap().len();
    let mut got = None;
    for _ in 0..10 {
        for event in bob.poll().unwrap() {
            if let Event::Message(m) = event {
                got = got.or(m.attachment);
            }
        }
    }
    let got = got.expect("bob receives the GIF");
    assert_eq!(got.kind, AttachmentKind::Image);
    let bytes = bob.fetch_attachment(&got.id).unwrap();
    assert_eq!(bytes, webp("/media/cat.webp"), "the provider's bytes, opened from the instance");
    assert_eq!(
        provider.seen.requests.lock().unwrap().len(),
        provider_requests_before,
        "the recipient must contact the provider not at all"
    );

    // And the instance holds ciphertext: the GIF's bytes appear nowhere in what it stored.
    let blob: cairn_proto::BlobId = got.id.parse().unwrap();
    let alice_user: UserId = alice.user_id().parse().unwrap();
    let stored = server.instance.fetch_blob(alice_user, blob).unwrap();
    let needle = &bytes[bytes.len() - 64..];
    assert!(!stored.windows(64).any(|w| w == needle), "the instance must not hold the plaintext");
}

#[test]
fn a_gif_that_is_not_an_image_is_never_sent() {
    let provider = start_provider();
    let server = start(Some(both_providers(provider.addr)));
    let mut alice = session(&server, "svg-alice");
    alice.create_group(10).unwrap();
    trusting_test_ca(&mut alice);
    let results = alice.gifs().unwrap().search("klipy", "x").unwrap();
    let svg = results.iter().find(|r| r.title == "svg wave").unwrap();
    let err = alice.send_gif(&svg.id).unwrap_err();
    assert!(matches!(err, SessionError::Gif(GifError::NotAnImage)), "{err}");
}

// ---- attacks on the relay itself ------------------------------------------------

/// A registered device that signs whatever action a probe needs — including ones an honest
/// client never would.
struct Prober {
    mls: cairn_crypto::mls::Session,
    device: DeviceId,
}

impl Prober {
    fn register(server: &Server) -> Self {
        let p = Self {
            mls: cairn_crypto::mls::Session::new(b"prober").unwrap(),
            device: DeviceId::new(),
        };
        server
            .instance
            .claim_account(UserId::new(), p.device, p.mls.public_key(), None, 0)
            .unwrap();
        p
    }

    fn headers(&self, action: &str) -> Vec<(&'static str, String)> {
        let issued_at =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis()
                as i64;
        let bytes = cairn_proto::request_signing_bytes(action, None, issued_at);
        vec![
            ("x-cairn-device", self.device.as_uuid().to_string()),
            ("x-cairn-timestamp", issued_at.to_string()),
            ("x-cairn-signature", hex::encode(self.mls.sign(&bytes).unwrap())),
        ]
    }
}

/// Ask for a tunnel and return the status, leaving the socket open if it upgraded.
fn ask_tunnel(
    server: &Server,
    path: &str,
    headers: &[(&str, String)],
    upgrade: bool,
) -> (u16, TcpStream) {
    let mut stream = TcpStream::connect(server.addr).unwrap();
    stream.set_read_timeout(Some(std::time::Duration::from_secs(15))).unwrap();
    let mut req = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n");
    if upgrade {
        req.push_str("Connection: Upgrade\r\nUpgrade: cairn-gif-tunnel\r\n");
    }
    for (name, value) in headers {
        req.push_str(&format!("{name}: {value}\r\n"));
    }
    req.push_str("\r\n");
    stream.write_all(req.as_bytes()).unwrap();
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if stream.read(&mut byte).unwrap() == 0 {
            break;
        }
        head.push(byte[0]);
    }
    let text = String::from_utf8_lossy(&head);
    let status =
        text.split_whitespace().nth(1).and_then(|s| s.parse().ok()).expect("a status line");
    (status, stream)
}

#[test]
fn the_relay_cannot_be_used_to_reach_anything_but_the_providers() {
    // Probe: with an honest signature for each target, ask the relay for everything an
    // attacker inside an instance would want — the instance itself, its neighbours, cloud
    // metadata, the provider on other ports, encodings of the provider's name. Every one is
    // refused before anything is dialled: the stand-in provider, which every approved tunnel
    // is routed to, must see no connection at all.
    let provider = start_provider();
    let server = start(Some(both_providers(provider.addr)));
    let prober = Prober::register(&server);
    let own_port = server.addr.port();
    let targets = [
        format!("127.0.0.1:{own_port}"),
        "127.0.0.1:443".into(),
        "localhost:443".into(),
        "[::1]:443".into(),
        "169.254.169.254:443".into(),
        "169.254.169.254:80".into(),
        "10.0.0.1:443".into(),
        "metadata.google.internal:443".into(),
        "api.klipy.com:80".into(),
        "api.klipy.com:22".into(),
        "api.klipy.com:6379".into(),
        "api.klipy.com".into(),
        "api.klipy.com.:443".into(),
        "api.klipy.com.evil.example:443".into(),
        "evil.example:443".into(),
        "klipy.com:443".into(),
        "api.klipy.com%2F..%2F127.0.0.1:443".into(),
        "api.klipy.com%00:443".into(),
        "user%40api.klipy.com:443".into(),
        "api.klipy.com:443%23".into(),
        "api.klipy.com:0443".into(),
    ];
    for target in &targets {
        let action = format!("gif_tunnel:{}", percent_decode(target));
        let (status, _) = ask_tunnel(
            &server,
            &format!("/v1/gifs/tunnel/{target}"),
            &prober.headers(&action),
            true,
        );
        assert!(matches!(status, 403 | 404), "{target} must be refused, got {status}");
    }
    assert_eq!(provider.seen.connections.load(Ordering::SeqCst), 0, "nothing may be dialled");

    // The honest target, for contrast: it upgrades, and the stand-in sees one connection.
    let (status, _open) = ask_tunnel(
        &server,
        "/v1/gifs/tunnel/api.klipy.com:443",
        &prober.headers("gif_tunnel:api.klipy.com:443"),
        true,
    );
    assert_eq!(status, 101);
    for _ in 0..50 {
        if provider.seen.connections.load(Ordering::SeqCst) == 1 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert_eq!(provider.seen.connections.load(Ordering::SeqCst), 1);
}

/// Axum decodes the path parameter, and the signature is over what it decoded to.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 3 <= bytes.len() {
            if let Ok(b) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(b);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[test]
fn a_tunnel_needs_a_signature_for_exactly_its_own_target() {
    let provider = start_provider();
    let server = start(Some(both_providers(provider.addr)));
    let prober = Prober::register(&server);

    // Unsigned.
    let (status, _) = ask_tunnel(&server, "/v1/gifs/tunnel/api.klipy.com:443", &[], true);
    assert_eq!(status, 401);
    // Signed for one host, presented for another: the target is inside the signature.
    let (status, _) = ask_tunnel(
        &server,
        "/v1/gifs/tunnel/static.klipy.com:443",
        &prober.headers("gif_tunnel:api.klipy.com:443"),
        true,
    );
    assert_eq!(status, 401);
    // Signed for the capability endpoint, presented to the tunnel.
    let (status, _) = ask_tunnel(
        &server,
        "/v1/gifs/tunnel/api.klipy.com:443",
        &prober.headers("gif_capability"),
        true,
    );
    assert_eq!(status, 401);
    // Properly signed, but not asking to upgrade: told how, and nothing is dialled.
    let (status, _) = ask_tunnel(
        &server,
        "/v1/gifs/tunnel/api.klipy.com:443",
        &prober.headers("gif_tunnel:api.klipy.com:443"),
        false,
    );
    assert_eq!(status, 426);
    assert_eq!(provider.seen.connections.load(Ordering::SeqCst), 0);
    // The capability, keys and all, is for accounts on this instance only.
    let (status, _) = ask_tunnel(&server, "/v1/gifs", &[], false);
    assert_eq!(status, 401);
}

#[test]
fn a_relay_with_no_provider_configured_opens_nothing() {
    let provider = start_provider();
    let server = start(None);
    let prober = Prober::register(&server);
    let (status, _) = ask_tunnel(
        &server,
        "/v1/gifs/tunnel/api.klipy.com:443",
        &prober.headers("gif_tunnel:api.klipy.com:443"),
        true,
    );
    assert_eq!(status, 404);
    assert_eq!(provider.seen.connections.load(Ordering::SeqCst), 0);
}
