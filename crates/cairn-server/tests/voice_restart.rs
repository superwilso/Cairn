#![cfg(feature = "sfu")]
//! A voice seat across an instance restart.
//!
//! Seats live in the instance's memory, so a restart empties the voice channel. Found by a
//! probe that restarted a real instance under a seated client: the client went on reporting
//! itself as joined to a channel the instance no longer had it in, so the desktop app kept
//! a dead call open and never offered to rejoin.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use cairn_client_core::session::Session;
use cairn_server::sfu::{SfuConfig, RECEIVE_SLOTS};
use cairn_server::state::{Instance, RegistrationPolicy};
use cairn_server::storage::DbStorage;
use str0m::media::{Direction, MediaKind};
use str0m::{Candidate, RtcConfig};

/// One run of the instance over the state in `dir`, until the runtime is dropped.
fn serve(dir: &Path) -> (SocketAddr, tokio::runtime::Runtime) {
    let storage = Arc::new(DbStorage::new(dir).unwrap());
    let instance = Arc::new(Instance::open(storage).unwrap());
    instance.set_registration_policy(RegistrationPolicy::Open).unwrap();
    let local: SocketAddr = "127.0.0.1:0".parse().unwrap();
    instance.start_sfu(SfuConfig { bind: local, advertise: local }).unwrap();
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
    (addr, runtime)
}

/// A one-request-per-connection proxy whose upstream can be swapped, so a client keeps its
/// address across a restart that lands the instance on a new port.
fn proxy(upstream: Arc<Mutex<SocketAddr>>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(client) = conn else { continue };
            let to = *upstream.lock().unwrap();
            std::thread::spawn(move || relay(client, to));
        }
    });
    addr
}

fn relay(mut client: TcpStream, upstream: SocketAddr) {
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
    let head = head.replacen("\r\n\r\n", "\r\nConnection: close\r\n\r\n", 1);
    let Ok(mut up) = TcpStream::connect(upstream) else { return };
    let _ = up.write_all(head.as_bytes());
    let _ = up.write_all(&buf[head_end..]);
    let mut response = Vec::new();
    let _ = up.read_to_end(&mut response);
    let _ = client.write_all(&response);
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("cairn-vrestart-{name}-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// An SDP offer shaped like the desktop app's, good enough for the SFU to seat it.
fn offer() -> String {
    let mut rtc = RtcConfig::new()
        .set_crypto_provider(Arc::new(str0m::crypto::from_feature_flags()))
        .clear_codecs()
        .enable_opus(true, false)
        .build(Instant::now());
    rtc.add_local_candidate(Candidate::host("127.0.0.1:9".parse().unwrap(), "udp").unwrap());
    let mut api = rtc.sdp_api();
    api.add_media(MediaKind::Audio, Direction::SendOnly, Some("me".into()), None, None);
    for _ in 0..RECEIVE_SLOTS {
        api.add_media(MediaKind::Audio, Direction::RecvOnly, None, None, None);
    }
    let (offer, _pending) = api.apply().unwrap();
    offer.to_sdp_string()
}

#[test]
fn a_restarted_instance_does_not_leave_a_client_believing_it_is_seated() {
    let state = scratch("server");
    let (first, runtime) = serve(&state);
    let upstream = Arc::new(Mutex::new(first));
    let url = format!("http://{}", proxy(Arc::clone(&upstream)));

    let mut alice = Session::open("alice", &url, Some(&scratch("alice"))).unwrap();
    alice.publish_key_packages(3).unwrap();
    alice.create_group(10).unwrap();
    alice.voice_join(&offer(), true).unwrap();
    assert!(alice.voice_state().unwrap().joined, "seated before the restart");

    // The process dies and comes back from disk. Seats were only ever in memory.
    runtime.shutdown_timeout(std::time::Duration::from_secs(5));
    let (second, _runtime) = serve(&state);
    *upstream.lock().unwrap() = second;

    let after = alice.voice_state().unwrap();
    assert!(after.available, "the restarted instance still runs an SFU");
    assert!(
        after.participants.iter().all(|p| !p.me),
        "the instance does not list this device, so nothing should claim it is in the channel"
    );
    assert!(!after.joined, "the client must find out its seat is gone, so the app can rejoin");

    // And rejoining works, rather than tripping over the seat the client remembered.
    alice.voice_join(&offer(), true).unwrap();
    let rejoined = alice.voice_state().unwrap();
    assert!(rejoined.joined && rejoined.participants.iter().any(|p| p.me));
}
