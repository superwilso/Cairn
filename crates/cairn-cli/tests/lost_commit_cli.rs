//! `cairn-cli` admitting someone while the commit is lost on its way to the instance.
//!
//! Found by a probe that ran the real binary through a proxy dropping one upload. The CLI
//! applied its commit before sending it, so a lost upload moved the owner into an epoch
//! nobody else reached: the joiner was never welcomed, and `/admit` then reported nobody
//! waiting, because the owner's own roster already listed them. The room was unusable for
//! good. The desktop client had the same fault and was fixed first; this is the CLI's half.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use cairn_server::state::{Instance, RegistrationPolicy};

fn start() -> SocketAddr {
    let instance = Arc::new(Instance::in_memory());
    instance.set_registration_policy(RegistrationPolicy::Open).unwrap();
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
    // The runtime must outlive the clients; the test process ends first.
    std::mem::forget(runtime);
    addr
}

/// A one-request-per-connection proxy that drops the next message upload when `lose` is set.
fn proxy(upstream: SocketAddr, lose: Arc<AtomicBool>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(client) = conn else { continue };
            let lose = lose.clone();
            std::thread::spawn(move || relay(client, upstream, &lose));
        }
    });
    addr
}

fn relay(mut client: TcpStream, upstream: SocketAddr, lose: &AtomicBool) {
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
    let first = head.lines().next().unwrap_or_default();
    let upload = first.starts_with("POST /v1/rooms/") && first.contains("/messages ");
    if upload && lose.swap(false, Ordering::SeqCst) {
        return;
    }
    let head = head.replacen("\r\n\r\n", "\r\nConnection: close\r\n\r\n", 1);
    let mut up = TcpStream::connect(upstream).unwrap();
    up.write_all(head.as_bytes()).unwrap();
    up.write_all(&buf[head_end..]).unwrap();
    let mut response = Vec::new();
    let _ = up.read_to_end(&mut response);
    let _ = client.write_all(&response);
}

/// The real `cairn-cli chat`, driven a line at a time.
struct Cli {
    child: Child,
    stdin: ChildStdin,
    out: Arc<Mutex<String>>,
}

impl Cli {
    fn start(name: &str, server: SocketAddr) -> Self {
        let dir: PathBuf =
            std::env::temp_dir().join(format!("cairn-cli-lost-{name}-{}", uuid::Uuid::new_v4()));
        let mut child = Command::new(env!("CARGO_BIN_EXE_cairn-cli"))
            .args(["chat", "--server", &format!("http://{server}"), "--name", name])
            .arg("--dir")
            .arg(&dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take().unwrap();
        let out = Arc::new(Mutex::new(String::new()));
        for mut stream in [
            Box::new(child.stdout.take().unwrap()) as Box<dyn Read + Send>,
            Box::new(child.stderr.take().unwrap()),
        ] {
            let out = out.clone();
            std::thread::spawn(move || {
                let mut chunk = [0u8; 4096];
                while let Ok(n) = stream.read(&mut chunk) {
                    if n == 0 {
                        break;
                    }
                    out.lock().unwrap().push_str(&String::from_utf8_lossy(&chunk[..n]));
                }
            });
        }
        Self { child, stdin, out }
    }

    /// Type `line`, and return what the client printed until `until` appeared in it.
    fn run(&mut self, line: &str, until: &str) -> String {
        let mark = self.out.lock().unwrap().len();
        writeln!(self.stdin, "{line}").unwrap();
        self.stdin.flush().unwrap();
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let seen = self.out.lock().unwrap()[mark..].to_string();
            if seen.contains(until) {
                return seen;
            }
            assert!(Instant::now() < deadline, "after {line:?}, never saw {until:?}; got:\n{seen}");
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for Cli {
    fn drop(&mut self) {
        let _ = self.child.kill();
    }
}

#[test]
fn a_lost_admit_commit_does_not_leave_the_cli_owner_alone_in_its_group() {
    let server = start();
    let lose = Arc::new(AtomicBool::new(false));
    let mut alice = Cli::start("alice", proxy(server, lose.clone()));
    let mut bob = Cli::start("bob", server);

    alice.run("/keys 5", "published");
    bob.run("/keys 5", "published");
    alice.run("/new", "created");
    let invite = alice.run("/invite 1 24", "they run");
    let room = invite.split("invite for ").nth(1).unwrap().split(':').next().unwrap().to_owned();
    let token = invite
        .lines()
        .map(str::trim)
        .find(|l| l.len() == 64 && l.chars().all(|c| c.is_ascii_hexdigit()))
        .unwrap()
        .to_owned();
    bob.run(&format!("/join {token}"), "joined");
    bob.run(&format!("/open {room}"), "waiting for a welcome");

    // The commit admitting Bob never reaches the instance. The poll after the command reads
    // the whole log without it, so it never landed, and it is dropped.
    lose.store(true, Ordering::SeqCst);
    let lost = alice.run("/admit", "]> ");
    assert!(lost.contains("could not admit"), "the upload failed:\n{lost}");

    // Bob is still waiting, and admitting him again works.
    let again = alice.run("/admit", "]> ");
    assert!(again.contains("admitted"), "bob was never added, so he must still wait:\n{again}");
    bob.run("", "joined this room");
    alice.run("hello after a lost commit", "]> ");
    bob.run("", "hello after a lost commit");
}
