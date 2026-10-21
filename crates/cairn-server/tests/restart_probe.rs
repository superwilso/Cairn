//! THROWAWAY PROBES: kill -9 the real server binary and real client processes, print what happens.

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use cairn_client_core::session::{Event, Session};

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("cairn-probe-{name}-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

struct Server {
    port: u16,
    data: PathBuf,
    child: Option<Child>,
    sfu: Option<u16>,
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

impl Server {
    fn start(data: &Path, sfu: bool) -> Self {
        let mut s = Server {
            port: free_port(),
            data: data.to_path_buf(),
            child: None,
            sfu: sfu.then(free_port),
        };
        s.boot();
        s
    }
    fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }
    fn boot(&mut self) {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_cairn-server"));
        cmd.env("CAIRN_DATA_DIR", &self.data)
            .env("CAIRN_BIND", format!("127.0.0.1:{}", self.port))
            .env("CAIRN_REGISTRATION_POLICY", "open")
            .env("RUST_LOG", "warn")
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        if let Some(p) = self.sfu {
            cmd.env("CAIRN_SFU_BIND", format!("127.0.0.1:{p}"));
            cmd.env("CAIRN_SFU_ADVERTISE", format!("127.0.0.1:{p}"));
        }
        let mut child = cmd.spawn().unwrap();
        let end = Instant::now() + Duration::from_secs(20);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                let mut err = String::new();
                use std::io::Read;
                child.stderr.take().unwrap().read_to_string(&mut err).unwrap();
                panic!("server exited at boot: {status} {err}");
            }
            if std::net::TcpStream::connect(("127.0.0.1", self.port)).is_ok() {
                break;
            }
            assert!(Instant::now() < end, "server did not come up");
            std::thread::sleep(Duration::from_millis(20));
        }
        self.child = Some(child);
    }
    fn kill9(&mut self) {
        let mut c = self.child.take().unwrap();
        c.kill().unwrap(); // SIGKILL on unix
        c.wait().unwrap();
    }
    fn restart(&mut self) {
        self.boot();
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

fn person(url: &str, name: &str, dir: &Path) -> Session {
    let s = Session::open(name, url, Some(dir)).unwrap();
    s.publish_key_packages(5).unwrap();
    s
}

fn group(owner: &mut Session, others: &mut [&mut Session]) -> String {
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

fn bodies(s: &mut Session, rounds: usize) -> Vec<String> {
    let mut out = Vec::new();
    for _ in 0..rounds {
        for e in s.poll().unwrap_or_default() {
            if let Event::Message(m) = e {
                out.push(m.body);
            }
        }
    }
    out
}

#[test]
fn probe_kill_server_during_sends() {
    let data = scratch("srv-sends");
    let mut server = Server::start(&data, false);
    let url = server.url();
    let mut alice = person(&url, "alice", &scratch("a"));
    let mut bob = person(&url, "bob", &scratch("b"));
    let _room = group(&mut alice, &mut [&mut bob]);

    let acked = Arc::new(Mutex::new(Vec::<String>::new()));
    let errors = Arc::new(Mutex::new(Vec::<String>::new()));
    let stop = Arc::new(AtomicBool::new(false));
    let worker = {
        let (acked, errors, stop) = (acked.clone(), errors.clone(), stop.clone());
        std::thread::spawn(move || {
            let mut i = 0;
            while !stop.load(Ordering::SeqCst) {
                let text = format!("m{i}");
                match alice.send(&text) {
                    Ok(_) => acked.lock().unwrap().push(text),
                    Err(e) => errors.lock().unwrap().push(e.to_string()),
                }
                i += 1;
            }
            alice
        })
    };
    std::thread::sleep(Duration::from_millis(800));
    server.kill9();
    std::thread::sleep(Duration::from_millis(300));
    server.restart();
    std::thread::sleep(Duration::from_millis(500));
    stop.store(true, Ordering::SeqCst);
    let mut alice = worker.join().unwrap();
    let acked = acked.lock().unwrap().clone();
    let errs = errors.lock().unwrap().clone();
    println!("PROBE sends: {} acked, {} errors, first error {:?}", acked.len(), errs.len(), errs.first());

    let heard = bodies(&mut bob, 6);
    let missing: Vec<_> = acked.iter().filter(|a| !heard.contains(a)).collect();
    println!("PROBE sends: bob heard {} of acked; missing {:?}", heard.len(), missing);
    let after = alice.send("after restart").is_ok();
    let heard2 = bodies(&mut bob, 3);
    println!("PROBE sends: alice can send after restart: {after}; bob reads it: {}", heard2.contains(&"after restart".to_string()));
}

#[test]
fn probe_kill_server_during_uploads_and_space_changes() {
    let data = scratch("srv-mixed");
    let mut server = Server::start(&data, false);
    let url = server.url();
    let mut alice = person(&url, "alice", &scratch("a2"));
    let mut bob = person(&url, "bob", &scratch("b2"));
    let _room = group(&mut alice, &mut [&mut bob]);

    let space = alice.create_space("S", None).unwrap();
    let tok = alice.create_space_invite(&space, 5, 24).unwrap();
    bob.redeem_space_invite(&tok).unwrap();
    let bob_id = bob.user_id();

    let acked_files = Arc::new(Mutex::new(Vec::<String>::new()));
    let acked_roles = Arc::new(Mutex::new(Vec::<String>::new()));
    let stop = Arc::new(AtomicBool::new(false));
    let a = {
        let (acked, stop) = (acked_files.clone(), stop.clone());
        std::thread::spawn(move || {
            let mut i = 0;
            while !stop.load(Ordering::SeqCst) {
                let name = format!("f{i}.bin");
                let bytes = vec![i as u8; 200_000];
                if alice.send_file(&name, "application/octet-stream", &bytes).is_ok() {
                    acked.lock().unwrap().push(name);
                }
                i += 1;
            }
            alice
        })
    };
    let owner2 = Session::open("alice", &url, None);
    let _ = owner2; // (sessions are not shareable across threads; roles via a second handle below)
    std::thread::sleep(Duration::from_millis(800));
    server.kill9();
    server.restart();
    std::thread::sleep(Duration::from_millis(500));
    stop.store(true, Ordering::SeqCst);
    let mut alice = a.join().unwrap();
    // Role changes with kill in the middle: issue them, killing between.
    let mut role_errs = 0;
    for i in 0..20 {
        match alice.create_role(&space, &format!("r{i}"), &["kick".into()], 1) {
            Ok(r) => {
                if alice.assign_role(&space, &bob_id, &r).is_ok() {
                    acked_roles.lock().unwrap().push(r);
                } else {
                    role_errs += 1
                }
            }
            Err(_) => role_errs += 1,
        }
        if i == 10 {
            server.kill9();
            server.restart();
        }
    }
    let files = acked_files.lock().unwrap().clone();
    println!("PROBE uploads: {} acked", files.len());
    let mut got = 0;
    let mut events = Vec::new();
    for _ in 0..6 {
        events.extend(bob.poll().unwrap_or_default());
    }
    for e in &events {
        if let Event::Message(m) = e {
            if let Some(att) = &m.attachment {
                if bob.fetch_attachment(&att.id).is_ok() {
                    got += 1;
                }
            }
        }
    }
    println!("PROBE uploads: bob fetched {got} attachments after restart");
    let view = alice.space(&space).unwrap();
    let roles = acked_roles.lock().unwrap().clone();
    println!("PROBE roles: {} acked ({} errs); space now {:?}", roles.len(), role_errs, format!("{view:?}").len());
    server.kill9();
    server.restart();
    let view2 = format!("{:?}", alice.space(&space).unwrap());
    let present = roles.iter().filter(|r| view2.contains(r.as_str())).count();
    println!("PROBE roles: after another restart {present} of {} acked roles present", roles.len());
}

#[test]
fn probe_voice_after_server_restart() {
    use str0m::media::{Direction, MediaKind};
    use str0m::{Candidate, RtcConfig};
    let data = scratch("srv-voice");
    let mut server = Server::start(&data, true);
    let url = server.url();
    let mut alice = person(&url, "alice", &scratch("a3"));
    let mut bob = person(&url, "bob", &scratch("b3"));
    let _room = group(&mut alice, &mut [&mut bob]);
    let offer = || {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut rtc = RtcConfig::new()
            .set_crypto_provider(Arc::new(str0m::crypto::from_feature_flags()))
            .clear_codecs()
            .enable_opus(true, false)
            .build(Instant::now());
        rtc.add_local_candidate(Candidate::host(socket.local_addr().unwrap(), "udp").unwrap());
        let mut api = rtc.sdp_api();
        api.add_media(MediaKind::Audio, Direction::SendOnly, Some("me".into()), None, None);
        let (offer, _p) = api.apply().unwrap();
        offer.to_sdp_string()
    };
    alice.voice_join(&offer(), true).unwrap();
    let st = alice.voice_state().unwrap();
    println!("PROBE voice before: joined {} participants {}", st.joined, st.participants.len());
    server.kill9();
    let during = alice.voice_state();
    println!("PROBE voice during outage: {:?}", during.as_ref().map(|s| s.joined).map_err(|e| e.to_string()));
    server.restart();
    let st = alice.voice_state().unwrap();
    println!(
        "PROBE voice after restart: joined {} (client thinks), participants on server {}",
        st.joined,
        st.participants.len()
    );
    let bob_view = bob.voice_state().unwrap();
    println!("PROBE voice after restart: bob sees {} participants", bob_view.participants.len());
}

/// Child mode: open a profile and send forever until killed.
#[test]
fn child_sender() {
    let Ok(spec) = std::env::var("CAIRN_PROBE_CHILD") else { return };
    let mut parts = spec.split('|');
    let (name, url, dir, room) =
        (parts.next().unwrap(), parts.next().unwrap(), parts.next().unwrap(), parts.next().unwrap());
    let mut s = Session::open(name, url, Some(Path::new(dir))).unwrap();
    s.open_room(room).unwrap();
    let mut i = 0;
    loop {
        let text = format!("c{i}");
        if s.send(&text).is_ok() {
            println!("ACK {text}");
        }
        i += 1;
    }
}

#[test]
fn probe_kill_client_mid_send() {
    let data = scratch("srv-client");
    let server = Server::start(&data, false);
    let url = server.url();
    let adir = scratch("a4");
    let mut alice = person(&url, "alice", &adir);
    let mut bob = person(&url, "bob", &scratch("b4"));
    let room = group(&mut alice, &mut [&mut bob]);
    drop(alice);
    let mut total_acked = 0;
    for round in 0..5 {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "child_sender", "--nocapture", "--test-threads=1"])
            .env("CAIRN_PROBE_CHILD", format!("alice|{url}|{}|{room}", adir.display()))
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        std::thread::sleep(Duration::from_millis(600 + round * 137));
        child.kill().unwrap();
        let out = child.wait_with_output().unwrap();
        let acks = String::from_utf8_lossy(&out.stdout).lines().filter(|l| l.starts_with("ACK")).count();
        total_acked += acks;
    }
    println!("PROBE client kill: child acked ~{total_acked} sends over 5 kills");
    let heard = bodies(&mut bob, 10);
    println!("PROBE client kill: bob decrypted {} messages", heard.len());
    let mut alice = Session::open("alice", &url, Some(&adir)).unwrap();
    alice.open_room(&room).unwrap();
    let ok = alice.send("alive after kills");
    let heard = bodies(&mut bob, 3);
    println!(
        "PROBE client kill: reopened alice send {:?}; bob reads it {}",
        ok.as_ref().map(|_| ()).map_err(|e| e.to_string()),
        heard.contains(&"alive after kills".to_string())
    );
    bob.send("bob to alice").unwrap();
    let a_heard = bodies(&mut alice, 3);
    println!("PROBE client kill: alice reads bob {}", a_heard.contains(&"bob to alice".to_string()));
}

/// One request per connection; when `drop_sends` is set, a POST to a room's messages is
/// swallowed and the connection closed — the server died before accepting it.
fn proxy(upstream: u16, drop_sends: Arc<AtomicBool>) -> u16 {
    use std::io::{Read, Write};
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for conn in l.incoming() {
            let Ok(mut c) = conn else { continue };
            let drop_sends = drop_sends.clone();
            std::thread::spawn(move || {
                let mut buf = Vec::new();
                let mut tmp = [0u8; 65536];
                let head_end = loop {
                    let n = match c.read(&mut tmp) { Ok(0) | Err(_) => return, Ok(n) => n };
                    buf.extend_from_slice(&tmp[..n]);
                    if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") { break p + 4; }
                };
                let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
                let len: usize = head.lines().find_map(|l| {
                    let l = l.to_ascii_lowercase();
                    l.strip_prefix("content-length:").map(|v| v.trim().parse().unwrap())
                }).unwrap_or(0);
                while buf.len() < head_end + len {
                    let n = match c.read(&mut tmp) { Ok(0) | Err(_) => return, Ok(n) => n };
                    buf.extend_from_slice(&tmp[..n]);
                }
                let first = head.lines().next().unwrap_or("").to_string();
                if drop_sends.load(Ordering::SeqCst) && first.starts_with("POST /v1/rooms/") && first.contains("/messages ") {
                    println!("PROXY dropped {first}");
                    return;
                }
                let head = head.replace("Connection: keep-alive", "Connection: close").replace("connection: keep-alive", "connection: close");
                let mut up = std::net::TcpStream::connect(("127.0.0.1", upstream)).unwrap();
                let mut req = if head.to_ascii_lowercase().contains("connection:") { head.into_bytes() } else {
                    head.replacen("\r\n\r\n", "\r\nConnection: close\r\n\r\n", 1).into_bytes()
                };
                req.extend_from_slice(&buf[head_end..]);
                up.write_all(&req).unwrap();
                let mut resp = Vec::new();
                let _ = up.read_to_end(&mut resp);
                let _ = c.write_all(&resp);
            });
        }
    });
    port
}

#[test]
fn probe_commit_lost_on_the_way_to_the_server() {
    let data = scratch("srv-commit");
    let server = Server::start(&data, false);
    let url = server.url();
    let flag = Arc::new(AtomicBool::new(false));
    let purl = format!("http://127.0.0.1:{}", proxy(server.port, flag.clone()));
    let mut alice = person(&purl, "alice", &scratch("a5"));
    let mut bob = person(&url, "bob", &scratch("b5"));
    let mut carol = person(&url, "carol", &scratch("c5"));
    let room = group(&mut alice, &mut [&mut bob]);
    let tok = alice.create_invite(1, 24).unwrap();
    carol.redeem_invite(&tok).unwrap();
    flag.store(true, Ordering::SeqCst);
    let r = alice.admit_waiting();
    flag.store(false, Ordering::SeqCst);
    println!("PROBE commit: admit with the commit lost -> {:?}", r.as_ref().map_err(|e| e.to_string()));
    println!("PROBE commit: alice waiting afterwards {:?}", alice.waiting().map_err(|e| e.to_string()));
    let r2 = alice.admit_waiting();
    println!("PROBE commit: second admit -> {:?}", r2.map_err(|e| e.to_string()));
    alice.send("after the lost commit").unwrap();
    let b = bodies(&mut bob, 3);
    println!("PROBE commit: bob reads alice afterwards: {}", b.contains(&"after the lost commit".to_string()));
    carol.open_room(&room).unwrap();
    let c = bodies(&mut carol, 3);
    println!("PROBE commit: carol reads alice afterwards: {}", c.contains(&"after the lost commit".to_string()));
    bob.send("bob speaks").unwrap();
    let a = bodies(&mut alice, 3);
    println!("PROBE commit: alice reads bob afterwards: {}", a.contains(&"bob speaks".to_string()));
}
