//! A stand-in for the Tauri shell, for `clients/desktop/tests/voice-channel.browser.test.js`.
//!
//! The browser test needs what the desktop app has behind `invoke`: a real `Session` per
//! person, a real MLS group, a real instance, a real SFU. This process is all of those, in
//! one place, and speaks line-delimited JSON on stdin/stdout so Node can forward each page's
//! `invoke` calls to the right person's session. Nothing here is a fake of the code under
//! test — the keys a page receives are derived by `cairn-client-core` from the group, and
//! the SFU is `cairn_server::sfu` on a real UDP socket.
//!
//! It also does the one thing the app must never be able to do: read the frames the SFU
//! forwarded (the `test-tap` feature) and try to open each under its sender's key with the
//! Rust reference implementation. That is how the test proves the SFU held ciphertext, and
//! that JavaScript and Rust agree on the frame format.
//!
//! Requests:  {"id": n, "op": "setup", "names": ["alice", "bob"]}
//!            {"id": n, "op": "invoke", "as": "alice", "cmd": "voice_state", "args": {}}
//!            {"id": n, "op": "tap"}
//!            {"id": n, "op": "remove", "as": "alice", "target": "bob"}
//! Responses: {"id": n, "ok": ...} or {"id": n, "err": "..."}; the first line is
//!            {"ready": {"http": "...", "sfu": "..."}}.

use std::collections::HashMap;
use std::io::{BufRead, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;

use cairn_client_core::session::Session;
use cairn_server::sfu::SfuConfig;
use cairn_server::state::{Instance, RegistrationPolicy};
use serde_json::{json, Value};

fn main() {
    let instance = Arc::new(Instance::in_memory());
    instance.set_registration_policy(RegistrationPolicy::Open).unwrap();
    let sfu_addr: SocketAddr = std::env::var("CAIRN_SFU_ADVERTISE")
        .unwrap_or_else(|_| "127.0.0.1:0".into())
        .parse()
        .expect("CAIRN_SFU_ADVERTISE");
    let sfu = instance.start_sfu(SfuConfig { bind: sfu_addr, advertise: sfu_addr }).expect("sfu");

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let http = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();
    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
    let router = cairn_server::http::router(Arc::clone(&instance));
    runtime.spawn(async move {
        let listener = tokio::net::TcpListener::from_std(listener).unwrap();
        axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>())
            .await
            .unwrap();
    });

    let base = format!("http://{http}");
    let scratch = std::env::temp_dir().join(format!("cairn-sfu-harness-{}", uuid::Uuid::new_v4()));
    let mut sessions: HashMap<String, Session> = HashMap::new();
    let mut room = String::new();

    let mut out = std::io::stdout();
    writeln!(out, "{}", json!({"ready": {"http": base, "sfu": sfu.local_addr().to_string()}}))
        .unwrap();
    out.flush().unwrap();

    for line in std::io::stdin().lock().lines() {
        let Ok(line) = line else { break };
        let Ok(req) = serde_json::from_str::<Value>(&line) else { continue };
        let id = req["id"].clone();
        let result: Result<Value, String> = match req["op"].as_str().unwrap_or("") {
            "setup" => setup(&req, &base, &scratch, &mut sessions, &mut room),
            "invoke" => invoke(&req, &mut sessions),
            "tap" => Ok(tap(&instance, &sfu, &sessions)),
            "tap_clear" => {
                sfu.clear_tap();
                Ok(Value::Null)
            }
            "remove" => remove(&req, &instance, &sessions, &room),
            other => Err(format!("unknown op {other}")),
        };
        let reply = match result {
            Ok(v) => json!({"id": id, "ok": v}),
            Err(e) => json!({"id": id, "err": e}),
        };
        writeln!(out, "{reply}").unwrap();
        out.flush().unwrap();
    }
    let _ = std::fs::remove_dir_all(&scratch);
}

/// One room, everyone in its MLS group, everyone with the room open.
fn setup(
    req: &Value,
    base: &str,
    scratch: &std::path::Path,
    sessions: &mut HashMap<String, Session>,
    room: &mut String,
) -> Result<Value, String> {
    let names: Vec<String> = req["names"]
        .as_array()
        .ok_or("names")?
        .iter()
        .filter_map(|n| n.as_str().map(String::from))
        .collect();
    let err = |e: cairn_client_core::session::SessionError| e.to_string();
    for name in &names {
        let dir = scratch.join(name);
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let s = Session::open(name, base, Some(&dir)).map_err(err)?;
        s.publish_key_packages(4).map_err(err)?;
        sessions.insert(name.clone(), s);
    }
    let owner = &names[0];
    *room = sessions.get_mut(owner).unwrap().create_group(50).map_err(err)?;
    for (i, name) in names.iter().enumerate().skip(1) {
        let token = sessions.get_mut(owner).unwrap().create_invite(1, 24).map_err(err)?;
        sessions.get_mut(name).unwrap().redeem_invite(&token).map_err(err)?;
        sessions.get_mut(owner).unwrap().admit_waiting().map_err(err)?;
        // Each new member must see the commit before the next is added.
        for other in &names[..=i] {
            let s = sessions.get_mut(other).unwrap();
            if s.open_room_id().as_deref() != Some(room.as_str()) {
                s.open_room(room).map_err(err)?;
            }
            for _ in 0..3 {
                s.poll().map_err(err)?;
            }
        }
    }
    let users: HashMap<&String, String> =
        names.iter().map(|n| (n, sessions[n].user_id())).collect();
    Ok(json!({"room": room, "users": users}))
}

fn invoke(req: &Value, sessions: &mut HashMap<String, Session>) -> Result<Value, String> {
    let who = req["as"].as_str().ok_or("as")?;
    let s = sessions.get_mut(who).ok_or("no such person")?;
    let args = &req["args"];
    let err = |e: cairn_client_core::session::SessionError| e.to_string();
    let to = |v: Result<Value, serde_json::Error>| v.map_err(|e| e.to_string());
    match req["cmd"].as_str().unwrap_or("") {
        "voice_join" => to(serde_json::to_value(
            s.voice_join(
                args["offer"].as_str().ok_or("offer")?,
                args["e2ee"].as_bool().unwrap_or(true),
            )
            .map_err(err)?,
        )),
        "voice_leave" => s.voice_leave().map(|_| Value::Null).map_err(err),
        "voice_state" => to(serde_json::to_value(s.voice_state().map_err(err)?)),
        "voice_keys" => to(serde_json::to_value(s.voice_keys().map_err(err)?)),
        "poll" => to(serde_json::to_value(s.poll().map_err(err)?)),
        "user_id" => Ok(json!(s.user_id())),
        other => Err(format!("the harness does not implement {other}")),
    }
}

/// What the SFU forwarded, per sender: how many frames, how many were sealed, and how many
/// open under that sender's key with the Rust implementation — plus the first plaintext's
/// Opus TOC byte, so "opened" means "opened into audio" and not "opened into anything".
fn tap(
    instance: &Instance,
    sfu: &cairn_server::sfu::Sfu,
    sessions: &HashMap<String, Session>,
) -> Value {
    let registry = instance.voice_registry();
    let mut by_device: HashMap<String, (String, cairn_crypto::media::MediaKey, u32)> =
        HashMap::new();
    for (name, s) in sessions {
        if let Ok(keys) = s.voice_keys() {
            if let Some(mine) = keys.keys.iter().find(|k| k.leaf == keys.me_leaf) {
                use base64::Engine as _;
                let raw = base64::engine::general_purpose::STANDARD.decode(&mine.key).unwrap();
                let key =
                    cairn_crypto::media::MediaKey::from_bytes_for_test(raw.try_into().unwrap());
                by_device.insert(mine.device.clone(), (name.clone(), key, keys.me_leaf));
            }
        }
    }
    let mut report: HashMap<String, Value> = HashMap::new();
    for frame in sfu.tapped() {
        let device = registry.lock().unwrap().occupant(frame.session).map(|o| o.device.to_string());
        let Some(device) = device else { continue };
        let Some((name, key, leaf)) = by_device.get(&device) else { continue };
        let entry = report.entry(name.clone()).or_insert_with(|| {
            json!({"frames": 0, "sealed": 0, "opened": 0, "leaf_matches": 0, "toc": null, "sample": null})
        });
        entry["frames"] = json!(entry["frames"].as_u64().unwrap() + 1);
        if let Ok(id) = cairn_crypto::media::peek(&frame.payload) {
            entry["sealed"] = json!(entry["sealed"].as_u64().unwrap() + 1);
            if id.leaf == *leaf {
                entry["leaf_matches"] = json!(entry["leaf_matches"].as_u64().unwrap() + 1);
            }
        } else {
            let unsealed = entry.as_object_mut().unwrap().entry("unsealed").or_insert(json!([]));
            let list = unsealed.as_array_mut().unwrap();
            if list.len() < 8 {
                list.push(json!(hex::encode(&frame.payload[..frame.payload.len().min(16)])));
            }
        }
        if let Ok((_, plain)) = cairn_crypto::media::open(key, &frame.payload) {
            entry["opened"] = json!(entry["opened"].as_u64().unwrap() + 1);
            if entry["toc"].is_null() && !plain.is_empty() {
                entry["toc"] = json!(plain[0]);
            }
        }
        if entry["sample"].is_null() {
            entry["sample"] = json!(hex::encode(&frame.payload[..frame.payload.len().min(24)]));
        }
    }
    json!(report)
}

fn remove(
    req: &Value,
    instance: &Instance,
    sessions: &HashMap<String, Session>,
    room: &str,
) -> Result<Value, String> {
    let actor: cairn_proto::UserId = sessions
        .get(req["as"].as_str().ok_or("as")?)
        .ok_or("as")?
        .user_id()
        .parse()
        .map_err(|_| "id")?;
    let target: cairn_proto::UserId = sessions
        .get(req["target"].as_str().ok_or("target")?)
        .ok_or("target")?
        .user_id()
        .parse()
        .map_err(|_| "id")?;
    let room: cairn_proto::RoomId = room.parse().map_err(|_| "room")?;
    instance.remove_room_member(room, actor, target).map_err(|e| e.to_string())?;
    Ok(Value::Null)
}
