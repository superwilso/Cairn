//! Spaces, channels and roles over a real socket.
//!
//! `CLAUDE.md`: both room bugs in this project's history looked fine in unit tests written
//! against the same wrong mental model, and were found by making the actual request. The
//! rules are tested in `state.rs`; this file attacks the HTTP boundary in front of them —
//! the signatures, the paths, the bodies, and the old room endpoints a channel must not be
//! reachable through.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;

use cairn_crypto::mls::Session;
use cairn_proto::{space_action, DeviceId, DeviceIdentity, Permissions, ResourceRef, UserId};
use cairn_server::state::{Instance, RegistrationPolicy};

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
        axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>())
            .await
            .unwrap();
    });
    Server { addr, instance, _runtime: runtime }
}

struct Response {
    status: u16,
    body: String,
}

impl Response {
    fn json(&self) -> serde_json::Value {
        serde_json::from_str(&self.body).unwrap_or(serde_json::Value::Null)
    }
}

/// Hand-rolled HTTP/1.1, as the other socket tests do.
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
    if !body.is_empty() || matches!(method, "POST" | "PUT" | "PATCH") {
        req.push_str("Content-Type: application/json\r\n");
        req.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    req.push_str("\r\n");
    req.push_str(body);
    stream.write_all(req.as_bytes()).unwrap();
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).unwrap();
    let raw = String::from_utf8_lossy(&raw).into_owned();
    let status = raw.split_whitespace().nth(1).and_then(|s| s.parse().ok()).expect("status");
    let body = raw.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
    Response { status, body }
}

struct Account {
    session: Session,
    user: UserId,
    device: DeviceId,
}

impl Account {
    fn register(server: &Server) -> Self {
        let (user, device) = (UserId::new(), DeviceId::new());
        let account = Self {
            session: Session::new(&DeviceIdentity::new(user, device).to_credential()).unwrap(),
            user,
            device,
        };
        server.instance.claim_account(user, device, account.session.public_key(), None, 0).unwrap();
        account
    }

    fn signed(&self, action: &str, resource: Option<ResourceRef>) -> Vec<(&'static str, String)> {
        let issued_at = now_ms();
        let bytes = cairn_proto::request_signing_bytes(action, resource, issued_at);
        let signature = self.session.sign(&bytes).unwrap();
        vec![
            ("x-cairn-device", self.device.as_uuid().to_string()),
            ("x-cairn-timestamp", issued_at.to_string()),
            ("x-cairn-signature", hex::encode(signature)),
        ]
    }

    fn space(
        &self,
        space: &str,
        verb: &str,
        targets: &[&uuid::Uuid],
    ) -> Vec<(&'static str, String)> {
        let id: cairn_proto::SpaceId = space.parse().unwrap();
        self.signed(&space_action(verb, targets), Some(id.into()))
    }
}

fn now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as i64
}

fn uuid_of(s: &str) -> uuid::Uuid {
    s.rsplit('_').next().unwrap().parse().unwrap()
}

/// A space with one private channel, an owner, and a plain member who joined by invite.
struct World {
    server: Server,
    owner: Account,
    member: Account,
    stranger: Account,
    space: String,
    channel: String,
}

fn world() -> World {
    let server = start();
    let owner = Account::register(&server);
    let member = Account::register(&server);
    let stranger = Account::register(&server);

    let r = request(
        server.addr,
        "POST",
        "/v1/spaces",
        &owner.signed("space.create", None),
        Some(r#"{"name":"Trailhead","member_ceiling":50}"#),
    );
    assert_eq!(r.status, 201, "{}", r.body);
    let space = r.json()["space"].as_str().unwrap().to_string();

    let r = request(
        server.addr,
        "POST",
        &format!("/v1/spaces/{space}/channels"),
        &owner.space(&space, "create_channel", &[]),
        Some(r#"{"name":"general"}"#),
    );
    assert_eq!(r.status, 201, "{}", r.body);
    assert_eq!(r.json()["tier"], "T2", "a private channel is end-to-end encrypted");
    let channel = r.json()["room"].as_str().unwrap().to_string();

    let r = request(
        server.addr,
        "POST",
        &format!("/v1/spaces/{space}/invites"),
        &owner.space(&space, "create_invite", &[]),
        Some(r#"{"uses":5}"#),
    );
    assert_eq!(r.status, 201, "{}", r.body);
    let token = r.json()["token"].as_str().unwrap().to_string();
    let r = request(
        server.addr,
        "POST",
        "/v1/space-invites/redeem",
        &member.signed("space.redeem_invite", None),
        Some(&serde_json::json!({ "token": token }).to_string()),
    );
    assert_eq!(r.status, 200, "{}", r.body);

    World { server, owner, member, stranger, space, channel }
}

fn read_channel(w: &World, who: &Account) -> u16 {
    let room: cairn_proto::RoomId = w.channel.parse().unwrap();
    request(
        w.server.addr,
        "GET",
        &format!("/v1/rooms/{}/messages", room.as_uuid()),
        &who.signed("read", Some(room.into())),
        None,
    )
    .status
}

#[test]
fn a_non_member_cannot_read_a_channel_over_http() {
    let w = world();
    assert_eq!(read_channel(&w, &w.member), 200, "the counterfactual: a member can");
    assert_eq!(read_channel(&w, &w.stranger), 403);
    let r = request(
        w.server.addr,
        "GET",
        &format!("/v1/spaces/{}", w.space),
        &w.stranger.space(&w.space, "describe", &[]),
        None,
    );
    assert_eq!(r.status, 403, "{}", r.body);
}

#[test]
fn a_channel_is_not_reachable_through_the_room_membership_endpoints() {
    let w = world();
    let room: cairn_proto::RoomId = w.channel.parse().unwrap();
    let path = |tail: &str| format!("/v1/rooms/{}{tail}", room.as_uuid());

    // The owner of the space adding a stranger at the room level.
    let r = request(
        w.server.addr,
        "POST",
        &path("/members"),
        &w.owner.signed("add_member", Some(room.into())),
        Some(&serde_json::json!({ "user": w.stranger.user.as_uuid() }).to_string()),
    );
    assert_eq!(r.status, 403, "{}", r.body);
    // A room invite that would bypass the space's bars and ceiling.
    let r = request(
        w.server.addr,
        "POST",
        &path("/invites"),
        &w.owner.signed("create_room_invite", Some(room.into())),
        Some(r#"{"uses":1}"#),
    );
    assert_eq!(r.status, 403, "{}", r.body);
    // Self-join.
    let r = request(
        w.server.addr,
        "POST",
        &path("/join"),
        &w.stranger.signed("join", Some(room.into())),
        None,
    );
    assert_eq!(r.status, 403, "{}", r.body);
    assert_eq!(read_channel(&w, &w.stranger), 403);
}

#[test]
fn a_member_without_permission_cannot_create_a_channel_or_hand_out_a_role_over_http() {
    let w = world();
    let r = request(
        w.server.addr,
        "POST",
        &format!("/v1/spaces/{}/channels", w.space),
        &w.member.space(&w.space, "create_channel", &[]),
        Some(r#"{"name":"mine"}"#),
    );
    assert_eq!(r.status, 403, "{}", r.body);

    let r = request(
        w.server.addr,
        "POST",
        &format!("/v1/spaces/{}/roles", w.space),
        &w.owner.space(&w.space, "create_role", &[]),
        Some(&format!(
            r#"{{"name":"mod","permissions":{},"position":5}}"#,
            Permissions::KICK.bits()
        )),
    );
    assert_eq!(r.status, 201, "{}", r.body);
    let role = r.json()["role"].as_str().unwrap().to_string();
    let role_uuid = uuid_of(&role);
    let me = *w.member.user.as_uuid();
    let r = request(
        w.server.addr,
        "PUT",
        &format!("/v1/spaces/{}/members/{me}/roles/{role_uuid}", w.space),
        &w.member.space(&w.space, "assign_role", &[&me, &role_uuid]),
        None,
    );
    assert_eq!(r.status, 403, "{}", r.body);
}

#[test]
fn a_signed_role_assignment_cannot_be_redirected_at_someone_else() {
    // The owner's signature for "give Bob this role", replayed with Mallory's id in the path.
    let w = world();
    let r = request(
        w.server.addr,
        "POST",
        &format!("/v1/spaces/{}/roles", w.space),
        &w.owner.space(&w.space, "create_role", &[]),
        Some(&format!(
            r#"{{"name":"mod","permissions":{},"position":5}}"#,
            Permissions::KICK.bits()
        )),
    );
    let role = uuid_of(r.json()["role"].as_str().unwrap());
    let bob = *w.member.user.as_uuid();
    let headers = w.owner.space(&w.space, "assign_role", &[&bob, &role]);

    let t = request(
        w.server.addr,
        "POST",
        "/v1/space-invites/redeem",
        &w.stranger.signed("space.redeem_invite", None),
        Some(&serde_json::json!({ "token": "nope-not-a-token" }).to_string()),
    );
    assert_eq!(t.status, 401);
    // Mallory in the space, so the only thing stopping the replay is the signature.
    let invite = w
        .server
        .instance
        .create_space_invite(w.space.parse().unwrap(), w.owner.user, 1, None)
        .unwrap();
    w.server.instance.redeem_space_invite(w.stranger.user, &invite, 0).unwrap();
    let mallory = *w.stranger.user.as_uuid();

    let r = request(
        w.server.addr,
        "PUT",
        &format!("/v1/spaces/{}/members/{mallory}/roles/{role}", w.space),
        &headers,
        None,
    );
    assert_eq!(r.status, 401, "a signature for Bob must not assign Mallory: {}", r.body);
    let r = request(
        w.server.addr,
        "PUT",
        &format!("/v1/spaces/{}/members/{bob}/roles/{role}", w.space),
        &headers,
        None,
    );
    assert_eq!(r.status, 204, "the counterfactual: it works for the target it names");
}

#[test]
fn nobody_escalates_past_their_own_rank_over_http() {
    let w = world();
    let s = &w.space;
    let mk = |name: &str, p: Permissions, pos: u32| {
        let r = request(
            w.server.addr,
            "POST",
            &format!("/v1/spaces/{s}/roles"),
            &w.owner.space(s, "create_role", &[]),
            Some(&format!(r#"{{"name":"{name}","permissions":{},"position":{pos}}}"#, p.bits())),
        );
        assert_eq!(r.status, 201, "{}", r.body);
        uuid_of(r.json()["role"].as_str().unwrap())
    };
    let moderator = mk("mod", Permissions::MANAGE_ROLES.union(Permissions::DEFAULT_EVERYONE), 5);
    let admin = mk("admin", Permissions::ALL, 10);
    let me = *w.member.user.as_uuid();
    let r = request(
        w.server.addr,
        "PUT",
        &format!("/v1/spaces/{s}/members/{me}/roles/{moderator}"),
        &w.owner.space(s, "assign_role", &[&me, &moderator]),
        None,
    );
    assert_eq!(r.status, 204, "{}", r.body);

    // Take the higher role.
    let r = request(
        w.server.addr,
        "PUT",
        &format!("/v1/spaces/{s}/members/{me}/roles/{admin}"),
        &w.member.space(s, "assign_role", &[&me, &admin]),
        None,
    );
    assert_eq!(r.status, 403, "{}", r.body);
    // Lift your own role over the one above it.
    let r = request(
        w.server.addr,
        "PATCH",
        &format!("/v1/spaces/{s}/roles/{moderator}"),
        &w.member.space(s, "edit_role", &[&moderator]),
        Some(r#"{"position":11}"#),
    );
    assert_eq!(r.status, 403, "{}", r.body);
    // Mint a role at your own rank carrying everything.
    let r = request(
        w.server.addr,
        "POST",
        &format!("/v1/spaces/{s}/roles"),
        &w.member.space(s, "create_role", &[]),
        Some(&format!(
            r#"{{"name":"me2","permissions":{},"position":4}}"#,
            Permissions::ALL.bits()
        )),
    );
    assert_eq!(r.status, 403, "{}", r.body);
    // Bits this build does not name.
    let r = request(
        w.server.addr,
        "POST",
        &format!("/v1/spaces/{s}/roles"),
        &w.member.space(s, "create_role", &[]),
        Some(r#"{"name":"x","permissions":2147483648,"position":1}"#),
    );
    assert_eq!(r.status, 400, "{}", r.body);
}

#[test]
fn a_kicked_member_loses_every_channel_and_cannot_rejoin_over_http() {
    let w = world();
    assert_eq!(read_channel(&w, &w.member), 200);
    // A link the member could have copied while they were in.
    let hoarded = w
        .server
        .instance
        .create_space_invite(w.space.parse().unwrap(), w.owner.user, 10, None)
        .unwrap();

    let target = *w.member.user.as_uuid();
    let r = request(
        w.server.addr,
        "DELETE",
        &format!("/v1/spaces/{}/members/{target}", w.space),
        &w.owner.space(&w.space, "kick", &[&target]),
        None,
    );
    assert_eq!(r.status, 204, "{}", r.body);

    assert_eq!(read_channel(&w, &w.member), 403);
    let r = request(
        w.server.addr,
        "POST",
        "/v1/space-invites/redeem",
        &w.member.signed("space.redeem_invite", None),
        Some(&serde_json::json!({ "token": hoarded }).to_string()),
    );
    assert_eq!(r.status, 401, "{}", r.body);
    assert_eq!(read_channel(&w, &w.member), 403);
}

#[test]
fn a_channels_tier_cannot_be_changed_over_http() {
    let w = world();
    let room: cairn_proto::RoomId = w.channel.parse().unwrap();
    let describe = || {
        request(
            w.server.addr,
            "GET",
            &format!("/v1/rooms/{}", room.as_uuid()),
            &w.owner.signed("describe", Some(room.into())),
            None,
        )
        .json()
    };
    assert_eq!(describe()["tier"], "T2");

    // A rename carrying the fields a tier is derived from. Refused outright, not ignored.
    let rid = *room.as_uuid();
    for body in [
        r#"{"name":"lobby","tier":"T3"}"#,
        r#"{"name":"lobby","public":true}"#,
        r#"{"name":"lobby","is_publicly_discoverable":true,"member_ceiling":50000}"#,
    ] {
        let r = request(
            w.server.addr,
            "PATCH",
            &format!("/v1/spaces/{}/channels/{rid}", w.space),
            &w.owner.space(&w.space, "rename_channel", &[&rid]),
            Some(body),
        );
        assert!((400..500).contains(&r.status), "{body} -> {} {}", r.status, r.body);
    }
    // Plaintext straight into the channel.
    let r = request(
        w.server.addr,
        "PATCH",
        &format!("/v1/spaces/{}/channels/{rid}", w.space),
        &w.owner.space(&w.space, "rename_channel", &[&rid]),
        Some(r#"{"name":"lobby"}"#),
    );
    assert_eq!(r.status, 204, "the counterfactual: a plain rename works");
    assert_eq!(describe()["tier"], "T2");
    assert_eq!(describe()["e2ee"], true);

    // And the space's view, which a client draws the badge next to, agrees.
    let r = request(
        w.server.addr,
        "GET",
        &format!("/v1/spaces/{}", w.space),
        &w.owner.space(&w.space, "describe", &[]),
        None,
    );
    let channels = r.json()["channels"].clone();
    assert_eq!(channels[0]["tier"], "T2", "{channels}");
    assert_eq!(channels[0]["name"], "lobby");
}
