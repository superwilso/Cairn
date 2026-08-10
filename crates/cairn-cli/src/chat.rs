//! A minimal interactive client — M2's "something a person who is not the author can use".
//!
//! Line-based rather than full-screen, and dependency-free on purpose: the point of M2 is
//! to make three protections *visible*, not to build the native client ADR-006 describes.
//! A curses UI would cost a dependency and several hundred lines without changing what the
//! user learns.
//!
//! ## What this exists to show
//!
//! Every design choice here follows from `docs/02-encryption-tiers.md` §4 and
//! `docs/01-threat-model.md` §4, which are normative:
//!
//! - **The tier badge is on every prompt and every message**, derived locally from the
//!   room's shape, never from what the instance says. A badge is a claim about who can read
//!   the message, and the only component that knows the answer is the one doing the
//!   encrypting.
//! - **The badge says when the transport is plaintext.** `T1` over `http://` means MLS is
//!   protecting content and nothing is protecting anything else. Rendering a lock there
//!   would be the exact false assurance the threat model forbids.
//! - **Safety numbers come from the group's roster** and are one command away. Until a
//!   user can compare one, a malicious server is unbounded — see
//!   `cairn_crypto::mls::GroupHandle::safety_number_with` for what went wrong when they
//!   came from anywhere else.
//! - **Membership changes are printed in the timeline as they arrive**, with the joiner's
//!   verification state. A silently added member is a wiretap.
//!
//! ## What it is not
//!
//! No history: messages arrive by polling and scroll past. A client that stored a decrypted
//! transcript would need to answer how that transcript is protected at rest, and
//! `cairn_crypto::store` already records that client state is written unencrypted. That
//! question deserves its own decision, not a default set here.

use std::io::{self, BufRead, Write};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use cairn_client_core::client::{Client, CreatedRoom};
use cairn_client_core::embed::{self, Card};
use cairn_client_core::transport::HttpTransport;
use cairn_client_core::{
    accept_welcome, ContactStore, Conversation, ConversationIndex, TimelineEvent,
};
use cairn_crypto::mls::{GroupMember, Session};
use cairn_crypto::verification::VerificationState;
use cairn_proto::{DeviceId, RoomId, RoomSeal, RoomShape, UserId};

type Fallible<T> = Result<T, Box<dyn std::error::Error>>;

fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

/// How the user asked to be identified, and where their state lives.
pub struct Options {
    pub server: String,
    pub dir: std::path::PathBuf,
    pub name: String,
    /// Registration invite, for an instance that is not open.
    ///
    /// Needed on first run only — once the account is claimed the token is spent, and a
    /// later run finds the account already claimed and carries on without one.
    pub invite: Option<String>,
}

impl Options {
    /// Parse `--server`, `--dir`, `--name`. Every one has a default that works.
    pub fn from_args(mut args: impl Iterator<Item = String>) -> Fallible<Self> {
        let mut server = "http://127.0.0.1:8080".to_string();
        let mut dir = None;
        let mut name = None;
        let mut invite = None;

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--server" => server = args.next().ok_or("--server needs a URL")?,
                "--dir" => dir = Some(args.next().ok_or("--dir needs a path")?),
                "--name" => name = Some(args.next().ok_or("--name needs a name")?),
                "--invite" => invite = Some(args.next().ok_or("--invite needs a token")?),
                other => return Err(format!("unknown argument {other}").into()),
            }
        }

        let name = name.unwrap_or_else(|| "me".to_string());
        let dir = dir.map_or_else(
            || std::env::temp_dir().join("cairn").join(&name),
            std::path::PathBuf::from,
        );
        Ok(Self { server, dir, name, invite })
    }
}

/// Everything one running client holds.
struct App {
    client: Client<HttpTransport>,
    session: Arc<Session>,
    index: ConversationIndex,
    contacts: ContactStore,
    /// The open conversation, if any. One at a time keeps the prompt honest: a badge can
    /// only describe the room it is next to.
    open: Option<Open>,
    identity: Vec<u8>,
    tls: bool,
}

struct Open {
    convo: Conversation,
    seal: RoomSeal,
    /// Last server sequence number seen, so polling does not re-read the room.
    cursor: u64,
}

/// Run the client until the user quits.
pub fn run(options: Options) -> Fallible<()> {
    let identity = format!("{}@{}", options.name, options.server).into_bytes();
    let session = Arc::new(Session::open(&options.dir, &identity)?);
    let transport = HttpTransport::new(&options.server);
    let tls = transport.is_tls();

    // Identity is per-directory, so a returning user must reuse their ids. Storing them
    // beside the group index keeps "who am I" and "what have I joined" in one place.
    let (user, device, already_claimed) = load_or_create_identity(&options.dir)?;
    let client = Client::new(transport, session.clone(), user, device);

    let mut app = App {
        client,
        session,
        index: ConversationIndex::open(&options.dir)?,
        contacts: ContactStore::open(&options.dir)?,
        open: None,
        identity,
        tls,
    };

    // Claim exactly once, ever, and record it locally.
    //
    // Not an optimisation. On an invite-only instance the server checks the invite before
    // it notices the account is already claimed, so a returning user re-running this gets
    // `401 registration requires an invite` and cannot get back into their own account.
    // Found by running it: the first version classified errors by substring, and the
    // server's rejection of a *spent* invite ("invite is unknown, already used, or
    // expired") contains the word "already" — so a spent token was read as "you are
    // already registered" and the client carried on with no account at all.
    if !already_claimed {
        match app.client.claim_account(options.invite.as_deref()) {
            Ok(()) => mark_claimed(&options.dir, user, device)?,
            Err(e) => {
                eprintln!("Could not register on {}: {e}", options.server);
                if options.invite.is_none() {
                    eprintln!(
                        "\nIf this instance is invite-only, ask its operator for a token and \n\
                         pass it with --invite <token>. Tokens are single-use."
                    );
                }
                return Err(e.into());
            }
        }
    }

    println!("Cairn — {}", options.server);
    if !tls {
        println!(
            "\n  !! This connection is plaintext http. Message *content* in a T1 or T2 room\n     \
             is still end-to-end encrypted, but who you talk to, when, and how often is\n     \
             visible to anyone on the path, and they can tamper with everything around the\n     \
             ciphertext. Use https for anything real."
        );
    }
    println!("\nYou are {}", String::from_utf8_lossy(&app.identity));
    println!("user id  {user}\n");
    help();

    let stdin = io::stdin();
    let mut lines = stdin.lock().lines();
    loop {
        app.poll();
        print!("{} ", app.prompt());
        io::stdout().flush()?;

        let Some(line) = lines.next() else { break };
        let line = line?;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        match app.dispatch(line) {
            Ok(true) => break,
            Ok(false) => {}
            Err(e) => println!("  ! {e}"),
        }
    }
    Ok(())
}

/// The user and device ids for this directory, minted on first run.
///
/// Kept next to the MLS state rather than derived from the name: a user id is claimed
/// once, and regenerating one each run would silently create a new account every time and
/// strand every room the old one was in.
fn load_or_create_identity(dir: &std::path::Path) -> Fallible<(UserId, DeviceId, bool)> {
    let path = dir.join("identity.json");
    if let Ok(bytes) = std::fs::read(&path) {
        let value: serde_json::Value = serde_json::from_slice(&bytes)?;
        let user: UserId = serde_json::from_value(value["user"].clone())?;
        let device: DeviceId = serde_json::from_value(value["device"].clone())?;
        let claimed = value["claimed"].as_bool().unwrap_or(false);
        return Ok((user, device, claimed));
    }

    let (user, device) = (UserId::new(), DeviceId::new());
    std::fs::create_dir_all(dir)?;
    std::fs::write(
        &path,
        serde_json::to_vec_pretty(&serde_json::json!({ "user": user, "device": device }))?,
    )?;
    Ok((user, device, false))
}

/// Remember that this account exists on the instance, so it is never claimed twice.
fn mark_claimed(dir: &std::path::Path, user: UserId, device: DeviceId) -> Fallible<()> {
    std::fs::write(
        dir.join("identity.json"),
        serde_json::to_vec_pretty(
            &serde_json::json!({ "user": user, "device": device, "claimed": true }),
        )?,
    )?;
    Ok(())
}

fn help() {
    println!("Commands:");
    println!("  /dm <@name|user-id>  start a direct message with someone");
    println!("  /new                 create an empty direct (T1) room");
    println!("  /rooms               list rooms this device knows");
    println!("  /open <room-id>      open a room already joined");
    println!(
        "  /add <@name|user-id> add someone to the open room
  /username <name>     claim your handle, so people can find you without a uuid"
    );
    println!("  /members             who is in the open room, and their verification state");
    println!("  /safety              safety numbers to compare out of band");
    println!("  /verify <n>          mark member n verified, having compared in person");
    println!("  /keys [count]        publish key packages so others can add you");
    println!("  /whoami              this device's ids");
    println!("  /help                this list");
    println!("  /quit");
    println!("\nAnything else is sent as a message.\n");
}

impl App {
    /// The badge. Present on every prompt, because a tier the user has to ask for is a
    /// tier they will assume.
    fn prompt(&self) -> String {
        let transport = if self.tls { "" } else { " plaintext-transport" };
        match &self.open {
            None => format!("[no room{transport}]>"),
            Some(open) => {
                let tier = open.seal.tier();
                let protection = if tier.is_e2ee() { "e2ee" } else { "server-readable" };
                let warn = if self.contacts.needing_attention().next().is_some() {
                    " !KEY-CHANGED"
                } else {
                    ""
                };
                format!(
                    "[{} {protection}{transport}{warn} {}]>",
                    tier.label(),
                    short(&open.convo.room().as_uuid().to_string())
                )
            }
        }
    }

    fn dispatch(&mut self, line: &str) -> Fallible<bool> {
        // Only a leading `/` makes a line a command. Splitting every line on its first
        // space and treating the head as the verb silently truncated messages at their
        // first space — "hello bob, this is a real socket" arrived as "hello", with no
        // error on either end. Found by running two clients against a server, not by any
        // test: every test sent a single word.
        if !line.starts_with('/') {
            return self.send(line).map(|()| false);
        }

        let (command, rest) = line.split_once(' ').unwrap_or((line, ""));
        let rest = rest.trim();

        match command {
            "/quit" | "/exit" => return Ok(true),
            "/help" => help(),
            "/whoami" => {
                println!("  identity {}", String::from_utf8_lossy(&self.identity));
                println!("  user     {}", self.client.user());
                println!("  device   {}", self.client.device());
            }
            "/keys" => {
                let count: usize = if rest.is_empty() { 5 } else { rest.parse()? };
                let remaining = self.client.publish_key_packages(count)?;
                println!("  published {count}; the instance now holds {remaining} for you");
            }
            "/new" => self.new_room()?,
            "/dm" => {
                let user = self.resolve(rest)?;
                self.direct_message(user)?
            }
            "/rooms" => self.list_rooms(),
            "/open" => self.open_room(rest.parse()?)?,
            "/add" => {
                let user = self.resolve(rest)?;
                self.add_member(user)?
            }
            "/username" => self.claim_username(rest)?,
            "/members" => self.list_members(),
            "/safety" => self.show_safety_numbers(),
            "/verify" => self.verify(rest.parse()?)?,
            other => println!("  ! unknown command {other}"),
        }
        Ok(false)
    }

    /// Accept either a raw user id or an `@handle`, so a person can be named the way they
    /// actually gave their details out.
    ///
    /// A handle is resolved against the instance, which means the instance decides who
    /// `@alice` is. That is not a new trust: it already holds every account and could
    /// substitute a key just as easily. It *is* a reason the safety-number check matters
    /// more once handles exist, because a handle is easier to mistype than a uuid and the
    /// user has less to compare against — so this prints what it resolved to.
    fn resolve(&self, input: &str) -> Fallible<cairn_proto::UserId> {
        let input = input.trim();
        if !input.starts_with('@') && input.starts_with("usr_") {
            return Ok(input.parse()?);
        }
        let name = cairn_proto::Username::parse(input)?;
        let user = self.client.lookup_username(&name)?;
        println!("  {name} is {user}");
        Ok(user)
    }

    /// Claim a handle for this account.
    fn claim_username(&self, input: &str) -> Fallible<()> {
        let name = cairn_proto::Username::parse(input)?;
        self.client.claim_username(&name)?;
        println!("  you are now {name}");
        println!("  it cannot be changed or released — tell people this, not your user id");
        Ok(())
    }

    /// Start a DM: create the room and add the other person, in one step.
    ///
    /// Composition of `/new` and `/add`, and deliberately nothing more — it introduces no
    /// new server call and no new authorization path. The two-step version stays because
    /// a room you create and populate later is a real case; this is for the common one.
    ///
    /// The result is a two-member T1 room, which is all a DM is in Cairn: there is no
    /// separate pairwise protocol, so a DM and a group chat share one code path and one
    /// set of bugs (ADR-002).
    fn direct_message(&mut self, peer: UserId) -> Fallible<()> {
        if peer == self.client.user() {
            return Err("that is your own user id".into());
        }
        self.new_room()?;
        self.add_member(peer)?;
        let room = self.open.as_ref().map(|open| open.convo.room());
        if let Some(room) = room {
            println!("  they should run: /open {room}");
            println!("  then both of you: /safety, and compare the numbers out of band");
        }
        Ok(())
    }

    fn new_room(&mut self) -> Fallible<()> {
        let shape =
            RoomShape { is_direct: true, is_publicly_discoverable: false, member_ceiling: 2 };
        let created: CreatedRoom = self.client.create_room(shape)?;
        let convo = Conversation::create_encrypted(
            created.seal,
            created.room,
            self.client.user(),
            self.client.device(),
            self.session.clone(),
        )?;

        self.index.record(created.room, &created.seal, convo.group_id())?;
        println!("  room {} created, tier {}", created.room, created.tier_label());
        self.open = Some(Open { convo, seal: created.seal, cursor: 0 });
        Ok(())
    }

    fn list_rooms(&self) {
        if self.index.rooms().next().is_none() {
            println!("  no rooms yet — /new creates one");
            return;
        }
        for (room, record) in self.index.rooms() {
            println!("  {} {}", record.tier.label(), room);
        }
    }

    /// Open a room, resuming its group if this device has one.
    ///
    /// A room that is recorded but has no group is one this device was added to and has not
    /// yet received the welcome for; polling picks it up.
    fn open_room(&mut self, room: RoomId) -> Fallible<()> {
        let seal = match self.index.get(&room) {
            Some(record) => RoomSeal::new(RoomShape {
                is_direct: record.tier == cairn_proto::Tier::Private,
                is_publicly_discoverable: !record.tier.is_e2ee(),
                member_ceiling: 2,
            })?,
            // Not recorded: this device was added by someone else. Assume the direct shape
            // and let the welcome confirm it — the tier is recorded only once, and
            // `ConversationIndex::record` refuses to change it afterwards.
            None => RoomSeal::new(RoomShape {
                is_direct: true,
                is_publicly_discoverable: false,
                member_ceiling: 2,
            })?,
        };

        let convo = match self.index.group_id(&room)? {
            Some(group_id) => Conversation::resume_encrypted(
                seal,
                room,
                self.client.user(),
                self.client.device(),
                self.session.clone(),
                &group_id,
            )?,
            None => {
                println!("  no group for this room yet; waiting for a welcome");
                self.index.record(room, &seal, None)?;
                let cursor = self.index.cursor(&room);
                self.open = Some(Open {
                    convo: Conversation::create_public(
                        RoomSeal::new(RoomShape {
                            is_direct: false,
                            is_publicly_discoverable: true,
                            member_ceiling: 2,
                        })?,
                        room,
                        self.client.user(),
                        self.client.device(),
                        self.session.clone(),
                    )?,
                    seal,
                    cursor,
                });
                return Ok(());
            }
        };

        println!("  opened {room} at tier {}", seal.tier().label());
        let cursor = self.index.cursor(&room);
        self.open = Some(Open { convo, seal, cursor });
        Ok(())
    }

    /// Add someone to the open room: server-side membership, then the MLS commit.
    ///
    /// The welcome travels through the room itself. Both halves are required — server
    /// membership without the MLS add leaves them unable to decrypt, and the MLS add
    /// without server membership leaves them unable to fetch.
    fn add_member(&mut self, user: UserId) -> Fallible<()> {
        let Some(open) = self.open.as_mut() else {
            return Err("open a room first".into());
        };

        self.client.add_room_member(open.convo.room(), user)?;
        let claimed = self.client.claim_key_packages(user)?;
        println!("  claimed {} key package(s) for {user}", claimed.len());

        for package in &claimed {
            let key_package =
                cairn_crypto::mls::parse_message(&hex::decode(&package.key_package)?)?;
            let group = open.convo.group_mut().ok_or("this room has no MLS group")?;
            let output = group.add_member(key_package)?;

            // The commit goes to existing members, the welcome to the newcomer. Both are
            // ordinary room traffic so the server sequences them with everything else.
            let commit = output.commit.to_bytes()?;
            self.client.send(open.convo.room(), &open.convo.wrap_handshake(&commit, now_ms())?)?;
            if let Some(welcome) = output.welcome {
                let bytes = welcome.to_bytes()?;
                self.client
                    .send(open.convo.room(), &open.convo.wrap_handshake(&bytes, now_ms())?)?;
            }
        }

        self.index.record(open.convo.room(), &open.seal, open.convo.group_id())?;
        println!("  added; they should see the room after their next poll");
        Ok(())
    }

    fn list_members(&mut self) {
        let Some(open) = self.open.as_ref() else {
            println!("  no room open");
            return;
        };
        let members = open.convo.members();
        if members.is_empty() {
            println!("  no MLS group yet");
            return;
        }
        let own = open.convo.own_member().ok();
        for (n, member) in members.iter().enumerate() {
            let you = own.as_ref().is_some_and(|o| o.index == member.index);
            println!(
                "  {n}. {} {}{}",
                label(member),
                state_marker(self.contacts.state_of(&member.identity)),
                if you { "  (you)" } else { "" }
            );
        }
    }

    /// Show a comparable number per peer.
    ///
    /// Pairwise, so a group of n has n-1 numbers. There is no single value that certifies
    /// a whole roster, and inventing one that looked like it did would be worse than the
    /// tedium of comparing several.
    fn show_safety_numbers(&mut self) {
        let Some(open) = self.open.as_ref() else {
            println!("  no room open");
            return;
        };
        let Ok(own) = open.convo.own_member() else {
            println!("  no MLS group yet");
            return;
        };

        println!("  Compare these aloud, in person or on a call the server cannot touch.");
        println!("  They are derived from the keys this group actually uses.\n");
        for (n, member) in open.convo.members().iter().enumerate() {
            if member.index == own.index {
                continue;
            }
            match open.convo.safety_number_with(member) {
                Ok(number) => {
                    println!(
                        "  {n}. {} {}",
                        label(member),
                        state_marker(self.contacts.state_of(&member.identity))
                    );
                    for chunk in number.as_str().split(' ').collect::<Vec<_>>().chunks(6) {
                        println!("     {}", chunk.join(" "));
                    }
                }
                Err(e) => println!("  {n}. {} — cannot compute: {e}", label(member)),
            }
        }
        println!("\n  If they match: /verify <n>. If they do not, stop and ask why.");
    }

    fn verify(&mut self, n: usize) -> Fallible<()> {
        let Some(open) = self.open.as_ref() else {
            return Err("no room open".into());
        };
        let members = open.convo.members();
        let member = members.get(n).ok_or("no member with that number")?;

        // Recording the sighting first means the fingerprint being marked verified is the
        // one from the roster, never one supplied from elsewhere.
        self.contacts.observe(member)?;
        if self.contacts.mark_verified(&member.identity)? {
            println!("  {} marked verified", label(member));
        } else {
            println!("  ! could not record that");
        }
        Ok(())
    }

    fn send(&mut self, text: &str) -> Fallible<()> {
        let Some(open) = self.open.as_mut() else {
            return Err("open a room first — /new or /open <room-id>".into());
        };
        if open.convo.group_id().is_none() {
            return Err("this room has no MLS group yet".into());
        }

        // The unfurl happens *here*, on the sender's device, and the finished card travels
        // inside the encrypted body. The server never sees the URL and the recipient never
        // contacts the site — see `docs/05-embeds.md`. A failure degrades to a bare link,
        // which is the last step of the fallback chain.
        let card = embed::first_url(text).and_then(|url| match embed::unfurl(url) {
            Ok(card) if card.is_useful() => Some(card),
            Ok(_) => None,
            Err(e) => {
                println!("  (no preview for {url}: {e})");
                None
            }
        });
        if let Some(card) = &card {
            println!("  (preview attached: {})", card.title.as_deref().unwrap_or(&card.url));
        }

        let sent = open.convo.send_with_card(text.as_bytes(), card, now_ms())?;
        let receipt = self.client.send(open.convo.room(), &sent.envelope)?;
        open.cursor = open.cursor.max(receipt.server_seq);
        self.index.advance(open.convo.room(), receipt.server_seq)?;
        Ok(())
    }

    /// Fetch and display anything new. Called before every prompt.
    fn poll(&mut self) {
        let Some(open) = self.open.as_mut() else { return };
        let room = open.convo.room();

        let fetched = match self.client.fetch_since(room, open.cursor) {
            Ok(fetched) => fetched,
            // A room this device was added to but has not joined can still refuse reads
            // until the server-side membership lands. Silent, because it resolves itself
            // and printing it every second would bury real output.
            Err(_) => return,
        };

        for message in fetched {
            open.cursor = open.cursor.max(message.server_seq);
            // Persisted as we go, not at the end: a crash mid-loop must not replay
            // messages whose keys MLS has already discarded.
            let _ = self.index.advance(room, message.server_seq);

            // Not yet in the group: the only envelope that can help is a welcome.
            if open.convo.group_id().is_none() {
                match accept_welcome(&self.session, &message.envelope) {
                    Ok(Some(group)) => {
                        let seal = open.seal;
                        let convo = Conversation::join_encrypted(
                            seal,
                            room,
                            self.client.user(),
                            self.client.device(),
                            self.session.clone(),
                            group,
                        );
                        match convo {
                            Ok(convo) => {
                                println!("\n  * joined this room; it is {}", seal.tier().label());
                                let _ = self.index.record(room, &seal, convo.group_id());
                                open.convo = convo;
                            }
                            Err(e) => println!("\n  ! could not join: {e}"),
                        }
                    }
                    Ok(None) => {}
                    Err(e) => println!("\n  ! malformed welcome: {e}"),
                }
                continue;
            }

            // A device does not receive its own messages back as readable traffic; MLS
            // cannot decrypt what this leaf encrypted.
            if message.envelope.sender_device == self.client.device() {
                continue;
            }

            match open.convo.receive(&message.envelope) {
                Ok(TimelineEvent::Message(received)) => {
                    println!(
                        "\n  [{}] {}: {}",
                        open.seal.tier().label(),
                        short(&message.envelope.sender.as_uuid().to_string()),
                        String::from_utf8_lossy(&received.body)
                    );
                    if let Some(card) = &received.card {
                        print_card(card);
                    }
                }
                Ok(TimelineEvent::Membership { added, removed, committer }) => {
                    announce(&mut self.contacts, &added, &removed, committer);
                }
                Ok(TimelineEvent::RemovedFromRoom { by }) => {
                    let who =
                        by.map_or_else(|| "Someone".to_string(), |index| format!("Member {index}"));
                    println!("\n  *** {who} REMOVED YOU from this room.");
                    println!("      You cannot read anything sent after this. Closing it.");
                    self.open = None;
                    return;
                }
                Ok(TimelineEvent::Nothing) => {}
                Err(e) => println!("\n  ! could not read a message: {e}"),
            }
        }
    }
}

/// Print a roster change, loudly enough that it is not mistaken for chat.
///
/// With each addition's verification state, because "someone joined" and "someone whose
/// key you have never checked joined" are different facts, and only the second tells the
/// user whether to care.
fn announce(
    contacts: &mut ContactStore,
    added: &[GroupMember],
    removed: &[GroupMember],
    committer: Option<u32>,
) {
    let by = committer.map_or_else(|| "someone".to_string(), |index| format!("member {index}"));

    for member in added {
        let _ = contacts.observe(member);
        println!(
            "\n  *** {by} ADDED {} {} — they can read everything sent from now on",
            label(member),
            state_marker(contacts.state_of(&member.identity))
        );
        println!("      /safety compares their key. Unexpected? Ask, out of band.");
    }
    for member in removed {
        println!("\n  *** {by} REMOVED {}", label(member));
    }
}

/// A member's identity as text, falling back to hex rather than replacement characters —
/// a mangled label is indistinguishable from a deliberately confusing one.
fn label(member: &GroupMember) -> String {
    String::from_utf8(member.identity.clone()).unwrap_or_else(|e| hex::encode(e.into_bytes()))
}

fn state_marker(state: VerificationState) -> &'static str {
    match state {
        VerificationState::Verified => "[verified]",
        VerificationState::Unverified => "[unverified]",
        VerificationState::ChangedSinceVerified => "[!! KEY CHANGED SINCE YOU VERIFIED]",
    }
}

fn short(id: &str) -> String {
    id.chars().take(8).collect()
}

/// Unused today; kept so the polling interval has one definition when a reader loop
/// replaces the poll-before-prompt model.
#[allow(dead_code)]
const POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Render a link card.
///
/// The framing is the security-relevant part, not the layout. `docs/05-embeds.md` §3: a
/// card produced on the sender's device is entirely the sender's output, and a modified
/// client can put a reputable outlet's name over any link. So:
///
/// - it is labelled as the *sender's* preview, with no language implying anyone checked it;
/// - the claimed source is prefixed `claims:`, never rendered as an attribution;
/// - **the real URL is always printed**, because it is the only part a recipient can judge;
/// - nothing is fetched to draw it, and no indicator is derived from its contents.
fn print_card(card: &Card) {
    println!("      ┌─ preview supplied by the sender, not verified");
    if let Some(title) = &card.title {
        println!("      │ {title}");
    }
    if let Some(description) = &card.description {
        println!("      │ {description}");
    }
    if let Some(source) = card.claimed_source() {
        println!("      │ claims: {source}");
    }
    // Always last and always present: the one checkable fact in the card.
    println!("      │ link: {}", card.url);
    if let Some(caveat) = card.source.caveat() {
        println!("      │ ! {caveat}");
    }
    println!("      └─");
}
