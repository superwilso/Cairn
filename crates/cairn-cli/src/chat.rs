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
use cairn_client_core::history::{Entry as HistoryEntry, History};
use cairn_client_core::transport::HttpTransport;
use cairn_client_core::verify;
use cairn_client_core::{
    accept_welcome, ContactStore, Conversation, ConversationIndex, TimelineEvent,
};
use cairn_crypto::mls::{GroupMember, Session};
use cairn_crypto::verification::VerificationState;
use cairn_proto::{DeviceId, DeviceIdentity, RoomId, RoomSeal, RoomShape, UserId};

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
        // The location comes from `client-core`, not from here. A UI choosing where the
        // device key lands is exactly what ADR-006 forbids, and this used to default to a
        // temp directory the OS deletes on reboot — taking the account with it.
        let dir = match dir {
            Some(explicit) => std::path::PathBuf::from(explicit),
            None => cairn_client_core::default_state_dir(&name)?,
        };
        cairn_client_core::statedir::prepare(&dir)?;

        // Anyone who ran an earlier build has state in the old temp location. Say so rather
        // than silently starting fresh, which looks exactly like a lost account — and rather
        // than migrating it, since a temp directory may already hold a partly-cleaned
        // identity and adopting half of one is worse than either.
        let legacy = cairn_client_core::statedir::legacy_temp_dir(&name);
        if legacy.exists() && legacy != dir {
            eprintln!("note: earlier state found at {}", legacy.display());
            eprintln!("      this build keeps state in {}", dir.display());
            eprintln!(
                "      the old location is a temp directory, cleared on reboot. Move it \
                 across if that account still matters, or delete it."
            );
        }
        Ok(Self { server, dir, name, invite })
    }
}

/// Everything one running client holds.
struct App {
    client: Client<HttpTransport>,
    session: Arc<Session>,
    index: ConversationIndex,
    contacts: ContactStore,
    history: History,
    /// The open conversation, if any. One at a time keeps the prompt honest: a badge can
    /// only describe the room it is next to.
    open: Option<Open>,
    identity: Vec<u8>,
    tls: bool,
    /// Where this client keeps its state; attachments land under it.
    dir: std::path::PathBuf,
}

struct Open {
    convo: Conversation,
    seal: RoomSeal,
    /// Last server sequence number seen, so polling does not re-read the room.
    cursor: u64,
    /// The safety numbers `/safety` last printed, by credential. `/verify` confirms one of
    /// *these* — never whatever the leaf holds at the moment the command is typed, which a
    /// commit arriving in between could have changed.
    shown: Vec<(Vec<u8>, String)>,
}

/// Run the client until the user quits.
pub fn run(options: Options) -> Fallible<()> {
    // Identity is per-directory, so a returning user must reuse their ids. Storing them
    // beside the group index keeps "who am I" and "what have I joined" in one place.
    //
    // Loaded *before* the session, because the MLS credential is now built from these ids
    // rather than from a display name. The old order could not have done that.
    let (user, device, already_claimed) = load_or_create_identity(&options.dir)?;

    // The credential names the account and device the server authenticates, not the name
    // this client was started with. Probing the old `name@server` form found that a member
    // could join a room presenting someone else's label — every client displayed her as
    // them, and MLS's duplicate-identity rule then locked the real person out of the room.
    let identity = DeviceIdentity::new(user, device).to_credential();
    let session = Arc::new(Session::open(&options.dir, &identity)?);
    let transport = HttpTransport::new(&options.server);
    let tls = transport.is_tls();
    let client = Client::new(transport, session.clone(), user, device);

    let mut app = App {
        client,
        session,
        index: ConversationIndex::open(&options.dir)?,
        contacts: ContactStore::open(&options.dir)?,
        history: History::open(&options.dir)?,
        open: None,
        identity,
        tls,
        dir: options.dir.clone(),
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
    // The name is a label for reading; the ids are what decide anything. Printing both,
    // in that order, is the same distinction the credential now makes — the old build
    // printed the credential itself here, which was a display name pretending to be an
    // identity.
    println!("\nYou are {} on this device", options.name);
    println!("user id   {user}");
    println!("device id {device}\n");
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
  /username <name>     claim your handle, so people can find you without a uuid
  /roster              server-side membership (who joined by invite, awaiting /admit)
  /admit               let everyone who joined by invite into the encrypted group
  /ttl <secs|off>      make messages in this room disappear after a while
  /send <path>         send a file, encrypted on this device before upload
  /invite [uses] [hrs] mint an invite link for the open room (default 1 use, 24h)
  /join <token>        redeem an invite"
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
            "/roster" => self.show_roster()?,
            "/admit" => self.admit_waiting()?,
            "/ttl" => self.set_ttl(rest)?,
            "/send" => self.send_file(rest)?,
            "/invite" => self.create_invite(rest)?,
            "/join" => self.join_by_invite(rest)?,
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

    /// Remember a message this device sent.
    ///
    /// MLS will not decrypt our own application messages back to us, so without this the
    /// stored transcript is half a conversation — every reply and none of the prompts.
    fn remember_own(
        &self,
        room: cairn_proto::RoomId,
        envelope: &cairn_proto::Envelope,
        body: &[u8],
        attachment_name: Option<String>,
    ) {
        let _ = self.history.append(
            room,
            &HistoryEntry {
                sender: envelope.sender,
                sent_at_ms: envelope.sent_at_ms,
                body: body.to_vec(),
                attachment_name,
                // The CLI writes the opened file to disk on receipt rather than keeping the
                // key to fetch it again, so there is nothing to remember here.
                attachment: None,
            },
        );
    }

    /// Print what this device remembers of a room, before any new messages arrive.
    ///
    /// Failure here is reported and then ignored. A transcript that cannot be read is worth
    /// saying out loud — it may be corruption — but it must not stop someone opening a room
    /// they can still use.
    fn replay_history(&self, room: cairn_proto::RoomId) {
        // The room's own timer governs the local copy too, so a disappearing message is not
        // quietly immortal on the one device its user controls.
        let ttl = self.client.room_ttl(room).unwrap_or(None);
        match self.history.replay(room, ttl, now_ms()) {
            Ok(entries) if entries.is_empty() => {}
            Ok(entries) => {
                println!("  --- {} remembered message(s) ---", entries.len());
                for entry in entries {
                    let body = String::from_utf8_lossy(&entry.body);
                    match entry.attachment_name {
                        Some(name) => println!(
                            "  [old] {}: {body} (attachment {name:?})",
                            short(&entry.sender.as_uuid().to_string())
                        ),
                        None => println!(
                            "  [old] {}: {body}",
                            short(&entry.sender.as_uuid().to_string())
                        ),
                    }
                }
                println!("  --- end of history ---");
            }
            Err(e) => println!("  ! stored history could not be read: {e}"),
        }
    }

    /// Set the room's disappearing-message timer. `/ttl 60` for a minute, `/ttl off`.
    fn set_ttl(&self, rest: &str) -> Fallible<()> {
        let room = self.open.as_ref().ok_or("open a room first")?.convo.room();
        let rest = rest.trim();
        let ttl = if rest.is_empty() || rest == "off" {
            None
        } else {
            Some(rest.parse::<i64>().map_err(|_| "usage: /ttl <seconds|off>")? * 1_000)
        };
        self.client.set_room_ttl(room, ttl)?;
        match ttl {
            Some(ms) => {
                println!("  messages in this room now disappear {}s after being sent", ms / 1_000);
                println!("  the timer runs from send, not from when anyone reads it");
            }
            None => println!("  disappearing messages are off for this room"),
        }
        Ok(())
    }

    /// Send a file. Sealed on this device; the instance stores bytes it cannot read.
    fn send_file(&mut self, rest: &str) -> Fallible<()> {
        let path = std::path::Path::new(rest.trim());
        let bytes =
            std::fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "attachment".into());

        let room = self.open.as_ref().ok_or("open a room first")?.convo.room();
        let (key, sealed) = cairn_crypto::attachment::seal(&bytes);
        let blob = self.client.upload_attachment(room, &sealed)?;

        let attachment = cairn_client_core::conversation::Attachment {
            blob,
            key,
            name: name.clone(),
            size: bytes.len(),
            // The CLI does not guess types. A recipient shows an untyped file as a download,
            // which is the safe reading of "unknown".
            mime: None,
        };

        let open = self.open.as_mut().expect("checked above");
        let out = open.convo.send_with_attachment(name.as_bytes(), attachment, now_ms())?;
        self.client.send(room, &out.envelope)?;
        self.remember_own(room, &out.envelope, name.as_bytes(), Some(name.clone()));
        println!("  sent {name} ({} bytes, encrypted before upload)", bytes.len());
        Ok(())
    }

    /// The room's **server-side** membership, which is not the MLS roster.
    ///
    /// The two diverge the moment someone joins by invite: the server admits them, and the
    /// encrypted group does not have them until a member runs `/add`. Listing them
    /// separately is the honest presentation — `/members` shows who can actually read the
    /// conversation, this shows who the instance will deliver to. Anyone here but not there
    /// is waiting to be let into the group.
    fn show_roster(&self) -> Fallible<()> {
        let room = self.open.as_ref().ok_or("open a room first")?.convo.room();
        let members = self.client.room_members(room)?;
        println!("  server-side membership of {room}:");
        for (user, role) in &members {
            println!("    {user} ({role})");
        }
        println!("  /members shows who is in the encrypted group — anyone listed here but");
        println!("  not there joined by invite and is waiting for /admit");
        Ok(())
    }

    /// Mint an invite for the open room. `/invite [uses] [hours]`, defaulting to one use
    /// and a day — the terms that make a leaked link least useful.
    fn create_invite(&self, rest: &str) -> Fallible<()> {
        let room = self.open.as_ref().ok_or("open a room first")?.convo.room();
        let mut parts = rest.split_whitespace();
        let uses: u32 = parts.next().unwrap_or("1").parse().unwrap_or(1);
        let hours: i64 = parts.next().unwrap_or("24").parse().unwrap_or(24);

        let expires = if hours > 0 { Some(now_ms() + hours * 3_600_000) } else { None };

        let token = self.client.create_room_invite(room, uses, expires)?;
        println!("  invite for {room}:");
        println!("    {token}");
        if hours > 0 {
            println!(
                "  admits {uses}, expires in {hours}h. Shown once — the server keeps only a hash."
            );
        } else {
            println!("  admits {uses}, never expires. Shown once — the server keeps only a hash.");
        }
        println!("  they run: /join <token>");
        Ok(())
    }

    /// Redeem an invite.
    ///
    /// Prints what redemption does *not* do, which matters more here than the success
    /// message. Joining the room server-side is not the same as being in its MLS group: the
    /// group's keys are held by its members, not the instance, so nobody can hand them out
    /// on the strength of a token. Until an existing member commits an Add, the room is
    /// visible and unreadable — and a client that implied otherwise would be claiming a
    /// protection had already been extended when it had not.
    fn join_by_invite(&self, rest: &str) -> Fallible<()> {
        let room = self.client.redeem_room_invite(rest.trim())?;
        println!("  joined {room}");
        println!("  publish key packages with /keys 5 if you have not — a member must still");
        println!("  add you to the encrypted group before you can read anything");
        Ok(())
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
        self.open = Some(Open { convo, seal: created.seal, cursor: 0, shown: Vec::new() });
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
                    shown: Vec::new(),
                });
                return Ok(());
            }
        };

        println!("  opened {room} at tier {}", seal.tier().label());
        self.replay_history(room);
        let cursor = self.index.cursor(&room);
        self.open = Some(Open { convo, seal, cursor, shown: Vec::new() });
        // Said on open rather than left to be discovered: someone who redeemed an invite is
        // sitting in a room they cannot read, and the only person who can fix that is
        // whoever opens it next.
        self.report_waiting();
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

    /// Accounts the instance lists as members that the encrypted group does not hold.
    ///
    /// This comparison is what the old display-name credential made impossible: the MLS
    /// roster carried labels a client chose for itself, so there was nothing to match the
    /// server's member list against. Now every leaf names its account.
    ///
    /// A leaf this build cannot attribute is treated as **matching nobody**, which is the
    /// safe direction: it may cause a redundant add attempt, where the opposite would
    /// silently treat an unknown leaf as covering an account and leave someone out.
    fn waiting_to_be_admitted(&self) -> Fallible<Vec<UserId>> {
        let Some(open) = self.open.as_ref() else {
            return Ok(Vec::new());
        };
        let in_group: Vec<UserId> = open
            .convo
            .members()
            .iter()
            .filter_map(|m| DeviceIdentity::parse(&m.identity).ok().map(|id| id.user()))
            .collect();

        Ok(self
            .client
            .room_members(open.convo.room())?
            .into_iter()
            .map(|(user, _role)| user)
            .filter(|user| !in_group.contains(user))
            .collect())
    }

    /// Tell the user who is waiting, if anyone is.
    fn report_waiting(&self) {
        let waiting = match self.waiting_to_be_admitted() {
            Ok(w) => w,
            // Not fatal: a failed lookup must not stop someone reading their messages.
            Err(e) => {
                println!("  (could not check who is waiting to join: {e})");
                return;
            }
        };
        if waiting.is_empty() {
            return;
        }
        println!(
            "\n  {} account(s) joined by invite and cannot read this room yet:",
            waiting.len()
        );
        for user in &waiting {
            println!("    {user}");
        }
        println!("  run /admit to let them into the encrypted group\n");
    }

    /// Add everyone the instance lists as a member but the group does not hold.
    ///
    /// **Deliberately one command rather than automatic**, and the distinction is the whole
    /// design. The list of who is waiting comes from the *instance*, so admitting on its
    /// word alone would let a malicious one name an account of its choosing and have a
    /// moderator's client hand it the group keys — silently. `cairn_crypto::mls` already
    /// notes that the server cannot add a leaf itself because it never sees group state;
    /// auto-admitting would give it that power back through the front door.
    ///
    /// So the friction this removes is the *uuid*, not the decision. Nobody pastes an id or
    /// coordinates out of band any more; a human still says yes, and the timeline still
    /// announces the join to every existing member.
    fn admit_waiting(&mut self) -> Fallible<()> {
        if self.open.is_none() {
            return Err("open a room first".into());
        }
        let waiting = self.waiting_to_be_admitted()?;
        if waiting.is_empty() {
            println!("  nobody is waiting; everyone the instance lists is already in the group");
            return Ok(());
        }

        for user in waiting {
            // Each admission is its own commit, so one account with no published key
            // packages does not block the rest. Reported rather than swallowed: a joiner
            // who never published cannot be added, and they need telling.
            match self.admit_one(user) {
                Ok(()) => println!("  admitted {user}"),
                Err(e) => println!("  could not admit {user}: {e}"),
            }
        }
        Ok(())
    }

    /// The MLS half of admitting one account that is already a server-side member.
    fn admit_one(&mut self, user: UserId) -> Fallible<()> {
        let open = self.open.as_mut().ok_or("open a room first")?;
        let claimed = self.client.claim_key_packages(user)?;

        for package in &claimed {
            let key_package =
                cairn_crypto::mls::parse_message(&hex::decode(&package.key_package)?)?;
            let group = open.convo.group_mut().ok_or("this room has no MLS group")?;
            let output = group.add_member(key_package)?;

            let commit = output.commit.to_bytes()?;
            self.client.send(open.convo.room(), &open.convo.wrap_handshake(&commit, now_ms())?)?;
            if let Some(welcome) = output.welcome {
                let bytes = welcome.to_bytes()?;
                self.client
                    .send(open.convo.room(), &open.convo.wrap_handshake(&bytes, now_ms())?)?;
            }
        }
        self.index.record(open.convo.room(), &open.seal, open.convo.group_id())?;
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
        // The store answers from what it last saw. Showing it the roster first means a key
        // substituted since then reads as changed, not as the verification it replaced.
        if let Err(e) = verify::observe_roster(&open.convo, &mut self.contacts) {
            println!("  ! could not update verification state: {e}");
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
        let Some(open) = self.open.as_mut() else {
            println!("  no room open");
            return;
        };
        let Ok(own) = open.convo.own_member() else {
            println!("  no MLS group yet");
            return;
        };
        if let Err(e) = verify::observe_roster(&open.convo, &mut self.contacts) {
            println!("  ! could not update verification state: {e}");
        }
        open.shown.clear();

        println!("  Compare these aloud, in person or on a call the server cannot touch.");
        println!("  They are derived from the keys this group actually uses.\n");
        for (n, member) in open.convo.members().iter().enumerate() {
            if member.index == own.index {
                continue;
            }
            match open.convo.safety_number_with(member) {
                Ok(number) => {
                    open.shown.push((member.identity.clone(), number.as_str().to_string()));
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

    /// Confirm the number `/safety` printed for member `n`.
    ///
    /// Goes through `cairn_client_core::verify`, the same rule the desktop uses: the number
    /// shown is handed back and checked against the leaf's number *now*. This used to mark
    /// whatever key sat at position `n` when the command ran — and the poll that runs before
    /// every prompt can land a commit between `/safety` and `/verify`, so the key certified
    /// could be one the user never compared.
    fn verify(&mut self, n: usize) -> Fallible<()> {
        let Some(open) = self.open.as_ref() else {
            return Err("no room open".into());
        };
        let members = open.convo.members();
        let member = members.get(n).ok_or("no member with that number")?;
        let Some((_, shown)) = open.shown.iter().find(|(id, _)| *id == member.identity) else {
            return Err("run /safety and compare the number first".into());
        };

        match verify::verify(&open.convo, &mut self.contacts, &member.identity, shown) {
            Ok(()) => println!("  {} marked verified", label(member)),
            Err(verify::VerifyError::NumberChanged) => {
                println!("  ! their safety number changed since /safety printed it.");
                println!("    Run /safety again and compare the new one.");
            }
            Err(e) => return Err(e.into()),
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
        let room = open.convo.room();
        let receipt = self.client.send(room, &sent.envelope)?;
        open.cursor = open.cursor.max(receipt.server_seq);
        self.index.advance(room, receipt.server_seq)?;
        self.remember_own(room, &sent.envelope, text.as_bytes(), None);
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
                    // Remembered before the attachment is fetched, so a failed download
                    // does not also lose the message it arrived with.
                    let _ = self.history.append(
                        message.envelope.room,
                        &HistoryEntry {
                            sender: message.envelope.sender,
                            sent_at_ms: message.envelope.sent_at_ms,
                            body: received.body.clone(),
                            attachment_name: received.attachment.as_ref().map(|a| a.name.clone()),
                            attachment: None,
                        },
                    );
                    if let Some(attachment) = &received.attachment {
                        // Fetched and opened here rather than announced and left: the key
                        // arrived inside this message and nothing else can open the blob, so
                        // deferring would mean holding a decryption key for a file the user
                        // may never ask for.
                        match fetch_attachment(&self.client, &self.dir, attachment) {
                            Ok(path) => println!("    attachment saved to {}", path.display()),
                            Err(e) => println!("    ! attachment could not be fetched: {e}"),
                        }
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

/// A member's identity, as something a person can compare against the roster.
///
/// The credential now carries the account and device rather than a name, so this shows the
/// account id — which is exactly the value `/roster` prints for server-side members, so the
/// two lists can be lined up by eye. That comparison is what the old display-name credential
/// made impossible.
///
/// A credential this build cannot parse is shown as hex and **named as unattributable**
/// rather than rendered as text. A leaf whose account nobody can determine is precisely the
/// thing that used to be displayed as a trustworthy-looking name.
fn label(member: &GroupMember) -> String {
    match DeviceIdentity::parse(&member.identity) {
        Ok(id) => format!("{} ({})", id.user(), short_device(id)),
        Err(_) => format!("unattributable leaf {}", hex::encode(&member.identity)),
    }
}

/// Enough of the device id to tell one of someone's devices from another.
fn short_device(id: DeviceIdentity) -> String {
    let full = id.device().to_string();
    full.chars().take(12).collect()
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

/// Download an attachment, open it, and write it under the client's directory.
///
/// The sender's filename is not used as a path. It is a label chosen by whoever sent the
/// message, so treating it as a location is a directory traversal waiting to happen — the
/// file lands under the blob id, and the claimed name is only printed.
fn fetch_attachment(
    client: &Client<HttpTransport>,
    dir: &std::path::Path,
    attachment: &cairn_client_core::conversation::Attachment,
) -> Fallible<std::path::PathBuf> {
    let sealed = client.download_attachment(attachment.blob)?;
    let plaintext = cairn_crypto::attachment::open(&attachment.key, &sealed)?;

    let downloads = dir.join("attachments");
    std::fs::create_dir_all(&downloads)?;
    let path = downloads.join(attachment.blob.as_uuid().to_string());
    std::fs::write(&path, &plaintext)?;
    println!(
        "    {} ({} bytes, sender calls it {:?})",
        attachment.blob,
        plaintext.len(),
        attachment.name
    );
    Ok(path)
}
