//! A whole client session, assembled once and reused by every frontend.
//!
//! ## Why this exists rather than living in the UI
//!
//! Everything a client needs — the network client, the MLS session, the room index, the
//! contact store, the local transcript — has to be wired together in the right order, and
//! getting that order wrong is not a visible failure. The device key must load before the
//! MLS credential is built from it; a room's group id must be recorded or the room cannot be
//! resumed; a cursor must advance or messages repeat.
//!
//! `cairn-cli` does that assembly inline, mixed with terminal printing. A desktop client
//! doing its own copy would be the "five clients, five sets of security bugs" outcome
//! [ADR-006](../../../docs/adr/006-platform-architecture.md) was written against — and
//! [ADR-008](../../../docs/adr/008-client-architecture.md) kept that rule when it replaced
//! five native UIs with one web client.
//!
//! So the assembly lives here, below the FFI line, and a frontend calls plain methods that
//! take and return plain data. **No caller of this module ever constructs an envelope,
//! decides a tier, or touches a key.**
//!
//! ## Group chats
//!
//! [`Session::create_group`] is the reason this landed when it did: the CLI could only ever
//! make a two-person room — `is_direct: true, member_ceiling: 2` was hardcoded — so a group
//! conversation was not reachable from any client. A group room is `is_direct: false` and
//! not publicly discoverable, which `derive_tier` seals as **T2, still end-to-end
//! encrypted**. Nothing about a group weakens the encryption; only *discoverability* does.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use cairn_crypto::mls::Session as MlsSession;
use cairn_crypto::verification::VerificationState;
use cairn_proto::{DeviceId, DeviceIdentity, RoomId, RoomSeal, RoomShape, Tier, UserId};

use crate::call::{CallSignal, SignalKind};
use crate::client::{Client, ClientError};
use crate::contacts::{ContactError, ContactStore};
use crate::conversation::{Conversation, ConversationError, TimelineEvent};
use crate::history::{Entry as HistoryEntry, History, HistoryError};
use crate::statedir::{self, StateDirError};
use crate::store::{ConversationIndex, IndexError};
use crate::transport::HttpTransport;
use crate::verify::{self, SafetyView, VerifyError};

mod attachments;
pub use attachments::{
    kind_of, normalize_mime, safe_file_name, AttachmentKind, AttachmentView, PendingDownload,
    PendingUpload, UploadedAttachment, MAX_ATTACHMENT_BYTES, SEAL_OVERHEAD,
};

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error(transparent)]
    Client(#[from] ClientError),
    #[error(transparent)]
    Conversation(#[from] ConversationError),
    #[error(transparent)]
    Index(#[from] IndexError),
    #[error(transparent)]
    Contacts(#[from] ContactError),
    #[error(transparent)]
    History(#[from] HistoryError),
    #[error(transparent)]
    StateDir(#[from] StateDirError),
    #[error(transparent)]
    Mls(#[from] cairn_crypto::mls::MlsError),
    #[error(transparent)]
    Shape(#[from] cairn_proto::ShapeError),
    #[error(transparent)]
    Verify(#[from] VerifyError),
    #[error("not a valid id: {0}")]
    BadId(String),
    #[error("no room is open")]
    NoRoomOpen,
    #[error("this room has no encrypted group on this device yet — wait to be admitted")]
    NoGroupYet,
    #[error("identity file is unreadable: {0}")]
    Identity(String),
    #[error(transparent)]
    Attachment(#[from] cairn_crypto::attachment::AttachmentError),
    #[error("that file is empty; there is nothing to send")]
    EmptyAttachment,
    #[error(
        "that file is {} — attachments are limited to {}",
        human_bytes(*size),
        human_bytes(*max)
    )]
    AttachmentTooLarge { size: usize, max: usize },
    #[error("that attachment is not one this device received in the open room")]
    UnknownAttachment,
    #[error("the room changed while the file was uploading, so it was not sent")]
    RoomChangedDuringUpload,
    #[error("could not save the attachment: {0}")]
    Save(std::io::Error),
}

/// A room as a frontend needs to show it.
///
/// The tier label comes from the **locally derived** seal, never from anything the instance
/// said. `docs/02-encryption-tiers.md` UI rule 8: the badge is a claim about who can read
/// the message, and only the component doing the encrypting knows the answer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoomSummary {
    pub id: String,
    pub tier: String,
    pub e2ee: bool,
    /// Whether this device holds the encrypted group. False means joined-but-not-admitted.
    pub joined: bool,
}

/// One person in a room, as both halves of the system see them.
///
/// `in_group` is the distinction that matters and the one a UI must not flatten: the
/// instance's member list and the encrypted group's roster are different things, and
/// somebody present in the first but not the second **cannot read the room**.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberView {
    pub user: String,
    /// The instance's word for this account's role — or [`UNLISTED`] for an account that
    /// holds a leaf in the encrypted group but that the instance did not list at all.
    pub role: String,
    pub in_group: bool,
    /// Every one of this account's devices in the group has had its safety number compared,
    /// and none has changed key since.
    pub verified: bool,
    /// At least one of this account's devices changed key after being verified. Sticky until
    /// the new number is compared — see [`ContactStore::observe`].
    pub key_changed: bool,
}

/// The role reported for a group member the instance's member list omits.
///
/// The list comes from the instance; the roster comes from the group. A member who can read
/// the room must never be invisible just because the instance left them out — that is the
/// "silently added member" of `docs/01-threat-model.md` §4 with extra steps.
pub const UNLISTED: &str = "unlisted";

/// A message for display. Plain data: no envelope, no keys.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageView {
    pub sender: String,
    pub body: String,
    pub sent_at_ms: i64,
    /// True when replayed from the local transcript rather than just received.
    pub historic: bool,
    /// The file, photo or voice note this message carried. No key: a frontend fetches the
    /// bytes by id through [`Session::fetch_attachment`].
    #[serde(default)]
    pub attachment: Option<AttachmentView>,
}

/// Something that happened while polling, for a frontend to render in the timeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Event {
    Message(MessageView),
    /// Someone joined or left the **encrypted group**.
    Membership {
        joined: Vec<String>,
        left: Vec<String>,
    },
    /// This device was removed. The frontend must close the room.
    Removed,
    /// Call signalling addressed to this device, for the WebRTC layer rather than the
    /// timeline. Already filtered: signals meant for somebody else never reach a frontend.
    Signal {
        from: String,
        signal: CallSignal,
    },
}

struct OpenRoom {
    convo: Conversation,
    seal: RoomSeal,
    cursor: u64,
}

/// One signed-in client.
pub struct Session {
    client: Client<HttpTransport>,
    mls: Arc<MlsSession>,
    index: ConversationIndex,
    contacts: ContactStore,
    history: History,
    open: Option<OpenRoom>,
    dir: PathBuf,
    tls: bool,
    /// The call this device is in, if any. One per room.
    call: Option<String>,
    /// Whether an offer or an answer has crossed under the current call id.
    ///
    /// It gates renaming the call. Before anything is negotiated a rename costs nothing;
    /// after it, adopting a different id would orphan every peer connection already built.
    negotiated: bool,
    /// A call announced in the open room that this device has not joined.
    ///
    /// This is what makes a call *ring*. Without it the only way into a call was for both
    /// people to press the button independently and hope their minted ids reconciled —
    /// there was no way to be told a call had started at all.
    ringing: Option<String>,
    /// Attachments seen in the open room, with the keys that open them. Never handed to a
    /// frontend; see `attachments.rs` for why a frontend can only fetch what is in here.
    attachments: attachments::Known,
}

#[derive(Serialize, Deserialize)]
struct StoredIdentity {
    user: uuid::Uuid,
    device: uuid::Uuid,
    #[serde(default)]
    claimed: bool,
}

impl Session {
    /// Open — or create — a client rooted at this profile's state directory.
    ///
    /// The order here is load-bearing and is the main reason this is not left to callers:
    /// the account and device ids must be read *before* the MLS session, because the
    /// credential is built from them. Building it from a display name is what let one member
    /// present another's label (`cairn_proto::identity`).
    pub fn open(profile: &str, server: &str, dir: Option<&Path>) -> Result<Self, SessionError> {
        Self::open_with_invite(profile, server, dir, None)
    }

    /// As [`Session::open`], with a **registration** invite for an instance that requires
    /// one.
    ///
    /// Distinct from a room invite, and the distinction is the whole reason this exists.
    /// A room invite admits an existing account to a room; this one admits an account to the
    /// *instance*. The server's default policy is `InviteOnly` and the self-hosting guide
    /// recommends keeping it that way, so without this the client could only ever sign in to
    /// an instance whose operator had opened registration to the whole internet — which is
    /// exactly the configuration nobody should be running.
    ///
    /// Ignored when this profile has already registered. The instance checks the invite
    /// *before* it notices the account exists, so a returning user presenting a spent token
    /// would otherwise be locked out of their own account.
    pub fn open_with_invite(
        profile: &str,
        server: &str,
        dir: Option<&Path>,
        invite: Option<&str>,
    ) -> Result<Self, SessionError> {
        let dir = match dir {
            Some(explicit) => explicit.to_path_buf(),
            None => statedir::default_state_dir(profile)?,
        };
        statedir::prepare(&dir)?;

        let (user, device, claimed) = load_or_create_identity(&dir)?;
        let identity = DeviceIdentity::new(user, device).to_credential();
        let mls = Arc::new(MlsSession::open(&dir, &identity)?);

        let transport = HttpTransport::new(server);
        let tls = transport.is_tls();
        let client = Client::new(transport, mls.clone(), user, device);

        let mut session = Self {
            client,
            mls,
            index: ConversationIndex::open(&dir)?,
            contacts: ContactStore::open(&dir)?,
            history: History::open(&dir)?,
            open: None,
            dir: dir.clone(),
            tls,
            call: None,
            negotiated: false,
            ringing: None,
            attachments: attachments::Known::new(),
        };
        if !claimed {
            session.claim(invite)?;
        }
        Ok(session)
    }

    /// Register this device with the instance. Idempotent from the caller's side: the
    /// claimed flag is recorded locally, because the server checks an invite *before* it
    /// notices the account exists, so a second attempt is refused even for its owner.
    pub fn claim(&mut self, invite: Option<&str>) -> Result<(), SessionError> {
        self.client.claim_account(invite)?;
        let path = self.dir.join("identity.json");
        let stored = StoredIdentity {
            user: *self.client.user().as_uuid(),
            device: *self.client.device().as_uuid(),
            claimed: true,
        };
        std::fs::write(
            &path,
            serde_json::to_vec_pretty(&stored)
                .map_err(|e| SessionError::Identity(e.to_string()))?,
        )
        .map_err(|e| SessionError::Identity(e.to_string()))?;
        Ok(())
    }

    pub fn user_id(&self) -> String {
        self.client.user().to_string()
    }

    /// Whether the connection to the instance is TLS.
    ///
    /// A frontend must show this: over `http://` the transport protects nothing, and a badge
    /// implying otherwise is the false assurance `docs/01-threat-model.md` forbids.
    pub const fn is_tls(&self) -> bool {
        self.tls
    }

    /// Publish key packages so others can add this device to their groups.
    pub fn publish_key_packages(&self, count: usize) -> Result<usize, SessionError> {
        Ok(self.client.publish_key_packages(count)?)
    }

    /// Create a **group** room: not direct, not discoverable, so T2 and end-to-end encrypted.
    ///
    /// `ceiling` is the maximum membership, sealed at creation and never changeable. It is
    /// an input to `derive_tier`, so asking for more than `T2_MAX_MEMBERS` does not get a
    /// bigger private room — it gets a **public** one, which is a different product. The
    /// client refuses rather than silently handing back something server-readable.
    pub fn create_group(&mut self, ceiling: u32) -> Result<String, SessionError> {
        if ceiling > cairn_proto::tier::T2_MAX_MEMBERS {
            return Err(SessionError::Shape(cairn_proto::ShapeError::DirectRoomTooLarge));
        }
        let shape = RoomShape {
            is_direct: false,
            is_publicly_discoverable: false,
            member_ceiling: ceiling,
        };
        self.create_room(shape)
    }

    /// Create a two-person direct room (T1).
    pub fn create_direct(&mut self) -> Result<String, SessionError> {
        let shape =
            RoomShape { is_direct: true, is_publicly_discoverable: false, member_ceiling: 2 };
        self.create_room(shape)
    }

    fn create_room(&mut self, shape: RoomShape) -> Result<String, SessionError> {
        let created = self.client.create_room(shape)?;
        let convo = Conversation::create_encrypted(
            created.seal,
            created.room,
            self.client.user(),
            self.client.device(),
            self.mls.clone(),
        )?;
        self.index.record(created.room, &created.seal, convo.group_id())?;
        let cursor = self.index.cursor(&created.room);
        self.open = Some(OpenRoom { convo, seal: created.seal, cursor });
        // Found by a probe: without this, creating a room left the previous room's
        // attachments fetchable from the new one.
        self.attachments.clear();
        Ok(created.room.to_string())
    }

    /// Every room this device knows about.
    pub fn rooms(&self) -> Vec<RoomSummary> {
        self.index
            .rooms()
            .map(|(room, record)| RoomSummary {
                id: room.to_string(),
                tier: record.tier.label().to_string(),
                e2ee: record.tier.is_e2ee(),
                joined: self.index.group_id(room).ok().flatten().is_some(),
            })
            .collect()
    }

    /// Open a room, resuming its encrypted group if this device holds one.
    pub fn open_room(&mut self, room: &str) -> Result<Vec<MessageView>, SessionError> {
        let room: RoomId = room.parse().map_err(|_| SessionError::NoRoomOpen)?;
        // Calls belong to a room. Carrying one across would have this device signalling into
        // a call whose participants are no longer being polled.
        self.call = None;
        self.negotiated = false;
        self.ringing = None;
        let record = self.index.get(&room);
        let seal = match record {
            Some(record) => RoomSeal::new(RoomShape {
                is_direct: record.tier == Tier::Private,
                is_publicly_discoverable: !record.tier.is_e2ee(),
                member_ceiling: if record.tier == Tier::Private { 2 } else { 256 },
            })?,
            // Added by someone else and not yet recorded; the welcome confirms the shape.
            None => RoomSeal::new(RoomShape {
                is_direct: false,
                is_publicly_discoverable: false,
                member_ceiling: 256,
            })?,
        };

        let convo = match self.index.group_id(&room)? {
            Some(group_id) => Conversation::resume_encrypted(
                seal,
                room,
                self.client.user(),
                self.client.device(),
                self.mls.clone(),
                &group_id,
            )?,
            None => {
                // No group yet: this device is a room member the group has not admitted.
                // Recorded so the room is listed, and polling can still pick up a welcome.
                self.index.record(room, &seal, None)?;
                Conversation::create_public(
                    RoomSeal::new(RoomShape {
                        is_direct: false,
                        is_publicly_discoverable: true,
                        member_ceiling: 256,
                    })?,
                    room,
                    self.client.user(),
                    self.client.device(),
                    self.mls.clone(),
                )?
            }
        };

        let cursor = self.index.cursor(&room);
        self.open = Some(OpenRoom { convo, seal, cursor });
        // A room's attachments are fetchable only while it is open.
        self.attachments.clear();
        self.replay(room)
    }

    /// The local transcript for a room, with the room's disappearing timer applied.
    fn replay(&mut self, room: RoomId) -> Result<Vec<MessageView>, SessionError> {
        let ttl = self.client.room_ttl(room).ok().flatten();
        let entries = self.history.replay(room, ttl, now_ms())?;
        Ok(entries
            .into_iter()
            .map(|e| {
                let attachment = e.attachment.map(|a| {
                    let view = AttachmentView::of(&a);
                    self.attachments.insert(a.blob, a);
                    view
                });
                MessageView {
                    sender: e.sender.to_string(),
                    body: String::from_utf8_lossy(&e.body).to_string(),
                    sent_at_ms: e.sent_at_ms,
                    historic: true,
                    attachment,
                }
            })
            .collect())
    }

    pub fn open_room_id(&self) -> Option<String> {
        self.open.as_ref().map(|o| o.convo.room().to_string())
    }

    /// The badge for the open room, derived locally.
    pub fn open_room_tier(&self) -> Option<String> {
        self.open.as_ref().map(|o| o.seal.tier().label().to_string())
    }

    /// Send a message to the open room.
    pub fn send(&mut self, text: &str) -> Result<(), SessionError> {
        let open = self.open.as_mut().ok_or(SessionError::NoRoomOpen)?;
        if open.convo.group_id().is_none() {
            return Err(SessionError::NoGroupYet);
        }
        let at = now_ms();
        let outbound = open.convo.send(text.as_bytes(), at)?;
        self.client.send(open.convo.room(), &outbound.envelope)?;

        // Recorded locally because MLS will not decrypt our own message back to us — without
        // this the transcript is every reply and none of the prompts.
        self.history.append(
            open.convo.room(),
            &HistoryEntry {
                sender: self.client.user(),
                sent_at_ms: at,
                body: text.as_bytes().to_vec(),
                attachment_name: None,
                attachment: None,
            },
        )?;
        Ok(())
    }

    /// Fetch and decrypt whatever has arrived since the last poll.
    ///
    /// The open room is taken out for the duration rather than borrowed in place: joining a
    /// group mid-loop *replaces* the conversation, and that cannot be done through a live
    /// borrow of the field it lives in.
    pub fn poll(&mut self) -> Result<Vec<Event>, SessionError> {
        let Some(mut open) = self.open.take() else { return Ok(Vec::new()) };
        let room = open.convo.room();
        let fetched = match self.client.fetch_since(room, open.cursor) {
            Ok(f) => f,
            Err(e) => {
                self.open = Some(open);
                return Err(e.into());
            }
        };
        let mut events = Vec::new();

        for message in fetched {
            open.cursor = open.cursor.max(message.server_seq);

            // Not in the group yet: the only envelope that can help is a welcome, and
            // everything else in the room is ciphertext for a group this device is not in.
            // Without this a joiner polls forever and never joins — which is exactly how
            // the first version of this failed its own test.
            if open.convo.group_id().is_none() {
                if let Ok(Some(group)) = crate::accept_welcome(&self.mls, &message.envelope) {
                    if let Ok(convo) = Conversation::join_encrypted(
                        open.seal,
                        room,
                        self.client.user(),
                        self.client.device(),
                        self.mls.clone(),
                        group,
                    ) {
                        open.convo = convo;
                        // Recorded immediately: a group this device can open but has not
                        // written down is one it loses on restart.
                        let _ = self.index.record(room, &open.seal, open.convo.group_id());
                        events.push(Event::Membership {
                            joined: vec![self.client.user().to_string()],
                            left: Vec::new(),
                        });
                    }
                }
                continue;
            }

            match open.convo.receive(&message.envelope) {
                Ok(TimelineEvent::Message(received)) => {
                    // Signalling first: it arrives as an ordinary encrypted message with an
                    // empty body, and rendering that in the timeline would show every
                    // participant a stream of blank lines during a call.
                    if let Some(signal) = received.signal {
                        let me = self.client.user().to_string();
                        let from = message.envelope.sender.to_string();
                        // Own signals come back through the room; applying one to yourself
                        // would have a peer negotiating with itself.
                        if from != me && signal.is_for(&me) {
                            if let Some(signal) = self.reconcile(*signal) {
                                events.push(Event::Signal { from, signal });
                            }
                        }
                        continue;
                    }
                    let body = String::from_utf8_lossy(&received.body).to_string();
                    let attachment = received.attachment.map(|a| *a);
                    let _ = self.history.append(
                        room,
                        &HistoryEntry {
                            sender: message.envelope.sender,
                            sent_at_ms: message.envelope.sent_at_ms,
                            body: received.body.clone(),
                            attachment_name: attachment.as_ref().map(|a| a.name.clone()),
                            attachment: attachment.clone(),
                        },
                    );
                    let view = attachment.map(|a| {
                        let view = AttachmentView::of(&a);
                        self.attachments.insert(a.blob, a);
                        view
                    });
                    events.push(Event::Message(MessageView {
                        sender: message.envelope.sender.to_string(),
                        body,
                        sent_at_ms: message.envelope.sent_at_ms,
                        historic: false,
                        attachment: view,
                    }));
                }
                Ok(TimelineEvent::Membership { added, removed, .. }) => {
                    events.push(Event::Membership {
                        joined: added.iter().map(describe_member).collect(),
                        left: removed.iter().map(describe_member).collect(),
                    });
                }
                Ok(TimelineEvent::RemovedFromRoom { .. }) => {
                    // Being ejected means the local transcript goes too: the room is no
                    // longer readable and keeping a plaintext copy is not a courtesy.
                    let _ = self.history.forget(room);
                    events.push(Event::Removed);
                }
                Ok(TimelineEvent::Nothing) => {}
                // A message this device cannot open is not an error worth surfacing: it is
                // ordinary before admission, and it is traffic for a group we are not in.
                Err(_) => {}
            }
        }

        // A roster change is when a key change happens, so it is when the contact store
        // should hear about it — a verified contact re-added under a new key is flagged now,
        // not whenever somebody next opens the member list. Best-effort: `members` and
        // `safety_numbers` observe again before reporting anything, and surface the error.
        if events.iter().any(|e| matches!(e, Event::Membership { .. }))
            && open.convo.group_id().is_some()
        {
            let _ = verify::observe_roster(&open.convo, &mut self.contacts);
        }

        let _ = self.index.advance(room, open.cursor);
        self.open = Some(open);
        Ok(events)
    }

    /// Join the call in the open room, announcing arrival to everyone already in it.
    ///
    /// Returns the call id. A room hosts one call at a time; the id exists so a signal left
    /// over from a previous call cannot be applied to this one.
    pub fn call_join(&mut self) -> Result<String, SessionError> {
        let open = self.open.as_ref().ok_or(SessionError::NoRoomOpen)?;
        if open.convo.group_id().is_none() {
            return Err(SessionError::NoGroupYet);
        }
        // **No room-size check here, deliberately.** There used to be one, counting the
        // devices in the encrypted group — the wrong thing entirely. A group chat of eight
        // could not hold a call between two of them, and the refusal named the room's size
        // as the reason, which reads as "calls are broken in big groups".
        //
        // The mesh ceiling is about how many people are *in the call*, and nobody knows that
        // at the moment of joining: a call starts with one person and grows as arrivals
        // announce themselves. What every device does know is how many peer connections it
        // is holding, and that is exactly the thing the ceiling bounds — so it is enforced
        // in the frontend, per connection, where the count is real. `call_config` hands it
        // `MAX_MESH_PARTICIPANTS` so the number still lives here.
        // Joining a call that has been announced must join *that* call. Minting a fresh id
        // here is what made two people pressing the button a race rather than a meeting.
        let call = self
            .call
            .clone()
            .or_else(|| self.ringing.take())
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        self.call = Some(call.clone());
        self.signal(CallSignal {
            call: call.clone(),
            kind: SignalKind::Join,
            to: None,
            payload: String::new(),
        })?;
        Ok(call)
    }

    /// Leave the call, telling peers so they tear down rather than waiting for a timeout.
    pub fn call_leave(&mut self) -> Result<(), SessionError> {
        let Some(call) = self.call.take() else { return Ok(()) };
        self.negotiated = false;
        // `signal` stamps `self.call`, which has just been cleared, so the id is passed
        // explicitly here — a leave has to name the call it is leaving.
        let announcement =
            CallSignal { call, kind: SignalKind::Leave, to: None, payload: String::new() };
        let open = self.open.as_mut().ok_or(SessionError::NoRoomOpen)?;
        let outbound = open.convo.send_signal(announcement, now_ms())?;
        self.client.send(open.convo.room(), &outbound.envelope)?;
        Ok(())
    }

    /// Decide whether an incoming signal belongs to the call this device is in — and, when
    /// two devices disagree about which call that is, settle it.
    ///
    /// **Found by a test, not by reading.** Every participant minted their own call id on
    /// joining, and every participant discarded signals that did not carry *their* id. Two
    /// people pressing "call" in the same second therefore ended up in two calls of one
    /// person each, both showing a connecting spinner and neither ever connecting. The
    /// symptom is indistinguishable from a network fault.
    ///
    /// The rule: an **addressed** join comes from somebody already in a call, so their id
    /// wins. Two **broadcast** joins are a race, so the smaller id wins — the same
    /// deterministic tie-break the frontend uses to decide who offers, needing no extra
    /// round trip. Renaming stops once anything has been negotiated, because by then a
    /// rename would orphan live peer connections.
    ///
    /// **What this does not defend against, stated rather than implied.** Between joining a
    /// call and exchanging the first offer, any *member of the room* can rename this device's
    /// call by sending an addressed join — splitting a call in two so each half waits for
    /// answers the other will never send. It is a denial of service by somebody who is
    /// already inside the room and could disrupt a call by simply joining it, so it buys an
    /// attacker nothing they did not have; it is recorded because the failure is silent and
    /// looks like a network fault. Closing it needs a roster the call does not have —
    /// `docs/12-realtime-media.md` §2's per-call MLS group is where that comes from.
    fn reconcile(&mut self, mut signal: CallSignal) -> Option<CallSignal> {
        let Some(mine) = self.call.clone() else {
            // Not in the call. Arrival and departure announcements are still worth
            // surfacing: the first is the only way this device learns a call is happening —
            // `call_join` picks the id up from here so accepting lands in *that* call rather
            // than starting a rival one — and the second is how a ring stops when the caller
            // gives up. Everything else describes a negotiation between two other devices,
            // and handing it to a frontend would have it build a peer connection for a call
            // its user has not accepted.
            return match signal.kind {
                SignalKind::Join => {
                    self.ringing = Some(signal.call.clone());
                    Some(signal)
                }
                SignalKind::Leave => {
                    // Whoever was calling has given up. Forgetting the id stops a later
                    // `call_join` adopting a call nobody is in; if somebody else is still in
                    // it, their acknowledgement renames this device into it anyway.
                    if self.ringing.as_deref() == Some(signal.call.as_str()) {
                        self.ringing = None;
                    }
                    Some(signal)
                }
                _ => None,
            };
        };

        if signal.call != mine
            && signal.kind == SignalKind::Join
            && !self.negotiated
            && (signal.to.is_some() || signal.call < mine)
        {
            self.call = Some(signal.call.clone());
        }
        let current = self.call.clone().unwrap_or(mine);

        // A join under a different id is still a real arrival — the two sides converge as
        // the acknowledgements cross. Anything else is a call this device is not in.
        if signal.call != current && signal.kind != SignalKind::Join {
            return None;
        }
        if matches!(signal.kind, SignalKind::Offer | SignalKind::Answer) {
            self.negotiated = true;
        }
        // Hand the frontend the agreed id rather than the one on the wire, so it cannot go
        // on signalling under a name the rest of the call has stopped using.
        signal.call = current;
        Some(signal)
    }

    /// Send one signalling message. Rides inside the encrypted body, so the instance sees
    /// ciphertext rather than an SDP offer full of the sender's network addresses.
    pub fn signal(&mut self, mut signal: CallSignal) -> Result<(), SessionError> {
        // The call id is this layer's to decide, not a frontend's. `reconcile` renames the
        // call when two people start one at the same moment, and a frontend that had cached
        // the old id would go on signalling into a call nobody else is in.
        if let Some(call) = &self.call {
            signal.call = call.clone();
        }
        let negotiating = matches!(signal.kind, SignalKind::Offer | SignalKind::Answer);
        let open = self.open.as_mut().ok_or(SessionError::NoRoomOpen)?;
        if open.convo.group_id().is_none() {
            return Err(SessionError::NoGroupYet);
        }
        let outbound = open.convo.send_signal(signal, now_ms())?;
        self.client.send(open.convo.room(), &outbound.envelope)?;
        // Only after it is actually on the wire. Marking it beforehand would let a send that
        // failed lock out a rename that is still legitimate.
        if negotiating {
            self.negotiated = true;
        }
        Ok(())
    }

    pub fn call_id(&self) -> Option<String> {
        self.call.clone()
    }

    /// Everyone in the room, from both the instance's list and the encrypted group.
    ///
    /// Observes the roster first. Without that, verification state is whatever the contact
    /// store last saw — and before this, nothing in `Session` ever showed it anything, so a
    /// contact verified once and then substituted was still reported verified.
    pub fn members(&mut self) -> Result<Vec<MemberView>, SessionError> {
        let open = self.open.as_ref().ok_or(SessionError::NoRoomOpen)?;
        let room = open.convo.room();
        if open.convo.group_id().is_some() {
            verify::observe_roster(&open.convo, &mut self.contacts)?;
        }
        let listed = self.client.room_members(room)?;
        Ok(member_views(listed, &open.convo.members(), &self.contacts))
    }

    /// The safety number for each of `user`'s devices in the open room's group.
    ///
    /// Computed from the group's own roster, never from a key the instance published — see
    /// [`crate::verify`]. Asking about your own account lists your other devices.
    pub fn safety_numbers(&mut self, user: &str) -> Result<Vec<SafetyView>, SessionError> {
        let user: UserId = user.parse().map_err(|_| SessionError::BadId(user.to_string()))?;
        let open = self.open.as_ref().ok_or(SessionError::NoRoomOpen)?;
        if open.convo.group_id().is_none() {
            return Err(SessionError::NoGroupYet);
        }
        Ok(verify::safety_numbers(&open.convo, &mut self.contacts, user)?)
    }

    /// Record that the user compared `number` with this device's owner and it matched.
    ///
    /// `number` is the one the frontend displayed, handed back unchanged. It is checked
    /// against the number *now*: if the key changed while it was on screen, this refuses
    /// rather than certifying a key the user never saw. Returns the account's refreshed
    /// numbers so the frontend can redraw from one call.
    pub fn verify(
        &mut self,
        user: &str,
        device: &str,
        number: &str,
    ) -> Result<Vec<SafetyView>, SessionError> {
        let account: UserId = user.parse().map_err(|_| SessionError::BadId(user.to_string()))?;
        let device: DeviceId =
            device.parse().map_err(|_| SessionError::BadId(device.to_string()))?;
        let identity = DeviceIdentity::new(account, device).to_credential();

        let open = self.open.as_ref().ok_or(SessionError::NoRoomOpen)?;
        if open.convo.group_id().is_none() {
            return Err(SessionError::NoGroupYet);
        }
        verify::verify(&open.convo, &mut self.contacts, &identity, number)?;
        Ok(verify::safety_numbers(&open.convo, &mut self.contacts, account)?)
    }

    /// Accounts the instance lists that the encrypted group does not hold.
    pub fn waiting(&mut self) -> Result<Vec<String>, SessionError> {
        Ok(self.members()?.into_iter().filter(|m| !m.in_group).map(|m| m.user).collect())
    }

    /// Admit everyone waiting into the encrypted group.
    ///
    /// **Deliberately an action, never automatic.** The waiting list comes from the
    /// instance, so admitting on its word alone would let a malicious one name an account
    /// and have this client hand it the group keys silently. What is removed is the need to
    /// paste a user id, not the decision.
    pub fn admit_waiting(&mut self) -> Result<Vec<String>, SessionError> {
        let waiting = self.waiting()?;
        let mut admitted = Vec::new();
        for user in waiting {
            let Ok(parsed) = user.parse::<UserId>() else { continue };
            if self.admit_one(parsed).is_ok() {
                admitted.push(user);
            }
        }
        Ok(admitted)
    }

    fn admit_one(&mut self, user: UserId) -> Result<(), SessionError> {
        let claimed = self.client.claim_key_packages(user)?;
        let open = self.open.as_mut().ok_or(SessionError::NoRoomOpen)?;
        for package in &claimed {
            let bytes = hex::decode(&package.key_package).map_err(|_| SessionError::NoGroupYet)?;
            let key_package = cairn_crypto::mls::parse_message(&bytes)?;
            let group = open.convo.group_mut().ok_or(SessionError::NoGroupYet)?;
            let output = group.add_member(key_package)?;

            let commit = output.commit.to_bytes().map_err(|_| SessionError::NoGroupYet)?;
            let wrapped = open.convo.wrap_handshake(&commit, now_ms())?;
            self.client.send(open.convo.room(), &wrapped)?;
            if let Some(welcome) = output.welcome {
                let bytes = welcome.to_bytes().map_err(|_| SessionError::NoGroupYet)?;
                let wrapped = open.convo.wrap_handshake(&bytes, now_ms())?;
                self.client.send(open.convo.room(), &wrapped)?;
            }
        }
        self.index.record(open.convo.room(), &open.seal, open.convo.group_id())?;
        Ok(())
    }

    /// Mint an invite link for the open room.
    pub fn create_invite(&self, uses: u32, hours: i64) -> Result<String, SessionError> {
        let open = self.open.as_ref().ok_or(SessionError::NoRoomOpen)?;
        let expires = (hours > 0).then(|| now_ms() + hours * 3_600_000);
        Ok(self.client.create_room_invite(open.convo.room(), uses, expires)?)
    }

    /// Redeem an invite. Joins the room; it does **not** grant the group keys — an existing
    /// member must still admit this device before anything is readable.
    pub fn redeem_invite(&mut self, token: &str) -> Result<String, SessionError> {
        let room = self.client.redeem_room_invite(token)?;
        let seal = RoomSeal::new(RoomShape {
            is_direct: false,
            is_publicly_discoverable: false,
            member_ceiling: 256,
        })?;
        self.index.record(room, &seal, None)?;
        Ok(room.to_string())
    }
}

fn describe_member(m: &cairn_crypto::mls::GroupMember) -> String {
    DeviceIdentity::parse(&m.identity)
        .map(|id| id.user().to_string())
        .unwrap_or_else(|_| format!("unattributable leaf {}", m.index))
}

/// Join the instance's member list with the group's roster.
///
/// Verification state is held per *device* — the contact store is keyed by MLS identity
/// bytes — so an account counts as verified only when every device of theirs in this group
/// has been verified. Reporting "verified" while one of someone's devices is unchecked would
/// be the badge overstating itself.
///
/// Roster accounts the instance did not list are appended as [`UNLISTED`] rather than
/// dropped. The member list is the only place a frontend shows who is in a room, and the
/// instance writes it: leaving someone off it must not make a reader of the room invisible.
fn member_views(
    listed: Vec<(UserId, String)>,
    roster: &[cairn_crypto::mls::GroupMember],
    contacts: &ContactStore,
) -> Vec<MemberView> {
    struct Seen {
        user: UserId,
        verified: bool,
        changed: bool,
    }
    let mut in_group: Vec<Seen> = Vec::new();
    for m in roster {
        let Ok(id) = DeviceIdentity::parse(&m.identity) else { continue };
        let state = contacts.state_of(&m.identity);
        let verified = state == VerificationState::Verified;
        let changed = state == VerificationState::ChangedSinceVerified;
        match in_group.iter_mut().find(|s| s.user == id.user()) {
            Some(entry) => {
                entry.verified &= verified;
                entry.changed |= changed;
            }
            None => in_group.push(Seen { user: id.user(), verified, changed }),
        }
    }

    let mut views: Vec<MemberView> = listed
        .iter()
        .map(|(user, role)| {
            let found = in_group.iter().find(|s| s.user == *user);
            MemberView {
                user: user.to_string(),
                role: role.clone(),
                in_group: found.is_some(),
                verified: found.is_some_and(|s| s.verified),
                key_changed: found.is_some_and(|s| s.changed),
            }
        })
        .collect();

    for seen in in_group.iter().filter(|s| !listed.iter().any(|(u, _)| *u == s.user)) {
        views.push(MemberView {
            user: seen.user.to_string(),
            role: UNLISTED.to_string(),
            in_group: true,
            verified: seen.verified,
            key_changed: seen.changed,
        });
    }
    views
}

fn load_or_create_identity(dir: &Path) -> Result<(UserId, DeviceId, bool), SessionError> {
    let path = dir.join("identity.json");
    match std::fs::read(&path) {
        Ok(bytes) => {
            let stored: StoredIdentity = serde_json::from_slice(&bytes)
                .map_err(|e| SessionError::Identity(e.to_string()))?;
            Ok((UserId::from_uuid(stored.user), DeviceId::from_uuid(stored.device), stored.claimed))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Ok((UserId::new(), DeviceId::new(), false))
        }
        Err(e) => Err(SessionError::Identity(e.to_string())),
    }
}

/// `12.3 MB`-style sizes for error messages a person reads. Binary units, labelled as such.
fn human_bytes(n: usize) -> String {
    const MIB: f64 = 1024.0 * 1024.0;
    if n >= 1024 * 1024 {
        format!("{:.1} MiB", n as f64 / MIB)
    } else if n >= 1024 {
        format!("{:.1} KiB", n as f64 / 1024.0)
    } else {
        format!("{n} bytes")
    }
}

fn now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cairn_crypto::mls::GroupMember;

    fn store(name: &str) -> ContactStore {
        let dir = std::env::temp_dir()
            .join("cairn-member-views")
            .join(format!("{name}-{}", uuid::Uuid::new_v4()));
        ContactStore::open(dir).unwrap()
    }

    fn leaf(index: u32, user: UserId, key: &[u8]) -> GroupMember {
        GroupMember {
            index,
            identity: DeviceIdentity::new(user, DeviceId::new()).to_credential(),
            signature_key: key.to_vec(),
        }
    }

    fn verified(contacts: &mut ContactStore, member: &GroupMember) {
        contacts.observe(member).unwrap();
        assert!(contacts.mark_verified(&member.identity).unwrap());
    }

    #[test]
    fn an_account_is_verified_only_when_every_device_is() {
        let bob = UserId::new();
        let phone = leaf(1, bob, b"phone");
        let laptop = leaf(2, bob, b"laptop");
        let mut contacts = store("every");
        verified(&mut contacts, &phone);

        let roster = [phone.clone(), laptop.clone()];
        let views = member_views(vec![(bob, "member".into())], &roster, &contacts);
        assert!(!views[0].verified, "one unchecked device must keep the account unverified");

        verified(&mut contacts, &laptop);
        let views = member_views(vec![(bob, "member".into())], &roster, &contacts);
        assert!(views[0].verified);
        assert!(!views[0].key_changed);
    }

    #[test]
    fn a_key_change_on_any_device_flags_the_account() {
        let bob = UserId::new();
        let phone = leaf(1, bob, b"phone");
        let laptop = leaf(2, bob, b"laptop");
        let mut contacts = store("flag");
        verified(&mut contacts, &phone);
        verified(&mut contacts, &laptop);

        let substituted = GroupMember { signature_key: b"someone else".to_vec(), ..laptop };
        contacts.observe(&substituted).unwrap();

        let views = member_views(vec![(bob, "member".into())], &[phone, substituted], &contacts);
        assert!(!views[0].verified);
        assert!(views[0].key_changed, "the account must carry the warning, not hide it");
    }

    #[test]
    fn a_group_member_the_instance_does_not_list_is_still_shown() {
        // The member list is the instance's to write. A leaf that can read the room must not
        // vanish from the only place a frontend shows people because the list omitted it.
        let alice = UserId::new();
        let hidden = UserId::new();
        let roster = [leaf(0, alice, b"alice"), leaf(1, hidden, b"hidden")];

        let views = member_views(vec![(alice, "owner".into())], &roster, &store("unlisted"));
        let shown = views.iter().find(|v| v.user == hidden.to_string());
        let shown = shown.expect("a group member the instance left out must still be shown");
        assert_eq!(shown.role, UNLISTED);
        assert!(shown.in_group);
        assert!(!shown.verified, "and unverified is the honest default");
    }

    #[test]
    fn a_listed_account_without_a_leaf_is_waiting_not_verified() {
        let carol = UserId::new();
        let views = member_views(vec![(carol, "member".into())], &[], &store("waiting"));
        assert!(!views[0].in_group);
        assert!(!views[0].verified);
        assert!(!views[0].key_changed);
    }
}
