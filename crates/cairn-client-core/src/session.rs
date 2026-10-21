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
use crate::conversation::{Conversation, ConversationError, MessageRef, Reaction, TimelineEvent};
use crate::history::{Entry as HistoryEntry, History, HistoryError};
use crate::statedir::{self, StateDirError};
use crate::store::{ConversationIndex, IndexError};
use crate::thread::Thread;
pub use crate::thread::{QuoteView, ReactionView};
use crate::transport::HttpTransport;
use crate::verify::{self, SafetyView, VerifyError};

mod attachments;
mod gifs;
pub use attachments::{
    kind_of, normalize_mime, safe_file_name, AttachmentKind, AttachmentView, PendingDownload,
    PendingUpload, UploadedAttachment, MAX_ATTACHMENT_BYTES, SEAL_OVERHEAD,
};
mod custom;
pub use custom::{
    custom_limits, CustomItemView, CustomLimits, CustomSetView, CustomSync, PendingCustomUpload,
    UploadedCustom,
};
mod profiles;
mod spaces;
mod voice;
pub use crate::profile::{ImageSlot, ImageView, ProfileView, StatusView};
pub use profiles::{profile_limits, PendingProfileImage, ProfileEdit, ProfileLimits};
pub use spaces::{
    ChannelDisplay, OverrideDisplay, RoleDisplay, SpaceDisplay, SpaceListing, SpaceMemberDisplay,
};
pub use voice::{
    VoiceJoined, VoiceKeyView, VoiceKeysView, VoiceParticipantView, VoiceProtection, VoiceStateView,
};

use crate::profile::{Label, ProfileError, ProfileStore, ProfileStoreError};
use std::collections::HashMap;

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
    #[error(transparent)]
    Gif(#[from] crate::gifs::GifError),
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
    #[error("a disappearing-message timer must be longer than zero")]
    BadTimer,
    #[error("that message is not on this device")]
    UnknownMessage,
    #[error("a reaction is a single emoji")]
    BadReaction,
    #[error(transparent)]
    Profile(#[from] ProfileError),
    #[error(transparent)]
    ProfileStore(#[from] ProfileStoreError),
    #[error("that profile image is not one this device holds for the open room")]
    UnknownProfileImage,
    #[error("you switched rooms before this message was sent, so it was not sent")]
    RoomChanged,
    #[error("link preview settings could not be saved: {0}")]
    Preferences(String),
    #[error(transparent)]
    Custom(#[from] crate::custom::CustomError),
    #[error(transparent)]
    CustomStore(#[from] crate::custom::CustomStoreError),
    #[error("that emoji, sticker or sound is not in this room's set on this device")]
    UnknownCustomAsset,
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
    /// Their profile in this room, labelled against everyone else's. **Presentation only**:
    /// `user` above is who they are, and `verified` is about their keys, not their name.
    #[serde(default)]
    pub profile: Option<ProfileView>,
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
    /// What to call the sender in this room — their nickname or display name, or their
    /// short id — as labelled when this view was made. `sender` is who they are.
    #[serde(default)]
    pub sender_label: String,
    /// Another member's name or id looks like `sender_label`, so a frontend must show the
    /// sender's id beside it.
    #[serde(default)]
    pub sender_ambiguous: bool,
    pub body: String,
    pub sent_at_ms: i64,
    /// True when replayed from the local transcript rather than just received.
    pub historic: bool,
    /// The file, photo or voice note this message carried. No key: a frontend fetches the
    /// bytes by id through [`Session::fetch_attachment`].
    #[serde(default)]
    pub attachment: Option<AttachmentView>,
    /// What a reply or reaction names this message by. `None` for a message recorded
    /// before replies existed, which can be read but not answered.
    pub id: Option<String>,
    /// The message this one answers, resolved from this device's own transcript.
    pub reply_to: Option<QuoteView>,
    /// Reactions already under it.
    pub reactions: Vec<ReactionView>,
    /// The sender's link card, already checked against this message and reduced to what
    /// is safe to show. `None` when there was no card or it did not pass
    /// ([`crate::embed::Card::view_for`]).
    #[serde(default)]
    pub card: Option<Box<crate::embed::CardView>>,
    /// The room sticker this message is, by name. A frontend draws it from the room's set on
    /// this device ([`Session::custom_asset`]) and shows `body` (`:name:`) if it has none.
    #[serde(default)]
    pub sticker: Option<String>,
}

/// Something that happened while polling, for a frontend to render in the timeline.
///
/// The size lint is allowed: events live for one poll on their way to being serialised, and
/// most of them are messages, so boxing the large variant would allocate for the common case.
#[allow(clippy::large_enum_variant)]
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
    /// The room's disappearing-message timer changed, as the instance now holds it.
    ///
    /// Read back from the instance rather than taken from anybody's announcement, because
    /// the instance's value is the one that actually deletes things — both its own copy and,
    /// through [`History::replay`], this device's. Unattributed for the same reason: the
    /// instance does not say who set it, and a name supplied by a message would be a claim.
    Timer {
        ttl_ms: Option<i64>,
    },
    /// Messages sent at or before `before_ms` are past the room's timer and have been
    /// deleted from this device's transcript. A frontend removes them from the screen too;
    /// a message still displayed after its timer has disappeared from everywhere except the
    /// place its user is looking.
    Expired {
        before_ms: i64,
    },
    /// The reactions under one message changed. The whole set, not the change: a frontend
    /// redraws it rather than keeping its own tally, which is a second copy of a rule.
    Reactions {
        sender: String,
        id: String,
        reactions: Vec<ReactionView>,
    },
    /// Call signalling addressed to this device, for the WebRTC layer rather than the
    /// timeline. Already filtered: signals meant for somebody else never reach a frontend.
    Signal {
        from: String,
        signal: CallSignal,
    },
    /// A device in the open room said, under the room's encryption, what its voice-channel
    /// media is. Only sent when it changed what this device knew. A frontend re-reads
    /// `voice_state` and, if the protection moved, tells its user — §5's announcement.
    VoiceMedia {
        user: String,
        device: String,
        e2ee: bool,
    },
    /// Somebody's profile arrived, or the room's membership changed. Every profile in the
    /// room, not the one that changed: a new name can make two *other* members ambiguous, so
    /// a frontend redraws every label rather than keeping its own copy of that rule.
    Profiles {
        profiles: Vec<ProfileView>,
    },
    /// The room's custom emoji, stickers and sounds changed. A frontend fetches the new
    /// assets with `prepare_custom_sync` straight away — all of them, used or not — and
    /// redraws; see `crate::custom` for why it must not wait for first use.
    Custom {
        set: CustomSetView,
    },
}

struct OpenRoom {
    convo: Conversation,
    seal: RoomSeal,
    cursor: u64,
    /// The disappearing-message timer as last read from the instance.
    ttl: Option<i64>,
    /// When `ttl` was last read, so polling re-reads it on a slower clock than messages.
    ttl_checked_ms: i64,
    /// Replies and reactions, folded over the transcript. Rebuilt whenever the timer sweeps
    /// it, so nothing here outlives the message it describes.
    thread: Thread,
    /// The accounts the instance last listed for this room, so a name can be checked
    /// against members who are waiting as well as those in the group.
    listed: Vec<UserId>,
    /// What to call everyone, and who needs their id shown. See [`crate::profile::labels`].
    labels: HashMap<UserId, Label>,
    /// The instance's roles for this room, as last read: who may change its custom set.
    /// `None` until first read.
    roles: Option<HashMap<UserId, String>>,
    /// When `roles` was last read. On the timer's clock — never because a set arrived.
    roles_checked_ms: i64,
    /// The welcome that goes with this device's pending commit, held until the commit is
    /// known to have landed. Sent early, it would invite someone into an epoch nobody else
    /// may ever reach.
    held_welcome: Option<Vec<u8>>,
    /// Welcomes whose commits landed, not yet sent. In memory only, like `held_welcome`: a
    /// restart before they go leaves the newcomer in the group but never welcomed.
    unsent_welcomes: Vec<Vec<u8>>,
}

/// How often an open room re-reads its timer and sweeps its transcript.
///
/// Any member may change the timer (`docs/10-roadmap.md`), from any client — the CLI's `/ttl`
/// announces nothing — so the only reliable way to notice is to ask. Asking on every poll
/// would double the requests an idle room makes; ten seconds bounds how long a stale timer
/// can be shown, and how long an expired message can outlive its timer on this disk while
/// the room stays open.
const TIMER_RECHECK_MS: i64 = 10_000;

/// A call this device is being rung for: which call, and who announced it.
///
/// Who is kept so a decline can be addressed to them — a decline broadcast to the room
/// would tell every participant, rather than the person who rang.
struct Ringing {
    call: String,
    from: String,
}

/// One signed-in client.
pub struct Session {
    client: Client<HttpTransport>,
    mls: Arc<MlsSession>,
    index: ConversationIndex,
    contacts: ContactStore,
    history: History,
    profiles: ProfileStore,
    /// Each room's custom emoji, stickers and sounds, and the cache they are drawn from.
    custom: crate::custom::CustomStore,
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
    ringing: Option<Ringing>,
    /// This device's seat in a voice channel, if it holds one. See `session::voice`.
    voice: Option<voice::Seat>,
    /// What each device in the open room has announced about its voice media.
    voice_modes: voice::Modes,
    /// Attachments seen in the open room, with the keys that open them. Never handed to a
    /// frontend; see `attachments.rs` for why a frontend can only fetch what is in here.
    attachments: attachments::Known,
    /// How often polling re-reads the open room's timer. [`TIMER_RECHECK_MS`] outside tests.
    timer_recheck_ms: i64,
    /// GIF search through the instance's relay, made on first use. See `crate::gifs`.
    gifs: Option<Arc<crate::gifs::Gifs>>,
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
            profiles: ProfileStore::open(&dir)?,
            custom: crate::custom::CustomStore::open(&dir)?,
            open: None,
            dir: dir.clone(),
            tls,
            call: None,
            negotiated: false,
            ringing: None,
            voice: None,
            voice_modes: HashMap::new(),
            attachments: attachments::Known::new(),
            timer_recheck_ms: TIMER_RECHECK_MS,
            gifs: None,
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
        self.start_group(created.room, created.seal)
    }

    /// Found the encrypted group for a room this device just created, and open it.
    ///
    /// Shared by rooms and channels: a channel is a room, and its group starts the same way —
    /// with only this device in it, everyone else waiting to be admitted.
    fn start_group(&mut self, room: RoomId, seal: RoomSeal) -> Result<String, SessionError> {
        let convo = Conversation::create_encrypted(
            seal,
            room,
            self.client.user(),
            self.client.device(),
            self.mls.clone(),
        )?;
        self.index.record(room, &seal, convo.group_id())?;
        let cursor = self.index.cursor(&room);
        // A room is created without a timer; nobody has had the chance to set one.
        let mut open = OpenRoom {
            convo,
            seal,
            cursor,
            ttl: None,
            ttl_checked_ms: now_ms(),
            thread: Thread::default(),
            listed: Vec::new(),
            labels: HashMap::new(),
            roles: None,
            roles_checked_ms: now_ms(),
            held_welcome: None,
            unsent_welcomes: Vec::new(),
        };
        self.relabel(&mut open);
        self.refresh_roles(&mut open);
        self.open = Some(open);
        // Found by a probe: without this, creating a room left the previous room's
        // attachments fetchable from the new one.
        self.attachments.clear();
        Ok(room.to_string())
    }

    /// Every DM and group this device knows about. Channels are listed by
    /// [`Session::space`], under their space.
    pub fn rooms(&self) -> Vec<RoomSummary> {
        self.index
            .rooms()
            .filter(|(_, record)| record.space.is_none())
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
        // A voice channel too: this device only polls the open room, so it would stop
        // hearing announcements — including a fallback — from the channel it left behind.
        let _ = self.voice_leave();
        self.voice_modes.clear();
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
        let ttl = self.client.room_ttl(room).ok().flatten();
        // The local transcript, with the room's disappearing timer applied.
        let entries = self.history.replay(room, ttl, now_ms())?;
        // A room's attachments are fetchable only while it is open.
        attachments::remember(&mut self.attachments, &entries);
        let thread = Thread::build(&entries);
        let labels = profiles::labels_for(&self.profiles, self.client.user(), &convo, &[]);
        let views = entries
            .iter()
            .filter(|e| e.reaction.is_none())
            .map(|e| view(e, &thread, &labels, true))
            .collect();
        self.open = Some(OpenRoom {
            convo,
            seal,
            cursor,
            ttl,
            ttl_checked_ms: now_ms(),
            thread,
            listed: Vec::new(),
            labels,
            roles: None,
            roles_checked_ms: now_ms(),
            held_welcome: None,
            unsent_welcomes: Vec::new(),
        });
        // Who may change the room's custom set, read now rather than when a set arrives.
        if let Some(mut open) = self.open.take() {
            self.refresh_roles(&mut open);
            self.open = Some(open);
        }
        Ok(views)
    }

    pub fn open_room_id(&self) -> Option<String> {
        self.open.as_ref().map(|o| o.convo.room().to_string())
    }

    /// The badge for the open room, derived locally.
    pub fn open_room_tier(&self) -> Option<String> {
        self.open.as_ref().map(|o| o.seal.tier().label().to_string())
    }

    /// Send a message to the open room.
    ///
    /// Returns it as the timeline should show it. MLS never decrypts a device's own message
    /// back to it, so polling will not deliver this; without the return value the sender's
    /// own words appeared only after reopening the room.
    pub fn send(&mut self, text: &str) -> Result<MessageView, SessionError> {
        self.send_message(text, None, None)
    }

    /// Reply to a message on this device's screen, named by its sender and id.
    ///
    /// Refused for a message this device does not hold: the quote shown to everyone else is
    /// resolved from *their* transcripts, and a reply to nothing would quote nothing.
    pub fn reply(
        &mut self,
        text: &str,
        sender: &str,
        id: &str,
    ) -> Result<MessageView, SessionError> {
        let target = self.known_target(sender, id)?;
        self.send_message(text, Some(target), None)
    }

    fn send_message(
        &mut self,
        text: &str,
        reply_to: Option<MessageRef>,
        card: Option<crate::embed::Card>,
    ) -> Result<MessageView, SessionError> {
        let open = self.open.as_mut().ok_or(SessionError::NoRoomOpen)?;
        if open.convo.group_id().is_none() {
            return Err(SessionError::NoGroupYet);
        }
        let at = now_ms();
        let card = card.map(crate::embed::Card::clamp);
        let outbound = open.convo.send_text(text.as_bytes(), reply_to.clone(), card.clone(), at)?;
        self.client.send(open.convo.room(), &outbound.envelope)?;

        // Recorded locally because MLS will not decrypt our own message back to us — without
        // this the transcript is every reply and none of the prompts.
        let entry = HistoryEntry {
            sender: self.client.user(),
            sent_at_ms: at,
            body: text.as_bytes().to_vec(),
            attachment_name: None,
            attachment: None,
            id: Some(outbound.commitment.to_hex()),
            reply_to,
            reaction: None,
            card,
            sticker: None,
        };
        self.history.append(open.convo.room(), &entry)?;
        open.thread.record(&entry);
        Ok(view(&entry, &open.thread, &open.labels, false))
    }

    /// React to a message on this device's screen, or withdraw this user's reaction to it
    /// (`emoji: None`). Returns every reaction now under that message.
    pub fn react(
        &mut self,
        sender: &str,
        id: &str,
        emoji: Option<&str>,
    ) -> Result<Vec<ReactionView>, SessionError> {
        let target = self.known_target(sender, id)?;
        let reaction = Reaction { target: target.clone(), emoji: emoji.map(str::to_owned) };
        // The same rule every recipient applies on receipt, applied first so a refusal is
        // a sentence here rather than a reaction that silently vanishes everywhere else.
        if !reaction.is_valid() {
            return Err(SessionError::BadReaction);
        }
        let open = self.open.as_mut().ok_or(SessionError::NoRoomOpen)?;
        if open.convo.group_id().is_none() {
            return Err(SessionError::NoGroupYet);
        }
        let at = now_ms();
        let outbound = open.convo.send_reaction(reaction.clone(), at)?;
        self.client.send(open.convo.room(), &outbound.envelope)?;
        let entry = HistoryEntry {
            sender: self.client.user(),
            sent_at_ms: at,
            body: Vec::new(),
            attachment_name: None,
            attachment: None,
            id: None,
            reply_to: None,
            reaction: Some(reaction),
            card: None,
            sticker: None,
        };
        self.history.append(open.convo.room(), &entry)?;
        open.thread.record(&entry);
        Ok(open.thread.reactions(&target))
    }

    /// Parse a frontend's `(sender, id)` and check this device holds that message.
    fn known_target(&self, sender: &str, id: &str) -> Result<MessageRef, SessionError> {
        let open = self.open.as_ref().ok_or(SessionError::NoRoomOpen)?;
        let sender: UserId = sender.parse().map_err(|_| SessionError::UnknownMessage)?;
        let target = MessageRef { sender, id: id.to_owned() };
        if !open.thread.knows(&target) {
            return Err(SessionError::UnknownMessage);
        }
        Ok(target)
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
        let mut profiles_changed = false;
        let mut custom_changed = false;

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
                        // Nothing sent before the welcome is readable here, so whatever was
                        // last sent to this room — by this device, in an earlier membership —
                        // is unknown to the group as it now is.
                        let _ = self.profiles.resend(&room);
                        profiles_changed = true;
                    }
                }
                continue;
            }

            let unsettled = open.convo.has_pending_commit();
            let outcome = open.convo.receive(&message.envelope);
            if unsettled && !open.convo.has_pending_commit() {
                if message.envelope.sender_device == self.client.device() {
                    // Ours, back from the log: it landed even though the upload failed.
                    open.unsent_welcomes.extend(open.held_welcome.take());
                } else {
                    // Someone else's commit was sequenced first, and `mls-rs` dropped ours
                    // for it. Whoever this device was adding was not added: still waiting.
                    open.held_welcome = None;
                }
            }
            match outcome {
                Ok(TimelineEvent::Message(received)) => {
                    // Signalling first: it arrives as an ordinary encrypted message with an
                    // empty body, and rendering that in the timeline would show every
                    // participant a stream of blank lines during a call.
                    if let Some(signal) = received.signal {
                        let me = self.client.user().to_string();
                        let from = message.envelope.sender.to_string();
                        // A voice channel's media announcement is not part of a rung call.
                        // Recorded per device, from the envelope `receive` has already
                        // checked against the roster — never from anything the instance
                        // says on its own. Own announcements are skipped by device, not by
                        // account: another of this user's devices is someone else's media.
                        if signal.kind == SignalKind::VoiceMedia {
                            let (user, device) =
                                (message.envelope.sender, message.envelope.sender_device);
                            if device != self.client.device() {
                                self.open = Some(open);
                                let news = self.voice_media_heard(user, device, &signal.payload);
                                open = self.open.take().expect("just put back");
                                if news {
                                    events.push(Event::VoiceMedia {
                                        user: user.to_string(),
                                        device: device.to_string(),
                                        e2ee: signal.payload == crate::call::VOICE_E2EE,
                                    });
                                }
                            }
                            continue;
                        }
                        // Own signals come back through the room; applying one to yourself
                        // would have a peer negotiating with itself.
                        if from != me && signal.is_for(&me) {
                            if let Some(signal) = self.reconcile(&from, *signal) {
                                events.push(Event::Signal { from, signal });
                            }
                        }
                        continue;
                    }
                    // A profile is state, not a message: it updates who is called what and
                    // never enters the transcript. Filed under the envelope's sender, which
                    // `receive` has already checked against the roster — the record itself
                    // has no field naming whose profile it is.
                    if let Some(profile) = received.profile {
                        if message.envelope.sender != self.client.user() {
                            let _ = self.profiles.receive(room, message.envelope.sender, *profile);
                            // At once, so a message later in this same batch is labelled
                            // with the name its sender had when they sent it.
                            self.relabel(&mut open);
                            profiles_changed = true;
                        }
                        continue;
                    }
                    // A room's custom set is state too. Whether its sender may change it is
                    // checked against the roles last read — see `session::custom`.
                    if let Some(set) = received.custom_set {
                        if message.envelope.sender != self.client.user() {
                            custom_changed |= self.receive_custom(
                                &open,
                                message.envelope.sender,
                                message.server_seq,
                                *set,
                            );
                        }
                        continue;
                    }
                    // Attributed to the envelope's sender, for a reaction as for a message:
                    // the payload has no field naming who reacted, so none can be forged.
                    let attachment = received.attachment.map(|a| *a);
                    let entry = HistoryEntry {
                        sender: message.envelope.sender,
                        sent_at_ms: message.envelope.sent_at_ms,
                        body: received.body,
                        attachment_name: attachment.as_ref().map(|a| a.name.clone()),
                        attachment,
                        id: received.franking.as_ref().map(|f| f.commitment.to_hex()),
                        reply_to: received.reply_to.map(|r| *r),
                        reaction: received.reaction.map(|r| *r),
                        card: received.card.map(|c| *c),
                        sticker: received.sticker,
                    };
                    let _ = self.history.append(room, &entry);
                    open.thread.record(&entry);
                    if let Some(a) = &entry.attachment {
                        self.attachments.insert(a.blob, a.clone());
                    }
                    if let Some(reaction) = &entry.reaction {
                        let target = &reaction.target;
                        events.push(Event::Reactions {
                            sender: target.sender.to_string(),
                            id: target.id.clone(),
                            reactions: open.thread.reactions(target),
                        });
                    } else {
                        events.push(Event::Message(view(
                            &entry,
                            &open.thread,
                            &open.labels,
                            false,
                        )));
                    }
                }
                Ok(TimelineEvent::Membership { added, removed, .. }) => {
                    // A new member cannot read anything sent before they joined, this
                    // account's profile included, so it goes again once this poll is done.
                    if !added.is_empty() {
                        let _ = self.profiles.resend(&room);
                        let _ = self.custom.mark_due(&room);
                    }
                    profiles_changed = true;
                    events.push(Event::Membership {
                        joined: added.iter().map(describe_member).collect(),
                        left: removed.iter().map(describe_member).collect(),
                    });
                }
                Ok(TimelineEvent::RemovedFromRoom { .. }) => {
                    // Being ejected means the local transcript goes too: the room is no
                    // longer readable and keeping a plaintext copy is not a courtesy. The
                    // same for what its members called themselves.
                    let _ = self.history.forget(room);
                    let _ = self.profiles.forget(&room);
                    let _ = self.custom.forget(&room);
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

        // A commit of ours still pending after the whole log has been read never reached the
        // instance — the upload failed before this poll began, and the instance commits a
        // message within the request that carries it. Dropped, so this device stays in the
        // epoch everyone else is in.
        if open.convo.has_pending_commit() {
            let _ = open.convo.discard_commit();
            open.held_welcome = None;
        }
        let _ = self.flush_welcomes(&mut open);

        if let Some(live) = self.recheck_timer(&mut open, &mut events) {
            // An expired message takes the only in-memory key to its attachment with it.
            attachments::remember(&mut self.attachments, &live);
        }
        // After everything fetched has been processed, so the group is at its current epoch
        // and a member who just joined can read it. A failure is retried on the next poll.
        let _ = self.flush_profile(&mut open);
        // Roles on their own clock, so the request says nothing about what just arrived.
        if now_ms().saturating_sub(open.roles_checked_ms) >= self.timer_recheck_ms {
            custom_changed |= self.refresh_roles(&mut open);
        }
        let _ = self.flush_custom(&mut open);
        if custom_changed {
            events.push(Event::Custom { set: self.custom_view(&open) });
        }
        if profiles_changed {
            self.relabel(&mut open);
            let mut users: Vec<&UserId> = open.labels.keys().collect();
            users.sort();
            let profiles = users.into_iter().map(|u| self.view_of(&open, u)).collect();
            events.push(Event::Profiles { profiles });
        }
        let _ = self.index.advance(room, open.cursor);
        self.open = Some(open);
        Ok(events)
    }

    /// The open room's disappearing-message timer, in milliseconds. `None` is off.
    ///
    /// As last read from the instance — on opening the room, and every
    /// [`TIMER_RECHECK_MS`] while polling.
    pub fn room_timer(&self) -> Result<Option<i64>, SessionError> {
        Ok(self.open.as_ref().ok_or(SessionError::NoRoomOpen)?.ttl)
    }

    /// Shorten how often polling re-reads the timer. For tests, which cannot wait out
    /// [`TIMER_RECHECK_MS`] on every assertion.
    #[doc(hidden)]
    pub fn set_timer_recheck_ms(&mut self, ms: i64) {
        self.timer_recheck_ms = ms;
    }

    /// Set or clear the open room's disappearing-message timer. Any member may.
    ///
    /// Returns the timer the instance reports *afterwards*, not the one asked for: the
    /// frontend shows what is in force, and the two only differ if something went wrong.
    ///
    /// **It reaches back.** The instance measures every stored message against the current
    /// setting each time the room is read (`Instance::purge_expired`), so turning a timer on
    /// deletes messages already older than it — not only future ones — and this device does
    /// the same to its own transcript here, immediately. `docs/10-roadmap.md` records the
    /// owner's decision as "applies to future messages only"; the instance does not implement
    /// that, and a client telling its user otherwise would be promising them a history the
    /// instance is about to delete. The frontend says so before anyone picks a value, and
    /// `crates/cairn-server/tests/disappearing_session.rs` fails the moment it stops being
    /// true.
    pub fn set_room_timer(&mut self, ttl_ms: Option<i64>) -> Result<Option<i64>, SessionError> {
        // The instance refuses these too. Refusing here as well means the user gets a
        // sentence rather than a status code.
        if ttl_ms.is_some_and(|t| t <= 0) {
            return Err(SessionError::BadTimer);
        }
        let open = self.open.as_mut().ok_or(SessionError::NoRoomOpen)?;
        let room = open.convo.room();
        self.client.set_room_ttl(room, ttl_ms)?;
        let confirmed = self.client.room_ttl(room)?;
        open.ttl = confirmed;
        // Forces the next poll to sweep, so a frontend learns at once which messages on its
        // screen the new timer has just ended.
        open.ttl_checked_ms = i64::MIN;
        open.thread = Thread::build(&self.history.replay(room, confirmed, now_ms())?);
        Ok(confirmed)
    }

    /// Re-read the timer, announce a change, and delete whatever has expired since the last
    /// sweep. Failures are swallowed: a missed recheck is retried on the next poll, and
    /// failing the poll over it would drop the messages it had already fetched.
    fn recheck_timer(
        &self,
        open: &mut OpenRoom,
        events: &mut Vec<Event>,
    ) -> Option<Vec<HistoryEntry>> {
        let now = now_ms();
        if now.saturating_sub(open.ttl_checked_ms) < self.timer_recheck_ms {
            return None;
        }
        let room = open.convo.room();
        let Ok(current) = self.client.room_ttl(room) else { return None };
        open.ttl_checked_ms = now;
        if current != open.ttl {
            open.ttl = current;
            events.push(Event::Timer { ttl_ms: current });
        }
        if let Some(ttl) = current {
            // Rewrites the transcript without anything past the timer — deletion, not a
            // filter on what is shown.
            let live = self.history.replay(room, Some(ttl), now).ok();
            if let Some(live) = &live {
                open.thread = Thread::build(live);
            }
            events.push(Event::Expired { before_ms: now.saturating_sub(ttl) });
            return live;
        }
        None
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
            .or_else(|| self.ringing.take().map(|r| r.call))
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

    /// Say no to the call this device is being rung for.
    ///
    /// Addressed to whoever rang, and sent under *their* call id: this device is not in a
    /// call, so there is no id of its own to stamp. Forgets the ring, so pressing "call"
    /// afterwards starts a call rather than quietly joining the one just declined.
    ///
    /// A no-op when nothing is ringing: declining twice, or after the caller hung up, must
    /// not put a stray signal on the wire.
    pub fn call_decline(&mut self) -> Result<(), SessionError> {
        if self.call.is_some() {
            return Ok(());
        }
        let Some(ring) = self.ringing.take() else { return Ok(()) };
        let decline = CallSignal {
            call: ring.call,
            kind: SignalKind::Decline,
            to: Some(ring.from),
            payload: String::new(),
        };
        let open = self.open.as_mut().ok_or(SessionError::NoRoomOpen)?;
        if open.convo.group_id().is_none() {
            return Err(SessionError::NoGroupYet);
        }
        let outbound = open.convo.send_signal(decline, now_ms())?;
        self.client.send(open.convo.room(), &outbound.envelope)?;
        Ok(())
    }

    /// What a call in the open room should use: ICE servers, with fresh relay credentials
    /// when the instance runs a relay, and whether the room is a DM.
    ///
    /// Asked for on every join rather than once per session, because relay credentials
    /// expire. Without an open room there is no call to configure, and the answer is the
    /// STUN-only default.
    pub fn call_config(&self) -> Result<crate::call::CallConfig, SessionError> {
        let (instance, direct) = match &self.open {
            Some(open) => (self.client.turn_credentials(open.convo.room())?, open.seal.is_direct()),
            None => (Vec::new(), false),
        };
        let ice_servers = crate::call::ice_servers_with(instance);
        Ok(crate::call::CallConfig {
            has_relay: crate::call::has_relay(&ice_servers),
            ice_servers,
            max_participants: crate::call::MAX_MESH_PARTICIPANTS,
            direct,
        })
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
    fn reconcile(&mut self, from: &str, mut signal: CallSignal) -> Option<CallSignal> {
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
                    self.ringing =
                        Some(Ringing { call: signal.call.clone(), from: from.to_string() });
                    Some(signal)
                }
                SignalKind::Leave => {
                    // Whoever was calling has given up. Forgetting the id stops a later
                    // `call_join` adopting a call nobody is in; if somebody else is still in
                    // it, their acknowledgement renames this device into it anyway.
                    if self.ringing.as_ref().is_some_and(|r| r.call == signal.call) {
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
        let mut views = member_views(listed.clone(), &open.convo.members(), &self.contacts);

        // Remember who the instance listed, so a name is labelled against waiting members
        // too, then attach each member's profile.
        if let Some(mut open) = self.open.take() {
            open.listed = listed.iter().map(|(u, _)| *u).collect();
            // A member list is a role list; a set held for want of one may now apply. A
            // change shows up on the next poll's `custom` event or the next `custom_set`.
            self.apply_roles(&mut open, &listed);
            self.relabel(&mut open);
            for v in &mut views {
                if let Ok(user) = v.user.parse::<UserId>() {
                    v.profile = Some(self.view_of(&open, &user));
                }
            }
            self.open = Some(open);
        }
        Ok(views)
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
        // Taken out for the duration, so a welcome can be sent through `self` with the room
        // in hand; put back whatever happens.
        let mut open = self.open.take().ok_or(SessionError::NoRoomOpen)?;
        let result = self.admit_packages(&mut open, &claimed);
        let recorded = self.index.record(open.convo.room(), &open.seal, open.convo.group_id());
        self.open = Some(open);
        result?;
        Ok(recorded?)
    }

    fn admit_packages(
        &mut self,
        open: &mut OpenRoom,
        claimed: &[crate::client::ClaimedKeyPackage],
    ) -> Result<(), SessionError> {
        for package in claimed {
            let bytes = hex::decode(&package.key_package).map_err(|_| SessionError::NoGroupYet)?;
            let key_package = cairn_crypto::mls::parse_message(&bytes)?;
            let group = open.convo.group_mut().ok_or(SessionError::NoGroupYet)?;
            let output = group.stage_add(key_package)?;
            let commit = output.commit.to_bytes().map_err(|_| SessionError::NoGroupYet)?;
            // Held before the commit goes, so a commit whose fate is unknown still has its
            // welcome when a poll finds it in the log.
            open.held_welcome = match output.welcome {
                Some(w) => Some(w.to_bytes().map_err(|_| SessionError::NoGroupYet)?),
                None => None,
            };
            relay_commit(&self.client, open, &commit)?;
            self.flush_welcomes(open)?;
        }
        Ok(())
    }

    /// Send the welcomes held for people this device added, once nothing is pending.
    ///
    /// Retried on every poll until it goes: a newcomer whose commit landed is in the group
    /// and no longer listed as waiting, so nothing else would ever send it again.
    fn flush_welcomes(&mut self, open: &mut OpenRoom) -> Result<(), SessionError> {
        if open.convo.has_pending_commit() || open.unsent_welcomes.is_empty() {
            return Ok(());
        }
        let room = open.convo.room();
        while let Some(welcome) = open.unsent_welcomes.first() {
            let wrapped = open.convo.wrap_handshake(welcome, now_ms())?;
            self.client.send(room, &wrapped)?;
            open.unsent_welcomes.remove(0);
        }
        // This device committed the add, so its own poll reports nothing to prompt these —
        // and the new member still needs this account's profile, sent after the welcome.
        let _ = self.profiles.resend(&room);
        let _ = self.custom.mark_due(&room);
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

/// Upload a commit this device staged, and settle it if the instance accepted it.
///
/// On any failure the commit stays pending rather than being applied or dropped, because a
/// failed request does not say whether the instance stored it: a connection lost after the
/// request went out looks the same as one refused before it. The next poll reads the log
/// and settles it either way. Applying first, as this used to, put the committer alone in
/// an epoch nobody else reached whenever the upload was lost — a probe that dropped one
/// commit on its way to the instance left the room unable to read its owner for good.
fn relay_commit(
    client: &Client<HttpTransport>,
    open: &mut OpenRoom,
    commit: &[u8],
) -> Result<(), SessionError> {
    let wrapped = open.convo.wrap_handshake(commit, now_ms())?;
    client.send(open.convo.room(), &wrapped)?;
    open.convo.group_mut().ok_or(SessionError::NoGroupYet)?.confirm_commit()?;
    open.unsent_welcomes.extend(open.held_welcome.take());
    Ok(())
}

/// Link-preview settings for one profile, persisted beside its state.
///
/// Its own file rather than a shared preferences file, so it can never clobber — or be
/// clobbered by — another setting written by code that does not know about this one.
///
/// **Everything off by default.** Building a preview means this device contacting the
/// linked site, which sees the sender's IP address; `docs/05-embeds.md` §1 requires that to
/// be opted into per platform. A file written by an earlier version — one global `enabled`
/// switch — loads as all off: nobody chose these per-platform switches yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct LinkPreviewSettings {
    /// One switch per platform, and one for every other website.
    #[serde(flatten)]
    pub sites: crate::embed::Sites,
    /// Whether an Instagram link the site will not describe may be sent to a third-party
    /// proxy ([`crate::embed::instagram::SUGGESTED_PROXY`]). **Off by default** — the proxy
    /// sees the link, and `docs/05-embeds.md` forbids taking a less private path silently.
    /// Has no effect unless Instagram previews are on.
    #[serde(default)]
    pub instagram_proxy: bool,
}

/// A message on its way out, holding everything needed to build its preview **without the
/// session**.
///
/// Sending is split in three — [`Session::begin_send`], [`PendingSend::unfurl`],
/// [`Session::finish_send`] — so the network fetch happens with no lock held. Fetching while
/// holding the session would stall polling (and, in the desktop shell, the window) for as
/// long as a slow site takes; that is what the split is for.
#[derive(Debug)]
pub struct PendingSend {
    room: RoomId,
    text: String,
    reply_to: Option<MessageRef>,
    preview: Option<Plan>,
    card: Option<crate::embed::Card>,
}

/// What one preview may do: which URL, which sites it may contact on the way (every hop is
/// checked, not only the link), and whether a third-party proxy may be asked.
#[derive(Debug)]
struct Plan {
    url: String,
    sites: crate::embed::Sites,
    proxy: crate::embed::instagram::ProxyPolicy,
}

impl PendingSend {
    /// Fetch the preview, if this message has a link and previews are on.
    ///
    /// Never fails: no card is a perfectly good outcome, and a preview is never worth
    /// holding back a message.
    pub fn unfurl(&mut self) {
        if let Some(plan) = &self.preview {
            self.card = crate::embed::preview(&plan.url, plan.sites, &plan.proxy);
        }
    }

    /// The URL a preview will be fetched for, if any. For a UI to say what is happening.
    pub fn preview_url(&self) -> Option<&str> {
        self.preview.as_ref().map(|plan| plan.url.as_str())
    }

    /// Attach a card built some other way — by a test, or a platform-supplied fetcher.
    ///
    /// Grants nothing a modified client does not already have: a card is the sender's claim
    /// however it was made, it is clamped on the way out and again on receipt, and a
    /// recipient drops one whose URL is not a link in the message ([`crate::embed::Card::view_for`]).
    pub fn with_card(mut self, card: crate::embed::Card) -> Self {
        self.card = Some(card);
        self
    }
}

impl Session {
    fn link_preview_path(&self) -> PathBuf {
        self.dir.join("link-previews.json")
    }

    /// This profile's link-preview settings. A missing or unreadable file means defaults.
    pub fn link_previews(&self) -> LinkPreviewSettings {
        std::fs::read(self.link_preview_path())
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default()
    }

    pub fn set_link_previews(&self, settings: LinkPreviewSettings) -> Result<(), SessionError> {
        let bytes = serde_json::to_vec_pretty(&settings)
            .map_err(|e| SessionError::Preferences(e.to_string()))?;
        std::fs::write(self.link_preview_path(), bytes)
            .map_err(|e| SessionError::Preferences(e.to_string()))
    }

    /// Start sending `text` to the open room, optionally as a reply to `(sender, id)`.
    /// Cheap: decides *whether* to fetch a preview and captures which room the message is
    /// for, and fetches nothing.
    pub fn begin_send(
        &self,
        text: &str,
        reply: Option<(&str, &str)>,
    ) -> Result<PendingSend, SessionError> {
        let open = self.open.as_ref().ok_or(SessionError::NoRoomOpen)?;
        if open.convo.group_id().is_none() {
            return Err(SessionError::NoGroupYet);
        }
        let reply_to = match reply {
            Some((sender, id)) => Some(self.known_target(sender, id)?),
            None => None,
        };
        let preview = preview_plan(self.link_previews(), text);
        Ok(PendingSend {
            room: open.convo.room(),
            text: text.to_string(),
            reply_to,
            preview,
            card: None,
        })
    }

    /// Encrypt and send a prepared message, returning it as the timeline should show it.
    ///
    /// **Refuses if the open room changed** since [`Session::begin_send`]. The preview fetch
    /// runs with no lock held and can take seconds; a user who switches rooms meanwhile
    /// would otherwise have the message delivered to whichever room is open when the fetch
    /// returns — somebody else's conversation.
    pub fn finish_send(&mut self, pending: PendingSend) -> Result<MessageView, SessionError> {
        let open = self.open.as_ref().ok_or(SessionError::NoRoomOpen)?;
        if open.convo.room() != pending.room {
            return Err(SessionError::RoomChanged);
        }
        self.send_message(&pending.text, pending.reply_to, pending.card)
    }
}

/// Which link to fetch for `text`, under which switches — or nothing.
///
/// `None` unless the first link's own site is switched on: a link to a platform the user has
/// not enabled is not fetched, and neither is a proxy asked about it.
fn preview_plan(settings: LinkPreviewSettings, text: &str) -> Option<Plan> {
    use crate::embed::instagram::{ProxyPolicy, SUGGESTED_PROXY};
    let url = crate::embed::first_url(text)?;
    settings.sites.permits(url).ok()?;
    let proxy = if settings.instagram_proxy && settings.sites.instagram {
        ProxyPolicy::with_hosts([SUGGESTED_PROXY])
    } else {
        ProxyPolicy::disabled()
    };
    Some(Plan { url: url.to_string(), sites: settings.sites, proxy })
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
                profile: None,
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
            profile: None,
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

/// A transcript entry as a frontend shows it, with its quote and reactions resolved.
fn view(
    entry: &HistoryEntry,
    thread: &Thread,
    labels: &HashMap<UserId, Label>,
    historic: bool,
) -> MessageView {
    let own = entry.id.as_ref().map(|id| MessageRef { sender: entry.sender, id: id.clone() });
    let label = labels.get(&entry.sender);
    let body = String::from_utf8_lossy(&entry.body).to_string();
    MessageView {
        sender: entry.sender.to_string(),
        sender_label: label
            .map_or_else(|| crate::profile::short_id(&entry.sender), |l| l.text.clone()),
        sender_ambiguous: label.is_some_and(|l| l.ambiguous),
        sent_at_ms: entry.sent_at_ms,
        historic,
        attachment: entry.attachment.as_ref().map(AttachmentView::of),
        id: entry.id.clone(),
        reply_to: entry.reply_to.as_ref().map(|r| thread.quote(r)),
        reactions: own.map(|r| thread.reactions(&r)).unwrap_or_default(),
        // Rendered from what arrived inside the envelope. Nothing is fetched to draw it —
        // the recipient-fetches-nothing rule (`docs/05-embeds.md`).
        card: entry.card.as_ref().and_then(|c| c.view_for(&body)).map(Box::new),
        sticker: entry.sticker.clone(),
        body,
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

#[cfg(test)]
mod link_preview_tests {
    use super::*;

    /// A session that never touches the network: the identity is already claimed, and the
    /// instance address is one nothing listens on.
    fn offline(name: &str) -> (Session, PathBuf) {
        let dir = std::env::temp_dir().join(format!("cairn-lp-{name}-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let identity = StoredIdentity {
            user: uuid::Uuid::new_v4(),
            device: uuid::Uuid::new_v4(),
            claimed: true,
        };
        std::fs::write(dir.join("identity.json"), serde_json::to_vec(&identity).unwrap()).unwrap();
        let session = Session::open(name, "http://127.0.0.1:9", Some(&dir)).unwrap();
        (session, dir)
    }

    #[test]
    fn every_preview_switch_is_off_until_someone_changes_it() {
        let (session, dir) = offline("defaults");
        let settings = session.link_previews();
        assert_eq!(settings, LinkPreviewSettings::default());
        assert!(!settings.sites.any(), "no site may be contacted by default");
        assert!(!settings.instagram_proxy, "a third party must never see links by default");
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn a_settings_file_from_the_single_switch_era_loads_as_all_off() {
        let (session, dir) = offline("migrate");
        std::fs::write(dir.join("link-previews.json"), br#"{"enabled":true}"#).unwrap();
        assert_eq!(session.link_previews(), LinkPreviewSettings::default());
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn a_preview_setting_survives_a_restart() {
        let (session, dir) = offline("persist");
        let chosen = LinkPreviewSettings {
            sites: crate::embed::Sites { youtube: true, web: true, ..Default::default() },
            instagram_proxy: true,
        };
        session.set_link_previews(chosen).unwrap();
        drop(session);
        let reopened = Session::open("persist", "http://127.0.0.1:9", Some(&dir)).unwrap();
        assert_eq!(reopened.link_previews(), chosen);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn a_message_is_never_delivered_to_a_room_opened_while_its_preview_loaded() {
        // The race the lock-free fetch creates: begin in room A, switch to room B during
        // the fetch, finish. The message must not land in B.
        let (mut session, dir) = offline("race");
        let a = RoomId::new();
        let b = RoomId::new();
        session.open_room(&a.to_string()).unwrap();
        let pending =
            PendingSend { room: a, text: "hi".into(), reply_to: None, preview: None, card: None };
        session.open_room(&b.to_string()).unwrap();
        assert!(
            matches!(session.finish_send(pending), Err(SessionError::RoomChanged)),
            "a message begun in one room must not be sent to another"
        );
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn only_a_link_to_a_switched_on_site_is_planned() {
        use crate::embed::Sites;
        let reel = "look https://www.instagram.com/reel/abc123/";
        let video = "watch https://youtu.be/dQw4w9WgXcQ";

        let off = LinkPreviewSettings { sites: Sites::default(), instagram_proxy: true };
        assert!(preview_plan(off, reel).is_none(), "off means nothing is fetched at all");
        assert!(preview_plan(off, video).is_none());

        let youtube = LinkPreviewSettings {
            sites: Sites { youtube: true, ..Sites::default() },
            instagram_proxy: true,
        };
        assert!(preview_plan(youtube, reel).is_none(), "YouTube on does not mean Instagram on");
        let plan = preview_plan(youtube, video).expect("an enabled platform is previewed");
        assert_eq!(plan.url, "https://youtu.be/dQw4w9WgXcQ");
        assert!(!plan.proxy.is_enabled(), "the Instagram proxy needs Instagram on too");
        assert!(!plan.sites.web, "and the switches travel with the plan, for every hop");

        let instagram = LinkPreviewSettings {
            sites: Sites { instagram: true, ..Sites::default() },
            instagram_proxy: false,
        };
        assert!(!preview_plan(instagram, reel).unwrap().proxy.is_enabled());
        let proxied = LinkPreviewSettings { instagram_proxy: true, ..instagram };
        assert!(preview_plan(proxied, reel).unwrap().proxy.is_enabled());
        assert!(preview_plan(proxied, "no links here").is_none());
    }
}
