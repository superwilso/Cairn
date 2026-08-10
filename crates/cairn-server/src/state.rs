//! Instance state and the rules the server enforces.
//!
//! Logic lives here rather than in the HTTP handlers so it can be tested without a
//! socket. The handlers in [`crate::http`] are a thin translation layer.
//!
//! Accounts, devices, rooms and invites are held in memory and written through
//! [`crate::storage`] record-by-record as they change. **Messages are not held in memory**:
//! they are the one unbounded thing here, and they are read back from storage on demand.
//! The franking key survives a restart, which is the property the whole persistence layer
//! exists for.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use cairn_crypto::franking::{Commitment, Context as FrankingContext, ServerFrankingKey, Tag};
use cairn_crypto::TranscriptReport;
use cairn_proto::{
    BlobId, DeviceId, Envelope, RoomId, RoomSeal, RoomShape, ShapeError, UserId, Username,
};

use crate::storage::{Storage, StorageError, Write};

#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    #[error("no such room")]
    NoSuchRoom,
    #[error("rejected: {0}")]
    Rejected(#[from] cairn_proto::envelope::EnvelopeError),
    #[error("invalid room shape: {0}")]
    Shape(#[from] ShapeError),
    #[error("malformed franking commitment")]
    BadCommitment,
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error("message is not signed")]
    Unsigned,
    #[error("unknown device; register it before sending")]
    UnknownDevice,
    #[error("signature does not verify for the sending device")]
    BadSignature,
    #[error("device is registered to a different account")]
    DeviceUserMismatch,
    #[error("device is already registered")]
    DeviceAlreadyRegistered,
    #[error("account is already claimed; link a device instead")]
    AccountAlreadyClaimed,
    #[error("no such account")]
    NoSuchAccount,
    #[error("the authorizing device does not belong to this account")]
    AuthorizingDeviceNotOnAccount,
    #[error("device authorization signature does not verify")]
    BadDeviceAuthorization,
    #[error("registration on this instance requires an invite")]
    InviteRequired,
    #[error("invite is unknown, already used, or expired")]
    InviteInvalid,
    #[error("not a member of this room")]
    NotAMember,
    #[error("this room is not open to join; a member must add you")]
    RoomNotOpen,
    #[error("room is at its member ceiling")]
    RoomFull,
    #[error("insufficient role in this room for that action")]
    InsufficientRole,
    #[error("a room must keep at least one owner")]
    LastOwner,
    #[error("that account is not a member of this room")]
    TargetNotAMember,
    #[error("request signature is missing, malformed, or does not verify")]
    BadRequestAuth,
    #[error("request timestamp is outside the accepted window")]
    RequestExpired,
    #[error("that device is registered to a different account")]
    NotYourDevice,
    #[error("no key packages are available for that account; it must publish more")]
    NoKeyPackages,
    #[error("key package is malformed")]
    BadKeyPackage,
    #[error("too many key packages; publish at most {MAX_KEY_PACKAGES_PER_DEVICE} per device")]
    TooManyKeyPackages,
    #[error("rate limited; retry later")]
    RateLimited,
    #[error("no such attachment")]
    NoSuchBlob,
    #[error("attachment is larger than this instance accepts ({MAX_BLOB_BYTES} bytes)")]
    BlobTooLarge,
    #[error("attachment is empty")]
    BlobEmpty,
    #[error("that username is already taken")]
    UsernameTaken,
    #[error("this account already has a username")]
    UsernameAlreadySet,
    #[error("no account has that username")]
    NoSuchUsername,
    #[error("not a usable username: {0}")]
    BadUsername(String),
    #[error("a disappearing-message timer must be a positive duration")]
    BadTtl,
    #[error("this invite is unknown, spent, expired, or revoked")]
    RoomInviteInvalid,
    #[error("an invite may admit at most {MAX_INVITE_USES} people; an unlimited one would be a public invite")]
    InviteUsesTooHigh,
}

/// How many unclaimed key packages one device may hold.
///
/// A ceiling rather than a target. Every stored package is server-held state an
/// unauthenticated party never sees but an authenticated one can drain, and without a cap
/// a device could park unbounded storage on someone else's instance.
pub const MAX_KEY_PACKAGES_PER_DEVICE: usize = 100;

/// The largest attachment this build accepts, in bytes.
///
/// A ceiling, not a target, and deliberately modest. Every byte here is storage and egress
/// the *operator* pays for — `docs/13-customisation.md` §2 is explicit that "unlimited
/// uploads, free" means the person running the server finds out when the bill arrives. An
/// instance that wants more should raise this knowingly.
pub const MAX_BLOB_BYTES: usize = 25 * 1024 * 1024;

/// How many times one account may claim key packages *for the same target* per window.
///
/// A legitimate claim happens when adding someone to a room, so a handful per hour is
/// generous. Probing showed why a ceiling is needed at all: a single authenticated account
/// drained a victim's entire published supply in a tight loop, after which **nobody** could
/// add that victim to a room until they came back online and published more. That is a
/// targeted denial of service on one person, and it left no trace the victim could see.
pub const MAX_CLAIMS_PER_TARGET: usize = 3;

/// How many key package claims one account may make in total per window, across all targets.
///
/// The per-target limit alone does not bound the work: an attacker can walk a list of user
/// ids, and user ids are on every message. This is the ceiling that makes enumeration cost
/// something.
pub const MAX_CLAIMS_TOTAL: usize = 30;

/// The most people a single room invite may admit.
///
/// A ceiling rather than a preference, and the reason is the tier model rather than
/// tidiness. `RoomSeal::may_mint_public_invite` forbids a *public* invite to a T1 or T2 room
/// because discoverability is an input to `derive_tier` — a published invite would mean the
/// room should have been T3, and the tier cannot change (ADR-001). A capability spent on
/// redemption does not make a room discoverable, so a capped link is fine. An **uncapped**
/// one is a public invite wearing a different name, which is why there is no "unlimited"
/// option here and must never be one.
pub const MAX_INVITE_USES: u32 = 100;

/// How many username lookups one account may make per window.
///
/// Exact-match-only resolution stops an attacker *listing* the instance's accounts. It does
/// not stop them *guessing* — a dictionary of common handles is cheap, and without a ceiling
/// an attacker walks it and rebuilds the roster the design was meant to withhold. So the
/// lookup path is bounded too, generously enough that a person adding friends never notices.
pub const MAX_LOOKUPS_TOTAL: usize = 60;

/// The window both claim limits are measured over.
pub const CLAIM_WINDOW_MS: i64 = 60 * 60 * 1_000;

/// How far outside the present a signed request's timestamp may be.
///
/// Bounds replay without requiring server-side nonce storage. Generous enough to tolerate
/// ordinary clock skew, tight enough that a captured request is not indefinitely useful.
pub const REQUEST_WINDOW_MS: i64 = 60_000;

/// What an account may do in a room.
///
/// Ordered so comparisons express authority directly: an actor may only act on a target
/// whose role is strictly lower than their own. Flat membership was a moderation dead
/// end — any member could add anyone, nobody could remove anyone, so one malicious member
/// could admit attackers permanently and the room had no recourse. A platform whose
/// stated differentiator is moderation cannot lack an eject.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoomRole {
    /// May read and write. May not change anyone's membership but their own.
    Member,
    /// May admit accounts and remove members.
    Moderator,
    /// May do anything a moderator can, plus change roles.
    Owner,
}

/// An account's place in a room.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoomMember {
    pub user: UserId,
    pub role: RoomRole,
}

/// A room as the server knows it — **without** its messages.
///
/// The log used to live here, inline, and that is precisely what made storage quadratic:
/// persisting a room meant rewriting every message it had ever carried. Messages are now
/// keyed by `(room, server_seq)` in [`crate::storage`] and are never held in memory, which
/// also matters for attachments — this record must stay small enough that every account,
/// device and room fits in RAM at once.
///
/// Public only because [`crate::storage::Storage`] is, and a public trait cannot traffic in
/// a private type. **Its fields stay private**: every rule about membership, sequencing and
/// the franking chain is enforced by the methods in this module, and a caller that could
/// set `members` or `next_seq` directly would bypass all of them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Room {
    seal: RoomSeal,
    /// Strictly increasing, assigned by the server.
    ///
    /// This is what gives a single-instance deployment the total ordering MLS requires,
    /// and it is the ordering a moderator can trust in a franking report — unlike the
    /// sender's self-reported clock.
    next_seq: u64,
    /// Commitment of the last *franked* message, as this server ordered it.
    ///
    /// The server owns the franking chain because a sender in a group cannot know what
    /// precedes its message — see `cairn_crypto::franking` module docs.
    #[serde(default)]
    last_franked: Option<Commitment>,
    /// Accounts entitled to read and write this room.
    ///
    /// Before this existed there was no membership concept at all: any authenticated
    /// account could post into any room by id — including a private end-to-end encrypted
    /// one — and could enumerate its history, learning who spoke and when. The read side
    /// broke a stated guarantee: `docs/01-threat-model.md` §3.1 concedes that the *server*
    /// sees metadata, not that any user does. The write side was worse than spam, because
    /// an injected franked message advances the room's franking chain and corrupts the
    /// evidence honest members would later report.
    #[serde(default)]
    members: Vec<RoomMember>,
    /// How long a message lives, in milliseconds, measured from when it was **sent**.
    ///
    /// Start-on-send rather than start-on-read: start-on-read needs the client to report
    /// having read a message, which is a read receipt by another name, and those were
    /// excluded for broadcasting presence (`docs/10-roadmap.md`).
    ///
    /// `default` so rooms created before this existed still decode.
    #[serde(default)]
    disappear_after_ms: Option<i64>,
}

impl Room {
    /// A bare room, for storage tests that need a value rather than a scenario.
    #[cfg(test)]
    pub(crate) fn for_test(seal: RoomSeal) -> Self {
        Self {
            seal,
            next_seq: 0,
            last_franked: None,
            members: Vec::new(),
            disappear_after_ms: None,
        }
    }

    fn has_member(&self, user: UserId) -> bool {
        self.members.iter().any(|m| m.user == user)
    }

    fn role_of(&self, user: UserId) -> Option<RoomRole> {
        self.members.iter().find(|m| m.user == user).map(|m| m.role)
    }

    fn owner_count(&self) -> usize {
        self.members.iter().filter(|m| m.role == RoomRole::Owner).count()
    }
}

/// A message the server has accepted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredMessage {
    pub envelope: Envelope,
    pub server_seq: u64,
    /// Present when the message carried a franking commitment.
    pub franking_tag: Option<Tag>,
}

/// A room invite, stored under the **hash** of its token.
///
/// The token itself is never stored. An operator reading the database, or an attacker who
/// exfiltrates it, finds hashes rather than a set of working invitations — the same reason
/// passwords are not stored in the clear, applied to a credential that admits someone to a
/// private room.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoomInviteRecord {
    pub room: RoomId,
    pub created_by: UserId,
    /// Counts down. Retained at zero rather than deleted, so a replayed invite is
    /// distinguishable from one that never existed — an operator debugging "my friend says
    /// the link does not work" needs to tell those apart.
    pub uses_remaining: u32,
    pub expires_at_ms: Option<i64>,
    pub revoked: bool,
}

/// An attachment the server holds, minus its bytes.
///
/// The server stores ciphertext it cannot read: the client encrypts the file under a key it
/// puts *inside* the encrypted message body, so the key never crosses the wire in the clear
/// and the tier's guarantee extends to attachments rather than stopping at message text.
///
/// `room` is the access control boundary and is fixed at upload. It is recorded server-side
/// rather than taken from the fetching client, because a client-supplied room would let
/// anyone read any blob by naming a room they happen to be in.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlobRecord {
    pub room: RoomId,
    pub uploader: UserId,
    pub size: usize,
}

/// A registered sending device.
///
/// The `user` binding is fixed at registration and never rewritten. On its own that is
/// **not** sufficient against impersonation — an earlier version of this code allowed
/// anyone to register a device against any user id, and the binding then faithfully
/// recorded the attacker's claim. What makes it sound is [`AccountRecord`]: a user id must
/// be claimed, and adding a device to a claimed account requires authorization from a
/// device already on it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceRecord {
    pub user: UserId,
    /// Hex-encoded signature public key.
    pub public_key: String,
}

/// An account, and the devices entitled to speak for it.
///
/// The existence of this record is what makes a user id *claimed*. Before accounts
/// existed, `register_device` bound a device to any user id the caller named — so anyone
/// who knew a user id, which is public and appears on every message that account sends,
/// could attach their own device and send as that account. Signatures verified correctly
/// and the impersonation went through.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountRecord {
    pub devices: Vec<DeviceId>,
}

/// A single-use registration invite.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InviteRecord {
    /// Consumed invites are retained rather than deleted, so a replay is distinguishable
    /// from an unknown token and an operator can audit who joined with what.
    pub used_by: Option<UserId>,
    /// Milliseconds since the Unix epoch, or `None` for no expiry.
    pub expires_at_ms: Option<i64>,
}

/// Who may create an account on this instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationPolicy {
    /// Anyone may claim any unused user id. Appropriate for a private test instance and
    /// nothing else — it lets an attacker race a user for their own id.
    Open,
    /// A valid, unused, unexpired invite is required. The sane default for a self-hosted
    /// instance, and what the operator guide should recommend.
    #[default]
    InviteOnly,
}

/// A fixed-window counter for key package claims.
///
/// In memory only, and deliberately not persisted. A restart forgets it, which is a real
/// weakness — an attacker who can crash or wait out the server gets a fresh budget — but
/// persisting it would put attacker-controlled write volume into the database, which is a
/// worse trade. Recorded rather than hidden; see `docs/11-self-hosting.md`.
#[derive(Debug, Default)]
struct ClaimLimiter {
    /// Timestamps of this actor's recent claims, oldest first, and who each was against.
    events: HashMap<UserId, VecDeque<(i64, UserId)>>,
}

impl ClaimLimiter {
    /// Record a claim by `actor` against `target`, or refuse it.
    ///
    /// Checks before recording, so a refused attempt does not itself consume budget. The
    /// budget is per-actor, so this is not about one account starving another — it is that
    /// a client which retries on a 429 would otherwise push its own window out indefinitely
    /// and never recover.
    fn admit(&mut self, actor: UserId, target: UserId, now_ms: i64) -> Result<(), ServerError> {
        let recent = self.events.entry(actor).or_default();
        while recent.front().is_some_and(|(at, _)| now_ms.saturating_sub(*at) >= CLAIM_WINDOW_MS) {
            recent.pop_front();
        }
        if recent.len() >= MAX_CLAIMS_TOTAL {
            return Err(ServerError::RateLimited);
        }
        if recent.iter().filter(|(_, t)| *t == target).count() >= MAX_CLAIMS_PER_TARGET {
            return Err(ServerError::RateLimited);
        }
        recent.push_back((now_ms, target));
        Ok(())
    }
}

/// The instance.
pub struct Instance {
    rooms: Mutex<HashMap<RoomId, Room>>,
    devices: Mutex<HashMap<DeviceId, DeviceRecord>>,
    accounts: Mutex<HashMap<UserId, AccountRecord>>,
    invites: Mutex<HashMap<String, InviteRecord>>,
    /// Unclaimed key packages, per device, oldest first.
    ///
    /// Single-use by construction: `mls-rs` deletes a key package's secrets once it is
    /// used to join, so handing the same package to two groups would leave the second
    /// welcome permanently unopenable. There is deliberately **no** last-resort package
    /// for that reason — an exhausted device is an error the caller can see, not a silent
    /// half-add.
    key_packages: Mutex<HashMap<DeviceId, VecDeque<String>>>,
    registration_policy: Mutex<RegistrationPolicy>,
    /// Not persisted; see [`ClaimLimiter`].
    claim_limiter: Mutex<ClaimLimiter>,
    /// Handle → account, both directions needed: one to resolve, one to refuse a second
    /// handle for an account that already has one.
    usernames: Mutex<HashMap<Username, UserId>>,
    /// Keyed by token hash; see [`RoomInviteRecord`].
    room_invites: Mutex<HashMap<String, RoomInviteRecord>>,
    /// Bounds username *guessing*, which exact-match resolution does not. Not persisted,
    /// for the same reason as [`ClaimLimiter`].
    lookup_limiter: Mutex<HashMap<UserId, VecDeque<i64>>>,
    franking_key: ServerFrankingKey,
    storage: Arc<dyn Storage>,
}

impl std::fmt::Debug for Instance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Instance")
    }
}

pub type SharedInstance = Arc<Instance>;

impl Instance {
    /// Open an instance against a store, restoring prior state.
    ///
    /// The franking key is loaded rather than generated whenever one already exists. That
    /// is what lets a report filed before a restart still verify afterwards.
    pub fn open(storage: Arc<dyn Storage>) -> Result<Self, ServerError> {
        let franking_key = storage.load_or_create_franking_key()?;
        // Everything but the message log. Messages are read from storage on demand — they
        // are the only unbounded thing here, and they will hold attachment bytes.
        let directory = storage.load_directory()?;
        Ok(Self {
            rooms: Mutex::new(directory.rooms.into_iter().collect()),
            devices: Mutex::new(directory.devices.into_iter().collect()),
            accounts: Mutex::new(directory.accounts.into_iter().collect()),
            invites: Mutex::new(directory.invites.into_iter().collect()),
            key_packages: Mutex::new(directory.key_packages.into_iter().collect()),
            registration_policy: Mutex::new(directory.registration_policy),
            claim_limiter: Mutex::new(ClaimLimiter::default()),
            usernames: Mutex::new(directory.usernames.into_iter().collect()),
            room_invites: Mutex::new(directory.room_invites.into_iter().collect()),
            lookup_limiter: Mutex::new(HashMap::new()),
            franking_key,
            storage,
        })
    }

    /// An ephemeral instance backed by nothing. Tests and throwaway runs only.
    pub fn in_memory() -> Self {
        Self::open(Arc::new(crate::storage::MemoryStorage::default()))
            .expect("memory storage cannot fail to open")
    }

    /// Snapshot to durable storage.
    ///
    /// Called while the caller still holds the rooms lock, so a save can never interleave
    /// with a mutation and record a torn view of the state.
    /// Persist exactly what changed, atomically.
    ///
    /// Replaces a `persist()` that wrote the entire instance on every call. That signature
    /// is what made storage quadratic, so it is gone rather than reimplemented: each caller
    /// now names the records it touched.
    ///
    /// The cost of that precision is that a caller which forgets a record loses it on
    /// restart, silently and only for that one field. `every_mutation_survives_a_restart`
    /// is the regression test that exists to catch exactly that.
    fn write(&self, writes: &[crate::storage::Write]) -> Result<(), ServerError> {
        self.storage.commit(writes)?;
        Ok(())
    }

    /// The instance's registration policy.
    pub fn registration_policy(&self) -> RegistrationPolicy {
        *self.registration_policy.lock().expect("policy mutex poisoned")
    }

    /// Set the registration policy. Operator action.
    pub fn set_registration_policy(&self, policy: RegistrationPolicy) -> Result<(), ServerError> {
        *self.registration_policy.lock().expect("policy mutex poisoned") = policy;
        self.write(&[Write::Policy(policy)])
    }

    /// Mint a registration invite. Operator action.
    pub fn create_invite(
        &self,
        token: &str,
        expires_at_ms: Option<i64>,
    ) -> Result<(), ServerError> {
        let record = InviteRecord { used_by: None, expires_at_ms };
        self.invites
            .lock()
            .expect("invites mutex poisoned")
            .insert(token.to_owned(), record.clone());
        self.write(&[Write::Invite(token.to_owned(), record)])
    }

    /// Claim a user id, creating the account and registering its first device.
    ///
    /// This is the only way an account comes into existence, and it is why a user id is a
    /// *claim* rather than a free-for-all. Under [`RegistrationPolicy::InviteOnly`] it
    /// additionally requires an unused, unexpired invite.
    pub fn claim_account(
        &self,
        user: UserId,
        device: DeviceId,
        public_key: &[u8],
        invite: Option<&str>,
        now_ms: i64,
    ) -> Result<(), ServerError> {
        let mut accounts = self.accounts.lock().expect("accounts mutex poisoned");
        if accounts.contains_key(&user) {
            // Never fall through to "link a device" here: that decision belongs to a
            // holder of the account, not to whoever asked.
            return Err(ServerError::AccountAlreadyClaimed);
        }

        let mut devices = self.devices.lock().expect("devices mutex poisoned");
        if devices.contains_key(&device) {
            return Err(ServerError::DeviceAlreadyRegistered);
        }

        let mut invites = self.invites.lock().expect("invites mutex poisoned");
        let mut spent_invite = None;
        if self.registration_policy() == RegistrationPolicy::InviteOnly {
            let token = invite.ok_or(ServerError::InviteRequired)?;
            let record = invites.get_mut(token).ok_or(ServerError::InviteInvalid)?;
            if record.used_by.is_some() {
                return Err(ServerError::InviteInvalid);
            }
            if record.expires_at_ms.is_some_and(|exp| now_ms >= exp) {
                return Err(ServerError::InviteInvalid);
            }
            record.used_by = Some(user);
            spent_invite = Some((token.to_owned(), record.clone()));
        }

        let device_record = DeviceRecord { user, public_key: hex::encode(public_key) };
        let account_record = AccountRecord { devices: vec![device] };
        devices.insert(device, device_record.clone());
        accounts.insert(user, account_record.clone());

        drop(devices);
        drop(accounts);
        drop(invites);

        // One batch, so a crash cannot leave the invite spent with no account to show for
        // it — which would lock the rightful holder out of an instance they were invited
        // to, with no way to tell that from a stolen token.
        let mut writes =
            vec![Write::Device(device, device_record), Write::Account(user, account_record)];
        if let Some((token, record)) = spent_invite {
            writes.push(Write::Invite(token, record));
        }
        self.write(&writes)
    }

    /// Add a device to an account that already exists.
    ///
    /// Requires a signature from a device **already on that account** over
    /// [`cairn_proto::device_authorization_bytes`]. That signature is the entire defence:
    /// a user id is public — it appears on every message the account sends — so without
    /// proof of possession anyone could attach a device of their own and speak as that
    /// account, with the signature check passing because they signed with their own key.
    pub fn link_device(
        &self,
        user: UserId,
        new_device: DeviceId,
        new_public_key: &[u8],
        authorizing_device: DeviceId,
        authorization: &[u8],
    ) -> Result<(), ServerError> {
        let mut accounts = self.accounts.lock().expect("accounts mutex poisoned");
        let account = accounts.get_mut(&user).ok_or(ServerError::NoSuchAccount)?;

        if !account.devices.contains(&authorizing_device) {
            return Err(ServerError::AuthorizingDeviceNotOnAccount);
        }

        let mut devices = self.devices.lock().expect("devices mutex poisoned");
        if devices.contains_key(&new_device) {
            return Err(ServerError::DeviceAlreadyRegistered);
        }

        let authorizer = devices.get(&authorizing_device).ok_or(ServerError::UnknownDevice)?;
        let authorizer_key =
            hex::decode(&authorizer.public_key).map_err(|_| ServerError::BadDeviceAuthorization)?;

        let signed = cairn_proto::device_authorization_bytes(user, new_device, new_public_key);
        if !cairn_crypto::mls::verify_signature(&authorizer_key, &signed, authorization) {
            return Err(ServerError::BadDeviceAuthorization);
        }

        let device_record = DeviceRecord { user, public_key: hex::encode(new_public_key) };
        devices.insert(new_device, device_record.clone());
        account.devices.push(new_device);
        let account_record = account.clone();

        drop(devices);
        drop(accounts);
        self.write(&[
            Write::Device(new_device, device_record),
            Write::Account(user, account_record),
        ])
    }

    /// Authenticate an envelope against its claimed sending device.
    ///
    /// Two checks, and both matter. The signature proves the holder of the device's key
    /// produced exactly these bytes; the user binding proves that device is entitled to
    /// speak for the account named in `sender`. Without the second, an attacker registers
    /// their own device, signs correctly with their own key, and still sends as anyone
    /// they like.
    fn authenticate(&self, envelope: &Envelope) -> Result<(), ServerError> {
        let signature = envelope.signature.as_deref().ok_or(ServerError::Unsigned)?;
        let signature = hex::decode(signature).map_err(|_| ServerError::BadSignature)?;

        let devices = self.devices.lock().expect("devices mutex poisoned");
        let record = devices.get(&envelope.sender_device).ok_or(ServerError::UnknownDevice)?;

        if record.user != envelope.sender {
            return Err(ServerError::DeviceUserMismatch);
        }

        let public_key = hex::decode(&record.public_key).map_err(|_| ServerError::BadSignature)?;
        if !cairn_crypto::mls::verify_signature(&public_key, &envelope.signing_bytes(), &signature)
        {
            return Err(ServerError::BadSignature);
        }
        Ok(())
    }

    /// Create a room, deriving and sealing its tier.
    pub fn create_room(
        &self,
        shape: RoomShape,
        creator: UserId,
    ) -> Result<(RoomId, RoomSeal), ServerError> {
        let seal = RoomSeal::new(shape)?;
        let id = RoomId::new();
        let room = Room {
            seal,
            next_seq: 0,
            last_franked: None,
            members: vec![RoomMember { user: creator, role: RoomRole::Owner }],
            disappear_after_ms: None,
        };
        let mut rooms = self.rooms.lock().expect("rooms mutex poisoned");
        rooms.insert(id, room.clone());
        drop(rooms);
        self.write(&[Write::Room(id, room)])?;
        Ok((id, seal))
    }

    /// Add an account to a room, at the request of a moderator or owner.
    ///
    /// Ordinary members cannot admit people. Letting them would mean one compromised
    /// account could flood a private room with attackers, and the tier model promises that
    /// a T1/T2 room's membership is deliberate — it cannot mint a public invite
    /// (`RoomSeal::may_mint_public_invite`), so there is no self-service path in either.
    pub fn add_room_member(
        &self,
        room: RoomId,
        actor: UserId,
        new_member: UserId,
    ) -> Result<(), ServerError> {
        let mut rooms = self.rooms.lock().expect("rooms mutex poisoned");
        let r = rooms.get_mut(&room).ok_or(ServerError::NoSuchRoom)?;
        let actor_role = r.role_of(actor).ok_or(ServerError::NotAMember)?;
        if actor_role < RoomRole::Moderator {
            return Err(ServerError::InsufficientRole);
        }
        // Already a member: nothing to do, and crucially *not* an error. The ceiling used to
        // be checked first, which meant re-adding an existing member of a full room failed
        // with RoomFull — and after invite redemption that is the normal case, because the
        // joiner is already a server-side member and a DM at its ceiling of 2 is full. It
        // made invite-then-add fail for exactly the situation invites exist for. Found by
        // running the flow, not by reading the check.
        if r.has_member(new_member) {
            return Ok(());
        }
        if r.members.len() as u32 >= r.seal.member_ceiling() {
            return Err(ServerError::RoomFull);
        }
        r.members.push(RoomMember { user: new_member, role: RoomRole::Member });
        let updated = r.clone();
        drop(rooms);
        self.write(&[Write::Room(room, updated)])
    }

    /// Remove an account from a room.
    ///
    /// An actor may only remove someone strictly below them, so moderators cannot depose
    /// each other or the owner. Anyone may remove themselves — leaving is not a privilege.
    ///
    /// The removed account's existing messages stay in the log. They are evidence, and a
    /// removal that erased history would let an abuser launder their own transcript by
    /// getting themselves ejected.
    pub fn remove_room_member(
        &self,
        room: RoomId,
        actor: UserId,
        target: UserId,
    ) -> Result<(), ServerError> {
        let mut rooms = self.rooms.lock().expect("rooms mutex poisoned");
        let r = rooms.get_mut(&room).ok_or(ServerError::NoSuchRoom)?;
        let actor_role = r.role_of(actor).ok_or(ServerError::NotAMember)?;
        let target_role = r.role_of(target).ok_or(ServerError::TargetNotAMember)?;

        let leaving = actor == target;
        if !leaving {
            if actor_role < RoomRole::Moderator {
                return Err(ServerError::InsufficientRole);
            }
            if target_role >= actor_role {
                return Err(ServerError::InsufficientRole);
            }
        }

        // A room with no owner can never be moderated again, so the last one cannot go —
        // not even voluntarily.
        if target_role == RoomRole::Owner && r.owner_count() <= 1 {
            return Err(ServerError::LastOwner);
        }

        r.members.retain(|m| m.user != target);
        let updated = r.clone();
        drop(rooms);
        self.write(&[Write::Room(room, updated)])
    }

    /// Change an account's role. Owners only.
    pub fn set_room_role(
        &self,
        room: RoomId,
        actor: UserId,
        target: UserId,
        role: RoomRole,
    ) -> Result<(), ServerError> {
        let mut rooms = self.rooms.lock().expect("rooms mutex poisoned");
        let r = rooms.get_mut(&room).ok_or(ServerError::NoSuchRoom)?;
        if r.role_of(actor).ok_or(ServerError::NotAMember)? < RoomRole::Owner {
            return Err(ServerError::InsufficientRole);
        }
        let previous = r.role_of(target).ok_or(ServerError::TargetNotAMember)?;
        if previous == RoomRole::Owner && role != RoomRole::Owner && r.owner_count() <= 1 {
            return Err(ServerError::LastOwner);
        }
        if let Some(m) = r.members.iter_mut().find(|m| m.user == target) {
            m.role = role;
        }
        let updated = r.clone();
        drop(rooms);
        self.write(&[Write::Room(room, updated)])
    }

    /// Set or clear the room's disappearing-message timer. Any member may.
    ///
    /// "Any member" rather than moderators-only because a DM has no moderator and both
    /// parties are equals — either should be able to ask for ephemerality. It applies to
    /// **future messages only**: retroactively shortening the life of messages people
    /// already sent under a different expectation is the same category of mistake as
    /// downgrading a room's tier.
    pub fn set_room_ttl(
        &self,
        room: RoomId,
        actor: UserId,
        ttl_ms: Option<i64>,
    ) -> Result<(), ServerError> {
        if ttl_ms.is_some_and(|t| t <= 0) {
            return Err(ServerError::BadTtl);
        }
        let mut rooms = self.rooms.lock().expect("rooms mutex poisoned");
        let r = rooms.get_mut(&room).ok_or(ServerError::NoSuchRoom)?;
        if !r.has_member(actor) {
            return Err(ServerError::NotAMember);
        }
        r.disappear_after_ms = ttl_ms;
        let updated = r.clone();
        drop(rooms);
        self.write(&[Write::Room(room, updated)])
    }

    /// The room's disappearing-message timer, if set.
    pub fn room_ttl(&self, room: RoomId) -> Option<i64> {
        self.rooms
            .lock()
            .expect("rooms mutex poisoned")
            .get(&room)
            .and_then(|r| r.disappear_after_ms)
    }

    /// Delete messages past the room's timer.
    ///
    /// Actually deletes rather than filtering. A message the server still holds has not
    /// disappeared, whatever the client shows — and the whole point of the feature is what
    /// the *instance* stops being able to hand over.
    ///
    /// Purged lazily, on read. That means an abandoned room keeps its messages until someone
    /// looks at it, which is a real limitation and is stated in `docs/11-self-hosting.md`
    /// rather than implied away.
    fn purge_expired(&self, room: RoomId, ttl_ms: i64, now_ms: i64) -> Result<(), ServerError> {
        let cutoff = now_ms.saturating_sub(ttl_ms);
        let expired: Vec<u64> = self
            .storage
            .messages_since(room, 0)?
            .into_iter()
            .filter(|m| m.envelope.sent_at_ms <= cutoff)
            .map(|m| m.server_seq)
            .collect();

        if expired.is_empty() {
            return Ok(());
        }
        let writes: Vec<Write> =
            expired.into_iter().map(|seq| Write::DeleteMessage(room, seq)).collect();
        self.write(&writes)
    }

    /// The room's server-side membership, for a member.
    ///
    /// This is the *server's* view — who may read and write — which is not the same as the
    /// MLS group's roster. The two diverge whenever someone joins by invite: the server
    /// admits them immediately, and the encrypted group only gains them when an existing
    /// member commits an Add. A client showing one and calling it the other would be
    /// telling a user they are talking to someone who cannot hear them.
    pub fn room_members(
        &self,
        room: RoomId,
        actor: UserId,
    ) -> Result<Vec<RoomMember>, ServerError> {
        let rooms = self.rooms.lock().expect("rooms mutex poisoned");
        let r = rooms.get(&room).ok_or(ServerError::NoSuchRoom)?;
        if !r.has_member(actor) {
            return Err(ServerError::NotAMember);
        }
        Ok(r.members.clone())
    }

    /// An account's role in a room, if any.
    pub fn room_role(&self, room: RoomId, user: UserId) -> Option<RoomRole> {
        self.rooms.lock().expect("rooms mutex poisoned").get(&room).and_then(|r| r.role_of(user))
    }

    /// Join a room that is open to anyone.
    ///
    /// Permitted only where the tier already implies public access — the same predicate
    /// that governs public invites. A private room is never self-joinable, or its tier
    /// badge would be claiming a confidentiality the membership rules do not enforce.
    pub fn join_room(&self, room: RoomId, user: UserId) -> Result<(), ServerError> {
        let mut rooms = self.rooms.lock().expect("rooms mutex poisoned");
        let r = rooms.get_mut(&room).ok_or(ServerError::NoSuchRoom)?;
        if !r.seal.may_mint_public_invite() {
            return Err(ServerError::RoomNotOpen);
        }
        if r.members.len() as u32 >= r.seal.member_ceiling() {
            return Err(ServerError::RoomFull);
        }
        if !r.has_member(user) {
            r.members.push(RoomMember { user, role: RoomRole::Member });
        }
        let updated = r.clone();
        drop(rooms);
        self.write(&[Write::Room(room, updated)])
    }

    /// Verify a signed non-message request and return the acting account.
    ///
    /// Membership enforced only in this layer would be bypassable by lying at the HTTP
    /// boundary, so the caller has to prove which account it is before membership means
    /// anything.
    pub fn authenticate_request(
        &self,
        device: DeviceId,
        action: &str,
        resource: Option<cairn_proto::ResourceRef>,
        issued_at_ms: i64,
        signature: &[u8],
        now_ms: i64,
    ) -> Result<UserId, ServerError> {
        if (now_ms - issued_at_ms).abs() > REQUEST_WINDOW_MS {
            return Err(ServerError::RequestExpired);
        }
        let devices = self.devices.lock().expect("devices mutex poisoned");
        let record = devices.get(&device).ok_or(ServerError::UnknownDevice)?;
        let key = hex::decode(&record.public_key).map_err(|_| ServerError::BadRequestAuth)?;
        let signed = cairn_proto::request_signing_bytes(action, resource, issued_at_ms);
        if !cairn_crypto::mls::verify_signature(&key, &signed, signature) {
            return Err(ServerError::BadRequestAuth);
        }
        Ok(record.user)
    }

    /// Publish key packages for one of the caller's own devices.
    ///
    /// `actor` must own `device`. Letting an account publish packages for someone else's
    /// device would be a key substitution with extra steps: a group creator asking for the
    /// victim's key package would receive one whose private half the attacker holds, and
    /// would then add the attacker while believing it added the victim. Safety numbers
    /// would catch it; nothing else here would.
    pub fn publish_key_packages(
        &self,
        actor: UserId,
        device: DeviceId,
        packages: Vec<String>,
    ) -> Result<usize, ServerError> {
        if packages.iter().any(|p| p.is_empty() || hex::decode(p).is_err()) {
            return Err(ServerError::BadKeyPackage);
        }

        {
            let devices = self.devices.lock().expect("devices mutex poisoned");
            let record = devices.get(&device).ok_or(ServerError::UnknownDevice)?;
            if record.user != actor {
                return Err(ServerError::NotYourDevice);
            }
        }

        let mut store = self.key_packages.lock().expect("key packages mutex poisoned");
        let queue = store.entry(device).or_default();
        if queue.len() + packages.len() > MAX_KEY_PACKAGES_PER_DEVICE {
            return Err(ServerError::TooManyKeyPackages);
        }
        queue.extend(packages);
        let remaining = queue.len();
        let updated = queue.clone();
        drop(store);

        self.write(&[Write::KeyPackages(device, updated)])?;
        Ok(remaining)
    }

    /// How many unclaimed packages a device still has. For a client deciding to top up.
    pub fn key_packages_remaining(&self, device: DeviceId) -> usize {
        self.key_packages
            .lock()
            .expect("key packages mutex poisoned")
            .get(&device)
            .map_or(0, |q| q.len())
    }

    /// Claim one key package for **every** device on an account, consuming each.
    ///
    /// Every device, not one: an account's devices each hold their own MLS leaf
    /// (`docs/01-threat-model.md` §6), so adding a user to a group means adding all of
    /// them. Returning a single package would quietly add one device and leave the
    /// account's other devices unable to read the room — a silent partial add, which is
    /// exactly the class of failure a user cannot diagnose.
    ///
    /// If any device has run out, this fails rather than returning a partial set, for the
    /// same reason. The caller learns the account cannot currently be added.
    pub fn claim_key_packages(
        &self,
        actor: UserId,
        user: UserId,
        now_ms: i64,
    ) -> Result<Vec<(DeviceId, String)>, ServerError> {
        // `actor` exists so this rule can live here rather than in the handler. The HTTP
        // layer already authenticated the caller and then dropped the identity on the
        // floor, which made the limit below impossible to express where the rules live —
        // and a rule in a handler is untested and bypassable.
        self.claim_limiter
            .lock()
            .expect("claim limiter mutex poisoned")
            .admit(actor, user, now_ms)?;

        let accounts = self.accounts.lock().expect("accounts mutex poisoned");
        let account = accounts.get(&user).ok_or(ServerError::NoSuchAccount)?;
        let devices = account.devices.clone();
        drop(accounts);

        if devices.is_empty() {
            return Err(ServerError::NoKeyPackages);
        }

        let mut store = self.key_packages.lock().expect("key packages mutex poisoned");

        // Check every device before consuming any, so a failure does not burn the
        // packages of the devices that did have one.
        if devices.iter().any(|d| store.get(d).is_none_or(|q| q.is_empty())) {
            return Err(ServerError::NoKeyPackages);
        }

        let claimed: Vec<(DeviceId, String)> = devices
            .iter()
            .map(|device| {
                let package = store
                    .get_mut(device)
                    .and_then(|q| q.pop_front())
                    .expect("checked non-empty above");
                (*device, package)
            })
            .collect();

        // Every drained queue in one batch. A partial write would hand out packages the
        // instance still believes it holds, and `mls-rs` destroys a package's secrets on
        // use — the second welcome built from a reissued package is permanently unopenable.
        let writes: Vec<Write> = devices
            .iter()
            .map(|d| Write::KeyPackages(*d, store.get(d).cloned().unwrap_or_default()))
            .collect();
        drop(store);

        self.write(&writes)?;
        Ok(claimed)
    }

    /// Store an encrypted attachment against a room.
    ///
    /// Membership is checked here rather than at the HTTP boundary, and it is checked on the
    /// *upload* as well as the fetch. Without the upload check, any authenticated account
    /// could park storage on any instance by naming a room it is not in — and the blob would
    /// then be readable by that room's members, which is a way to push content at people who
    /// never admitted you.
    pub fn store_blob(
        &self,
        actor: UserId,
        room: RoomId,
        bytes: Vec<u8>,
    ) -> Result<BlobId, ServerError> {
        if bytes.is_empty() {
            return Err(ServerError::BlobEmpty);
        }
        if bytes.len() > MAX_BLOB_BYTES {
            return Err(ServerError::BlobTooLarge);
        }

        {
            let rooms = self.rooms.lock().expect("rooms mutex poisoned");
            let r = rooms.get(&room).ok_or(ServerError::NoSuchRoom)?;
            if !r.has_member(actor) {
                return Err(ServerError::NotAMember);
            }
        }

        let id = BlobId::new();
        let record = BlobRecord { room, uploader: actor, size: bytes.len() };
        self.write(&[Write::Blob(id, record, bytes)])?;
        Ok(id)
    }

    /// Fetch an attachment, for a member of the room it was uploaded to.
    ///
    /// The membership check reads metadata first and the bytes only afterwards. Loading a
    /// 25 MiB payload in order to decide whether the caller may see it would make the
    /// access check itself the denial of service.
    ///
    /// Membership is evaluated **now**, not at upload time, so an account removed from a
    /// room loses access to its attachments — consistent with `remove_room_member`, and the
    /// alternative would leave a removed member with a permanent read channel into the room.
    pub fn fetch_blob(&self, actor: UserId, id: BlobId) -> Result<Vec<u8>, ServerError> {
        let record = self.storage.blob_meta(id)?.ok_or(ServerError::NoSuchBlob)?;

        {
            let rooms = self.rooms.lock().expect("rooms mutex poisoned");
            // A blob whose room is gone is unreachable rather than public.
            let r = rooms.get(&record.room).ok_or(ServerError::NoSuchBlob)?;
            if !r.has_member(actor) {
                return Err(ServerError::NotAMember);
            }
        }

        self.storage.blob_bytes(id)?.ok_or(ServerError::NoSuchBlob)
    }

    /// Mint a room invite. The creator chooses how many people it admits and for how long.
    ///
    /// Returns the token **once**. It is stored only as a hash, so an instance that loses
    /// this value cannot recover it — which is the point.
    pub fn create_room_invite(
        &self,
        actor: UserId,
        room: RoomId,
        uses: u32,
        expires_at_ms: Option<i64>,
    ) -> Result<String, ServerError> {
        if uses == 0 || uses > MAX_INVITE_USES {
            return Err(ServerError::InviteUsesTooHigh);
        }

        {
            let rooms = self.rooms.lock().expect("rooms mutex poisoned");
            let r = rooms.get(&room).ok_or(ServerError::NoSuchRoom)?;
            // Same authority as adding someone directly. An invite is a deferred add, so a
            // member who cannot admit people must not be able to mint one that does it later.
            if r.role_of(actor).ok_or(ServerError::NotAMember)? < RoomRole::Moderator {
                return Err(ServerError::InsufficientRole);
            }
        }

        let token = mint_token();
        let record = RoomInviteRecord {
            room,
            created_by: actor,
            uses_remaining: uses,
            expires_at_ms,
            revoked: false,
        };
        let hash = hash_token(&token);
        self.room_invites
            .lock()
            .expect("room invites mutex poisoned")
            .insert(hash.clone(), record.clone());
        self.write(&[Write::RoomInvite(hash, record)])?;
        Ok(token)
    }

    /// Redeem an invite, joining the acting account to its room.
    ///
    /// Every reason for refusal collapses into one error deliberately: telling a caller
    /// *why* a token failed tells an attacker probing tokens whether they found a real one
    /// that was merely spent.
    pub fn redeem_room_invite(
        &self,
        actor: UserId,
        token: &str,
        now_ms: i64,
    ) -> Result<RoomId, ServerError> {
        let hash = hash_token(token);
        let mut invites = self.room_invites.lock().expect("room invites mutex poisoned");
        let record = invites.get_mut(&hash).ok_or(ServerError::RoomInviteInvalid)?;

        if record.revoked
            || record.uses_remaining == 0
            || record.expires_at_ms.is_some_and(|exp| now_ms >= exp)
        {
            return Err(ServerError::RoomInviteInvalid);
        }

        let room_id = record.room;
        let mut rooms = self.rooms.lock().expect("rooms mutex poisoned");
        let room = rooms.get_mut(&room_id).ok_or(ServerError::RoomInviteInvalid)?;

        // Already a member: succeed without spending a use. Otherwise a shared link burns a
        // slot every time someone re-opens it.
        if room.has_member(actor) {
            return Ok(room_id);
        }
        // The ceiling still binds. An invite is not permission to exceed the room's shape,
        // which is what `derive_tier` was computed from.
        if room.members.len() as u32 >= room.seal.member_ceiling() {
            return Err(ServerError::RoomFull);
        }

        room.members.push(RoomMember { user: actor, role: RoomRole::Member });
        record.uses_remaining -= 1;

        let updated_room = room.clone();
        let updated_invite = record.clone();
        drop(rooms);
        drop(invites);

        // One batch: a crash between them either admits someone without spending the use, or
        // spends it without admitting them. Both are wrong, and the second locks out a
        // person holding a legitimate invite.
        self.write(&[Write::Room(room_id, updated_room), Write::RoomInvite(hash, updated_invite)])?;
        Ok(room_id)
    }

    /// Revoke an invite, so a link that has escaped stops working.
    pub fn revoke_room_invite(&self, actor: UserId, token: &str) -> Result<(), ServerError> {
        let hash = hash_token(token);
        let mut invites = self.room_invites.lock().expect("room invites mutex poisoned");
        let record = invites.get_mut(&hash).ok_or(ServerError::RoomInviteInvalid)?;
        let room = record.room;

        {
            let rooms = self.rooms.lock().expect("rooms mutex poisoned");
            let r = rooms.get(&room).ok_or(ServerError::NoSuchRoom)?;
            if r.role_of(actor).ok_or(ServerError::NotAMember)? < RoomRole::Moderator {
                return Err(ServerError::InsufficientRole);
            }
        }

        record.revoked = true;
        let updated = record.clone();
        drop(invites);
        self.write(&[Write::RoomInvite(hash, updated)])
    }

    /// Claim a handle for the acting account.
    ///
    /// One per account, and not reassignable here. A handle that could be released and
    /// re-taken is a handle someone else can inherit: a person who remembers "@alice" and
    /// types it a month later would reach whoever picked it up, with no signal that anything
    /// changed. Renaming needs a story about the old name's afterlife before it is offered.
    pub fn claim_username(&self, actor: UserId, name: Username) -> Result<(), ServerError> {
        let mut usernames = self.usernames.lock().expect("usernames mutex poisoned");

        if usernames.contains_key(&name) {
            return Err(ServerError::UsernameTaken);
        }
        if usernames.values().any(|u| *u == actor) {
            return Err(ServerError::UsernameAlreadySet);
        }
        // An unclaimed account must not be able to reserve a handle: registration is the
        // thing that costs an invite, and a handle without an account behind it is squatting.
        if !self.accounts.lock().expect("accounts mutex poisoned").contains_key(&actor) {
            return Err(ServerError::NoSuchAccount);
        }

        usernames.insert(name.clone(), actor);
        drop(usernames);
        self.write(&[Write::Username(name, actor)])
    }

    /// Resolve a handle to an account. Exact match only — there is deliberately no search.
    ///
    /// Rate limited per actor, because exact-match resolution stops an attacker *listing*
    /// accounts but not *guessing* them, and an unbounded lookup path rebuilds the roster
    /// that withholding search was meant to protect.
    pub fn lookup_username(
        &self,
        actor: UserId,
        name: &Username,
        now_ms: i64,
    ) -> Result<UserId, ServerError> {
        {
            let mut limiter = self.lookup_limiter.lock().expect("lookup limiter poisoned");
            let recent = limiter.entry(actor).or_default();
            while recent.front().is_some_and(|at| now_ms.saturating_sub(*at) >= CLAIM_WINDOW_MS) {
                recent.pop_front();
            }
            if recent.len() >= MAX_LOOKUPS_TOTAL {
                return Err(ServerError::RateLimited);
            }
            // Recorded before the answer is known, so a miss costs the same as a hit. A
            // limiter that only counted successes would let an attacker guess for free.
            recent.push_back(now_ms);
        }

        self.usernames
            .lock()
            .expect("usernames mutex poisoned")
            .get(name)
            .copied()
            .ok_or(ServerError::NoSuchUsername)
    }

    /// The handle for an account, if it has claimed one.
    pub fn username_of(&self, user: UserId) -> Option<Username> {
        self.usernames
            .lock()
            .expect("usernames mutex poisoned")
            .iter()
            .find(|(_, u)| **u == user)
            .map(|(n, _)| n.clone())
    }

    pub fn room_seal(&self, room: RoomId) -> Option<RoomSeal> {
        self.rooms.lock().expect("rooms mutex poisoned").get(&room).map(|r| r.seal)
    }

    /// Accept a message: validate it against the room's tier, sequence it, and frank it.
    ///
    /// The tier check is the important part. `docs/01-threat-model.md` §7 accepts that
    /// modified clients exist, so the server cannot rely on a client having enforced the
    /// tier — it re-checks. A client that tries to put plaintext into an encrypted room
    /// is rejected here.
    pub fn accept(&self, envelope: Envelope) -> Result<StoredMessage, ServerError> {
        // Before anything else: is this actually from who it says it is? Everything
        // downstream — the franking tag especially — attributes the message to
        // `envelope.sender`, so that attribution must be earned first.
        self.authenticate(&envelope)?;

        let mut rooms = self.rooms.lock().expect("rooms mutex poisoned");
        let room = rooms.get_mut(&envelope.room).ok_or(ServerError::NoSuchRoom)?;

        if !room.has_member(envelope.sender) {
            // A non-member's message would advance next_seq and the franking chain of a
            // room they are not in, corrupting evidence for the members who are.
            return Err(ServerError::NotAMember);
        }

        envelope.validate_for_tier(room.seal.tier())?;

        room.next_seq += 1;
        let server_seq = room.next_seq;

        let franking_tag = match &envelope.franking_commitment {
            Some(hex_commitment) => {
                let commitment =
                    decode_commitment(hex_commitment).ok_or(ServerError::BadCommitment)?;
                let tag = self.franking_key.tag(&FrankingContext {
                    commitment,
                    room: envelope.room,
                    sender: envelope.sender,
                    sender_device: envelope.sender_device,
                    server_seq,
                    prev_commitment: room.last_franked,
                });
                room.last_franked = Some(commitment);
                Some(tag)
            }
            None => None,
        };

        let stored = StoredMessage { envelope, server_seq, franking_tag };
        let room_id = stored.envelope.room;
        let updated = room.clone();
        drop(rooms);

        // The room and the message in one transaction. Split, a crash between them either
        // loses the message while keeping the sequence number it consumed, or — far worse
        // in the other order — replays that number onto a different message later and
        // rewrites franked history at a sequence a moderator has already been shown.
        self.write(&[Write::Room(room_id, updated), Write::Message(room_id, stored.clone())])?;
        Ok(stored)
    }

    /// Fetch messages after a sequence number.
    /// Fetch messages after a sequence number, for a member of the room.
    ///
    /// `actor` is required and checked. Without it any account could enumerate any room by
    /// id and learn who spoke and when — metadata the threat model concedes to the server,
    /// not to other users.
    pub fn messages_since(
        &self,
        room: RoomId,
        actor: UserId,
        after: u64,
        now_ms: i64,
    ) -> Result<Vec<StoredMessage>, ServerError> {
        {
            let rooms = self.rooms.lock().expect("rooms mutex poisoned");
            let r = rooms.get(&room).ok_or(ServerError::NoSuchRoom)?;
            if !r.has_member(actor) {
                return Err(ServerError::NotAMember);
            }
        }
        // Purge before reading, so an expired message is gone from storage rather than
        // merely hidden from this caller.
        if let Some(ttl) = self.room_ttl(room) {
            self.purge_expired(room, ttl, now_ms)?;
        }
        // Read from storage rather than memory: the log is the one thing that grows
        // without bound, and it is where attachment bytes will land.
        Ok(self.storage.messages_since(room, after)?)
    }

    /// Verify a franking report submitted by a recipient.
    ///
    /// This is the whole point of franking: the server learns what was said **only**
    /// because a recipient chose to disclose it, and can verify the disclosure is honest
    /// without ever having held the plaintext.
    pub fn verify_report(
        &self,
        report: &TranscriptReport,
    ) -> Result<(), cairn_crypto::ReportError> {
        report.verify(&self.franking_key)
    }

    /// Franking key handle, for tests and for tooling that must verify reports offline.
    #[cfg(test)]
    pub(crate) fn franking_key(&self) -> &ServerFrankingKey {
        &self.franking_key
    }
}

impl Default for Instance {
    fn default() -> Self {
        Self::in_memory()
    }
}

fn decode_commitment(hex_str: &str) -> Option<Commitment> {
    let bytes = hex::decode(hex_str).ok()?;
    let arr: [u8; 32] = bytes.try_into().ok()?;
    Some(Commitment(arr))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use cairn_proto::{DeviceId, EnvelopePayload, Tier, UserId};

    fn dm_shape() -> RoomShape {
        RoomShape { is_direct: true, is_publicly_discoverable: false, member_ceiling: 2 }
    }

    pub(crate) fn public_shape() -> RoomShape {
        RoomShape { is_direct: false, is_publicly_discoverable: true, member_ceiling: 50_000 }
    }

    /// A registered device that can produce properly signed envelopes.
    pub(crate) struct TestSender {
        pub(crate) session: cairn_crypto::mls::Session,
        pub(crate) user: UserId,
        pub(crate) device: DeviceId,
    }

    impl TestSender {
        pub(crate) fn registered(inst: &Instance) -> Self {
            let s = Self {
                session: cairn_crypto::mls::Session::new(b"tester").unwrap(),
                user: UserId::new(),
                device: DeviceId::new(),
            };
            inst.set_registration_policy(RegistrationPolicy::Open).unwrap();
            inst.claim_account(s.user, s.device, s.session.public_key(), None, 0).unwrap();
            s
        }

        pub(crate) fn envelope(&self, room: RoomId, payload: EnvelopePayload) -> Envelope {
            self.sign(self.unsigned(room, payload))
        }

        fn unsigned(&self, room: RoomId, payload: EnvelopePayload) -> Envelope {
            Envelope {
                version: cairn_proto::PROTOCOL_VERSION,
                id: cairn_proto::MessageId::new(),
                room,
                sender: self.user,
                sender_device: self.device,
                sent_at_ms: 0,
                payload,
                franking_commitment: None,
                signature: None,
            }
        }

        fn sign(&self, e: Envelope) -> Envelope {
            let sig = self.session.sign(&e.signing_bytes()).unwrap();
            e.with_signature(hex::encode(sig))
        }
    }

    #[test]
    fn rooms_get_the_tier_their_shape_implies() {
        let inst = Instance::in_memory();
        let sender = TestSender::registered(&inst);
        let (_, dm) = inst.create_room(dm_shape(), sender.user).unwrap();
        assert_eq!(dm.tier(), Tier::Private);
        let (_, pubc) = inst.create_room(public_shape(), sender.user).unwrap();
        assert_eq!(pubc.tier(), Tier::PublicCommunity);
    }

    #[test]
    fn server_rejects_plaintext_smuggled_into_an_encrypted_room() {
        // The defence that does not depend on the client behaving.
        let inst = Instance::in_memory();
        let sender = TestSender::registered(&inst);
        let (room, _) = inst.create_room(dm_shape(), sender.user).unwrap();
        let e = sender.envelope(room, EnvelopePayload::Plaintext { body: "sneaky".into() });
        assert!(matches!(inst.accept(e), Err(ServerError::Rejected(_))));
    }

    #[test]
    fn server_accepts_ciphertext_in_an_encrypted_room() {
        let inst = Instance::in_memory();
        let sender = TestSender::registered(&inst);
        let (room, _) = inst.create_room(dm_shape(), sender.user).unwrap();
        let e =
            sender.envelope(room, EnvelopePayload::MlsApplication { ciphertext: vec![1, 2, 3] });
        assert!(inst.accept(e).is_ok());
    }

    #[test]
    fn sequence_numbers_are_strictly_increasing() {
        let inst = Instance::in_memory();
        let sender = TestSender::registered(&inst);
        let (room, _) = inst.create_room(public_shape(), sender.user).unwrap();
        let mut last = 0;
        for i in 0..5 {
            let e = sender.envelope(room, EnvelopePayload::Plaintext { body: format!("m{i}") });
            let stored = inst.accept(e).unwrap();
            assert!(stored.server_seq > last);
            last = stored.server_seq;
        }
    }

    #[test]
    fn unknown_room_is_rejected() {
        let inst = Instance::in_memory();
        let sender = TestSender::registered(&inst);
        let e = sender.envelope(RoomId::new(), EnvelopePayload::Plaintext { body: "x".into() });
        assert!(matches!(inst.accept(e), Err(ServerError::NoSuchRoom)));
    }

    #[test]
    fn messages_are_franked_when_a_commitment_is_present() {
        let inst = Instance::in_memory();
        let sender = TestSender::registered(&inst);
        let (room, _) = inst.create_room(dm_shape(), sender.user).unwrap();
        let (commitment, _opening) = cairn_crypto::commit(b"hello");

        let e = sender
            .unsigned(room, EnvelopePayload::MlsApplication { ciphertext: vec![9] })
            .with_franking_commitment(commitment.to_hex());
        let stored = inst.accept(sender.sign(e)).unwrap();

        let tag = stored.franking_tag.expect("a franked message must carry a tag");
        let ctx = FrankingContext {
            commitment,
            room,
            sender: stored.envelope.sender,
            sender_device: stored.envelope.sender_device,
            server_seq: stored.server_seq,
            prev_commitment: None,
        };
        assert!(inst.franking_key().verify_tag(&ctx, &tag));
    }

    #[test]
    fn malformed_commitment_is_rejected() {
        let inst = Instance::in_memory();
        let sender = TestSender::registered(&inst);
        let (room, _) = inst.create_room(dm_shape(), sender.user).unwrap();
        let e = sender
            .unsigned(room, EnvelopePayload::MlsApplication { ciphertext: vec![9] })
            .with_franking_commitment("not-hex");
        assert!(matches!(inst.accept(sender.sign(e)), Err(ServerError::BadCommitment)));
    }

    pub(crate) fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("cairn-state-{}-{}", name, uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Wraps a real store and records what each commit actually costs.
    ///
    /// The point is to measure the property ADR-007 exists for without a wall-clock
    /// assertion, which on a shared CI runner would be noise rather than a signal.
    #[derive(Debug)]
    struct CountingStorage {
        inner: crate::storage::DbStorage,
        commits: Mutex<Vec<usize>>,
    }

    impl crate::storage::Storage for CountingStorage {
        fn load_or_create_franking_key(
            &self,
        ) -> Result<cairn_crypto::franking::ServerFrankingKey, StorageError> {
            self.inner.load_or_create_franking_key()
        }
        fn load_directory(&self) -> Result<crate::storage::Directory, StorageError> {
            self.inner.load_directory()
        }
        fn commit(&self, writes: &[Write]) -> Result<(), StorageError> {
            let bytes: usize = writes
                .iter()
                .map(|w| match w {
                    Write::Room(_, r) => serde_json::to_vec(r).map(|v| v.len()).unwrap_or(0),
                    Write::Message(_, m) => serde_json::to_vec(m).map(|v| v.len()).unwrap_or(0),
                    _ => 0,
                })
                .sum();
            self.commits.lock().unwrap().push(bytes);
            self.inner.commit(writes)
        }
        fn messages_since(
            &self,
            room: RoomId,
            after: u64,
        ) -> Result<Vec<StoredMessage>, StorageError> {
            self.inner.messages_since(room, after)
        }
        fn blob_meta(&self, id: BlobId) -> Result<Option<BlobRecord>, StorageError> {
            self.inner.blob_meta(id)
        }
        fn blob_bytes(&self, id: BlobId) -> Result<Option<Vec<u8>>, StorageError> {
            self.inner.blob_bytes(id)
        }
    }

    #[test]
    fn a_message_costs_the_same_to_store_however_long_the_backlog() {
        // ADR-007's fourth probe, and the one a passing functional test would not tell us:
        // the old design serialised every message in the room on every append, so message
        // 500 cost 500 times message 1. Nothing about correctness changes when that
        // regresses — only the bill — so this is asserted rather than left to review.
        let dir = temp_dir("flatcost");
        let storage = Arc::new(CountingStorage {
            inner: crate::storage::DbStorage::new(&dir).unwrap(),
            commits: Mutex::new(Vec::new()),
        });
        let inst = Instance::open(storage.clone()).unwrap();
        let sender = TestSender::registered(&inst);
        let (room, _) = inst.create_room(public_shape(), sender.user).unwrap();

        storage.commits.lock().unwrap().clear();
        for i in 0..200 {
            let e = sender.envelope(room, EnvelopePayload::Plaintext { body: format!("m{i}") });
            inst.accept(e).unwrap();
        }

        let costs = storage.commits.lock().unwrap().clone();
        let first = costs[0];
        let last = *costs.last().unwrap();
        println!("bytes written for message 1: {first}, for message 200: {last}");

        // Not "equal": the body carries the message number, so a couple of bytes of drift
        // is expected and meaningless. Growth proportional to the backlog is not.
        assert!(
            last < first * 2,
            "storing a message must not get more expensive as the room fills: \
             first={first} bytes, last={last} bytes"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn every_mutation_survives_a_restart() {
        // Each caller now names the records it changed, instead of one `persist()` writing
        // the world. That is what makes the cost flat, and it is also a new way to lose
        // data silently: a caller that forgets a record loses just that field, only on
        // restart. So exercise every mutating path and reload from disk.
        let dir = temp_dir("allmutations");
        let storage = Arc::new(crate::storage::DbStorage::new(&dir).unwrap());

        let (room, owner, moderator, second_device, invite_used_by) = {
            let inst = Instance::open(storage.clone()).unwrap();
            inst.set_registration_policy(RegistrationPolicy::InviteOnly).unwrap();
            inst.create_invite("tok-a", None).unwrap();

            let owner_key = cairn_crypto::mls::Session::new(b"owner").unwrap();
            let owner = UserId::new();
            let owner_device = DeviceId::new();
            inst.claim_account(owner, owner_device, owner_key.public_key(), Some("tok-a"), 0)
                .unwrap();

            // A second device on the same account, authorised by the first.
            let second_key = cairn_crypto::mls::Session::new(b"owner-2").unwrap();
            let second_device = DeviceId::new();
            let authorization = owner_key
                .sign(&cairn_proto::device_authorization_bytes(
                    owner,
                    second_device,
                    second_key.public_key(),
                ))
                .unwrap();
            inst.link_device(
                owner,
                second_device,
                second_key.public_key(),
                owner_device,
                &authorization,
            )
            .unwrap();

            inst.create_invite("tok-b", None).unwrap();
            let mod_key = cairn_crypto::mls::Session::new(b"mod").unwrap();
            let moderator = UserId::new();
            let mod_device = DeviceId::new();
            inst.claim_account(moderator, mod_device, mod_key.public_key(), Some("tok-b"), 0)
                .unwrap();

            let (room, _) = inst.create_room(public_shape(), owner).unwrap();
            inst.add_room_member(room, owner, moderator).unwrap();
            inst.set_room_role(room, owner, moderator, RoomRole::Moderator).unwrap();
            inst.publish_key_packages(owner, owner_device, vec!["aa".into(), "bb".into()]).unwrap();

            let e = cairn_proto::Envelope::new(
                Tier::PublicCommunity,
                room,
                owner,
                owner_device,
                0,
                EnvelopePayload::Plaintext { body: "kept".into() },
            )
            .unwrap();
            let signature = owner_key.sign(&e.signing_bytes()).unwrap();
            inst.accept(e.with_signature(hex::encode(signature))).unwrap();

            let used_by = inst
                .invites
                .lock()
                .unwrap()
                .get("tok-a")
                .and_then(|r| r.used_by)
                .expect("the invite must have been recorded as spent");
            (room, owner, moderator, second_device, used_by)
        };

        let restarted = Instance::open(storage).unwrap();

        assert_eq!(
            restarted.registration_policy(),
            RegistrationPolicy::InviteOnly,
            "the registration policy must survive"
        );
        assert_eq!(
            restarted.invites.lock().unwrap().get("tok-a").and_then(|r| r.used_by),
            Some(invite_used_by),
            "a spent invite must stay spent, or it could be redeemed twice"
        );
        assert!(
            restarted
                .accounts
                .lock()
                .unwrap()
                .get(&owner)
                .unwrap()
                .devices
                .contains(&second_device),
            "a linked device must survive, or the account loses it on restart"
        );
        assert_eq!(
            restarted.room_role(room, moderator),
            Some(RoomRole::Moderator),
            "a role change must survive"
        );
        assert_eq!(
            restarted.key_packages_remaining(
                *restarted.accounts.lock().unwrap()[&owner].devices.first().unwrap()
            ),
            2,
            "published key packages must survive"
        );
        assert_eq!(
            restarted.messages_since(room, owner, 0, 0).unwrap().len(),
            1,
            "the message log must survive"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_report_filed_before_a_restart_still_verifies_after_it() {
        // The property persistence exists for. If the franking key changed on restart,
        // every tag the instance ever issued would stop verifying — a moderation system
        // that forgets its own evidence.
        use cairn_crypto::franking::{Context, ReportedMessage, TranscriptReport};

        let dir = temp_dir("restart");
        let storage = Arc::new(crate::storage::DbStorage::new(&dir).unwrap());

        let (room, sender, device, commitment, opening, tag, seq) = {
            let inst = Instance::open(storage.clone()).unwrap();
            let sender = TestSender::registered(&inst);
            let (room, _) = inst.create_room(dm_shape(), sender.user).unwrap();
            let (commitment, opening) = cairn_crypto::commit(b"evidence");
            let e = sender
                .unsigned(room, EnvelopePayload::MlsApplication { ciphertext: vec![1] })
                .with_franking_commitment(commitment.to_hex());
            let stored = inst.accept(sender.sign(e)).unwrap();
            (
                room,
                stored.envelope.sender,
                stored.envelope.sender_device,
                commitment,
                opening,
                stored.franking_tag.unwrap(),
                stored.server_seq,
            )
        };

        // Restart: a brand new Instance over the same directory.
        let restarted = Instance::open(storage).unwrap();

        let report = TranscriptReport {
            messages: vec![ReportedMessage {
                plaintext: b"evidence".to_vec(),
                opening,
                context: Context {
                    commitment,
                    room,
                    sender,
                    sender_device: device,
                    server_seq: seq,
                    prev_commitment: None,
                },
                tag,
            }],
        };
        assert_eq!(
            restarted.verify_report(&report),
            Ok(()),
            "a tag issued before the restart must still verify after it"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rooms_and_messages_survive_a_restart() {
        let dir = temp_dir("rooms");
        let storage = Arc::new(crate::storage::DbStorage::new(&dir).unwrap());

        let (room, user, device, pubkey) = {
            let inst = Instance::open(storage.clone()).unwrap();
            let sender = TestSender::registered(&inst);
            let (room, _) = inst.create_room(public_shape(), sender.user).unwrap();
            for i in 0..3 {
                let e = sender.envelope(room, EnvelopePayload::Plaintext { body: format!("m{i}") });
                inst.accept(e).unwrap();
            }
            (room, sender.user, sender.device, sender.session.public_key().to_vec())
        };

        let restarted = Instance::open(storage).unwrap();
        assert_eq!(restarted.room_seal(room).unwrap().tier(), Tier::PublicCommunity);
        assert_eq!(restarted.messages_since(room, user, 0, 0).unwrap().len(), 3);

        // Device registrations must survive too, or every client is locked out after a
        // restart. Re-registering the same device must be refused, which proves the
        // record was actually restored rather than quietly recreated.
        assert!(matches!(
            restarted.claim_account(user, device, &pubkey, None, 0),
            Err(ServerError::AccountAlreadyClaimed)
        ));

        // Sequence numbers must continue, not restart — a repeated server_seq would let
        // two different messages carry interchangeable franking contexts.
        // Room membership must survive the restart too, or every member is locked out.
        let sender2 = TestSender::registered(&restarted);
        restarted.join_room(room, sender2.user).unwrap();
        let e = sender2.envelope(room, EnvelopePayload::Plaintext { body: "after".into() });
        assert_eq!(restarted.accept(e).unwrap().server_seq, 4);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn unsigned_messages_are_rejected() {
        let inst = Instance::in_memory();
        let sender = TestSender::registered(&inst);
        let (room, _) = inst.create_room(public_shape(), sender.user).unwrap();
        let e = sender.unsigned(room, EnvelopePayload::Plaintext { body: "hi".into() });
        assert!(matches!(inst.accept(e), Err(ServerError::Unsigned)));
    }

    #[test]
    fn an_unregistered_device_cannot_send() {
        let inst = Instance::in_memory();
        let owner = TestSender::registered(&inst);
        let (room, _) = inst.create_room(public_shape(), owner.user).unwrap();
        let stranger = TestSender {
            session: cairn_crypto::mls::Session::new(b"stranger").unwrap(),
            user: UserId::new(),
            device: DeviceId::new(),
        };
        let e = stranger.envelope(room, EnvelopePayload::Plaintext { body: "hi".into() });
        assert!(matches!(inst.accept(e), Err(ServerError::UnknownDevice)));
    }

    #[test]
    fn an_attacker_cannot_send_as_someone_else() {
        // The property this whole mechanism exists for. Mallory has a perfectly valid
        // device and signs correctly with her own key — she simply claims Alice's user
        // id. The device→account binding is what stops her, and without it the franking
        // tag would attribute her message to Alice.
        let inst = Instance::in_memory();
        let alice = TestSender::registered(&inst);
        let mallory = TestSender::registered(&inst);
        let (room, _) = inst.create_room(public_shape(), alice.user).unwrap();
        inst.join_room(room, mallory.user).unwrap();

        let mut e = mallory.unsigned(room, EnvelopePayload::Plaintext { body: "not me".into() });
        e.sender = alice.user; // claim Alice's account
        let e = mallory.sign(e); // …but sign with Mallory's own key, correctly

        assert!(matches!(inst.accept(e), Err(ServerError::DeviceUserMismatch)));
    }

    #[test]
    fn a_tampered_envelope_fails_verification() {
        // Signing covers every field the server acts on, so rewriting one in transit
        // must invalidate the signature.
        let inst = Instance::in_memory();
        let sender = TestSender::registered(&inst);
        let (room, _) = inst.create_room(public_shape(), sender.user).unwrap();

        let mut e = sender.envelope(room, EnvelopePayload::Plaintext { body: "original".into() });
        e.payload = EnvelopePayload::Plaintext { body: "rewritten in transit".into() };
        assert!(matches!(inst.accept(e), Err(ServerError::BadSignature)));
    }

    #[test]
    fn a_signature_from_another_device_is_rejected() {
        // Mallory signs a message that names Alice's device. She has no access to Alice's
        // key, so verification against the registered key must fail.
        let inst = Instance::in_memory();
        let alice = TestSender::registered(&inst);
        let mallory = TestSender::registered(&inst);
        let (room, _) = inst.create_room(public_shape(), alice.user).unwrap();
        inst.join_room(room, mallory.user).unwrap();

        let mut e = alice.unsigned(room, EnvelopePayload::Plaintext { body: "forged".into() });
        e.sender = alice.user;
        e.sender_device = alice.device;
        let sig = mallory.session.sign(&e.signing_bytes()).unwrap();
        let e = e.with_signature(hex::encode(sig));

        assert!(matches!(inst.accept(e), Err(ServerError::BadSignature)));
    }

    #[test]
    fn a_device_cannot_be_re_registered_with_a_different_key() {
        // Otherwise anyone who learns a device id overwrites its key and then sends as
        // its owner — precisely the attack signatures are meant to prevent.
        let inst = Instance::in_memory();
        let alice = TestSender::registered(&inst);
        let attacker_key = cairn_crypto::mls::Session::new(b"attacker").unwrap();
        assert!(matches!(
            inst.claim_account(alice.user, alice.device, attacker_key.public_key(), None, 0),
            Err(ServerError::AccountAlreadyClaimed)
        ));
    }

    #[test]
    fn the_server_chains_franked_messages_from_different_senders() {
        // The group case. Two members send without seeing each other's message; neither
        // can know what precedes theirs. The server orders them and supplies the chain,
        // so the resulting transcript is reportable — which it was not when the sender
        // guessed the predecessor.
        use cairn_crypto::franking::{ReportedMessage, TranscriptReport};

        let inst = Instance::in_memory();
        let alice = TestSender::registered(&inst);
        let bob = TestSender::registered(&inst);
        let (room, _) = inst.create_room(dm_shape(), alice.user).unwrap();
        inst.add_room_member(room, alice.user, bob.user).unwrap();

        let mut reported = Vec::new();
        for (sender, text) in [(&alice, &b"alice speaks"[..]), (&bob, &b"bob speaks"[..])] {
            let (commitment, opening) = cairn_crypto::commit(text);
            let e = sender
                .unsigned(room, EnvelopePayload::MlsApplication { ciphertext: vec![1] })
                .with_franking_commitment(commitment.to_hex());
            let stored = inst.accept(sender.sign(e)).unwrap();

            reported.push(ReportedMessage {
                plaintext: text.to_vec(),
                opening,
                context: FrankingContext {
                    commitment,
                    room,
                    sender: stored.envelope.sender,
                    sender_device: stored.envelope.sender_device,
                    server_seq: stored.server_seq,
                    // Reconstructed from what the server attested; the first has none.
                    prev_commitment: reported
                        .last()
                        .map(|m: &ReportedMessage| m.context.commitment),
                },
                tag: stored.franking_tag.unwrap(),
            });
        }

        let report = TranscriptReport { messages: reported };
        assert_eq!(
            inst.verify_report(&report),
            Ok(()),
            "a transcript spanning two senders must verify"
        );
    }

    #[test]
    fn unfranked_messages_do_not_break_the_chain() {
        // A T3 room mixes franked and unfranked messages. The chain must track only
        // franked ones, or an unfranked message in between would orphan the next report.
        let inst = Instance::in_memory();
        let sender = TestSender::registered(&inst);
        let (room, _) = inst.create_room(public_shape(), sender.user).unwrap();

        let (c1, _) = cairn_crypto::commit(b"one");
        let e = sender
            .unsigned(room, EnvelopePayload::Plaintext { body: "one".into() })
            .with_franking_commitment(c1.to_hex());
        let signature = sender.session.sign(&e.signing_bytes()).unwrap();
        inst.accept(e.with_signature(hex::encode(signature))).unwrap();

        // An unfranked message in between.
        inst.accept(sender.envelope(room, EnvelopePayload::Plaintext { body: "plain".into() }))
            .unwrap();

        let (c2, o2) = cairn_crypto::commit(b"two");
        let e = sender
            .unsigned(room, EnvelopePayload::Plaintext { body: "two".into() })
            .with_franking_commitment(c2.to_hex());
        let stored = inst.accept(sender.sign(e)).unwrap();

        // The second franked message must chain to the first, not to the unfranked one.
        let ctx = FrankingContext {
            commitment: c2,
            room,
            sender: stored.envelope.sender,
            sender_device: stored.envelope.sender_device,
            server_seq: stored.server_seq,
            prev_commitment: Some(c1),
        };
        assert!(
            inst.franking_key().verify_tag(&ctx, &stored.franking_tag.unwrap()),
            "the chain must skip unfranked messages"
        );
        let _ = o2;
    }

    #[test]
    fn messages_since_filters_by_sequence() {
        let inst = Instance::in_memory();
        let sender = TestSender::registered(&inst);
        let (room, _) = inst.create_room(public_shape(), sender.user).unwrap();
        for i in 0..3 {
            let e = sender.envelope(room, EnvelopePayload::Plaintext { body: format!("m{i}") });
            inst.accept(e).unwrap();
        }
        assert_eq!(inst.messages_since(room, sender.user, 0, 0).unwrap().len(), 3);
        assert_eq!(inst.messages_since(room, sender.user, 2, 0).unwrap().len(), 1);
        assert_eq!(inst.messages_since(room, sender.user, 99, 0).unwrap().len(), 0);
    }
}

#[cfg(test)]
mod accounts {
    use super::tests::*;
    use super::*;
    use cairn_proto::EnvelopePayload;

    fn signed_as(
        key: &cairn_crypto::mls::Session,
        user: UserId,
        device: DeviceId,
        room: RoomId,
        body: &str,
    ) -> Envelope {
        let e = Envelope {
            version: cairn_proto::PROTOCOL_VERSION,
            id: cairn_proto::MessageId::new(),
            room,
            sender: user,
            sender_device: device,
            sent_at_ms: 0,
            payload: EnvelopePayload::Plaintext { body: body.into() },
            franking_commitment: None,
            signature: None,
        };
        let sig = key.sign(&e.signing_bytes()).unwrap();
        e.with_signature(hex::encode(sig))
    }

    /// Regression test for a real vulnerability.
    ///
    /// Before accounts existed, `register_device` bound a device to whatever user id the
    /// caller named. A user id is public — it is on every message the account sends — so
    /// an attacker could attach their own device to someone else's id and send as them,
    /// with the signature check passing because they signed with their own key. This was
    /// confirmed against the shipped code before the fix.
    #[test]
    fn an_attacker_cannot_attach_a_device_to_someone_elses_account() {
        let inst = Instance::in_memory();
        let alice = TestSender::registered(&inst);
        let (room, _) = inst.create_room(public_shape(), alice.user).unwrap();

        let mallory_key = cairn_crypto::mls::Session::new(b"mallory").unwrap();
        let mallory_device = DeviceId::new();

        // Claiming Alice's id outright is refused: it is already claimed.
        assert!(matches!(
            inst.claim_account(alice.user, mallory_device, mallory_key.public_key(), None, 0),
            Err(ServerError::AccountAlreadyClaimed)
        ));

        // Linking is refused too: Mallory holds no device on Alice's account, and she
        // cannot produce a signature from one.
        let forged = mallory_key
            .sign(&cairn_proto::device_authorization_bytes(
                alice.user,
                mallory_device,
                mallory_key.public_key(),
            ))
            .unwrap();
        assert!(matches!(
            inst.link_device(
                alice.user,
                mallory_device,
                mallory_key.public_key(),
                mallory_device,
                &forged,
            ),
            Err(ServerError::AuthorizingDeviceNotOnAccount)
        ));

        // And with no registered device, she cannot send as Alice at all.
        let e = signed_as(&mallory_key, alice.user, mallory_device, room, "not alice");
        assert!(matches!(inst.accept(e), Err(ServerError::UnknownDevice)));
    }

    #[test]
    fn a_holder_can_link_a_second_device_and_it_can_send() {
        let inst = Instance::in_memory();
        let alice = TestSender::registered(&inst);
        let (room, _) = inst.create_room(public_shape(), alice.user).unwrap();

        let laptop = cairn_crypto::mls::Session::new(b"alice-laptop").unwrap();
        let laptop_id = DeviceId::new();
        let auth = alice
            .session
            .sign(&cairn_proto::device_authorization_bytes(
                alice.user,
                laptop_id,
                laptop.public_key(),
            ))
            .unwrap();

        inst.link_device(alice.user, laptop_id, laptop.public_key(), alice.device, &auth).unwrap();

        let e = signed_as(&laptop, alice.user, laptop_id, room, "from my laptop");
        assert!(inst.accept(e).is_ok());
    }

    #[test]
    fn an_authorization_for_one_device_cannot_be_replayed_for_another() {
        // The signature covers the specific new device and key, so capturing one off the
        // wire does not let an attacker attach a device of their own.
        let inst = Instance::in_memory();
        let alice = TestSender::registered(&inst);

        let honest = cairn_crypto::mls::Session::new(b"alice-laptop").unwrap();
        let honest_id = DeviceId::new();
        let auth = alice
            .session
            .sign(&cairn_proto::device_authorization_bytes(
                alice.user,
                honest_id,
                honest.public_key(),
            ))
            .unwrap();

        let mallory = cairn_crypto::mls::Session::new(b"mallory").unwrap();
        assert!(matches!(
            inst.link_device(
                alice.user,
                DeviceId::new(),
                mallory.public_key(),
                alice.device,
                &auth
            ),
            Err(ServerError::BadDeviceAuthorization)
        ));
    }

    #[test]
    fn linking_to_an_unclaimed_account_is_refused() {
        let inst = Instance::in_memory();
        let alice = TestSender::registered(&inst);
        let key = cairn_crypto::mls::Session::new(b"x").unwrap();
        assert!(matches!(
            inst.link_device(UserId::new(), DeviceId::new(), key.public_key(), alice.device, b"x"),
            Err(ServerError::NoSuchAccount)
        ));
    }

    #[test]
    fn invite_only_is_the_default_and_is_enforced() {
        let inst = Instance::in_memory();
        assert_eq!(inst.registration_policy(), RegistrationPolicy::InviteOnly);

        let key = cairn_crypto::mls::Session::new(b"newcomer").unwrap();
        assert!(matches!(
            inst.claim_account(UserId::new(), DeviceId::new(), key.public_key(), None, 0),
            Err(ServerError::InviteRequired)
        ));
    }

    #[test]
    fn an_invite_works_once() {
        let inst = Instance::in_memory();
        inst.create_invite("token-abc", None).unwrap();

        let first = cairn_crypto::mls::Session::new(b"first").unwrap();
        inst.claim_account(
            UserId::new(),
            DeviceId::new(),
            first.public_key(),
            Some("token-abc"),
            0,
        )
        .unwrap();

        // Reuse must fail, or one leaked invite becomes unlimited registrations.
        let second = cairn_crypto::mls::Session::new(b"second").unwrap();
        assert!(matches!(
            inst.claim_account(
                UserId::new(),
                DeviceId::new(),
                second.public_key(),
                Some("token-abc"),
                0
            ),
            Err(ServerError::InviteInvalid)
        ));
    }

    #[test]
    fn an_expired_invite_is_refused() {
        let inst = Instance::in_memory();
        inst.create_invite("expiring", Some(1_000)).unwrap();
        let key = cairn_crypto::mls::Session::new(b"late").unwrap();
        assert!(matches!(
            inst.claim_account(
                UserId::new(),
                DeviceId::new(),
                key.public_key(),
                Some("expiring"),
                1_000
            ),
            Err(ServerError::InviteInvalid)
        ));
    }

    #[test]
    fn an_unknown_invite_is_refused() {
        let inst = Instance::in_memory();
        let key = cairn_crypto::mls::Session::new(b"guess").unwrap();
        assert!(matches!(
            inst.claim_account(
                UserId::new(),
                DeviceId::new(),
                key.public_key(),
                Some("guessed"),
                0
            ),
            Err(ServerError::InviteInvalid)
        ));
    }

    #[test]
    fn accounts_and_invites_survive_a_restart() {
        let dir = std::env::temp_dir().join(format!("cairn-acct-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let storage = Arc::new(crate::storage::DbStorage::new(&dir).unwrap());

        let (user, device) = {
            let inst = Instance::open(storage.clone()).unwrap();
            inst.create_invite("persisted", None).unwrap();
            let key = cairn_crypto::mls::Session::new(b"a").unwrap();
            let (u, d) = (UserId::new(), DeviceId::new());
            inst.claim_account(u, d, key.public_key(), Some("persisted"), 0).unwrap();
            (u, d)
        };

        let restarted = Instance::open(storage).unwrap();
        // The account is still claimed…
        let key = cairn_crypto::mls::Session::new(b"b").unwrap();
        assert!(matches!(
            restarted.claim_account(user, DeviceId::new(), key.public_key(), None, 0),
            Err(ServerError::AccountAlreadyClaimed)
        ));
        // …and the consumed invite is still consumed, not reusable after a restart.
        assert!(matches!(
            restarted.claim_account(
                UserId::new(),
                DeviceId::new(),
                key.public_key(),
                Some("persisted"),
                0
            ),
            Err(ServerError::InviteInvalid)
        ));
        let _ = device;
        std::fs::remove_dir_all(&dir).ok();
    }
}

#[cfg(test)]
mod membership {
    use super::tests::*;
    use super::*;
    use cairn_proto::EnvelopePayload;

    fn private_room(inst: &Instance, owner: UserId) -> RoomId {
        inst.create_room(
            RoomShape { is_direct: true, is_publicly_discoverable: false, member_ceiling: 8 },
            owner,
        )
        .unwrap()
        .0
    }

    /// Regression test for a real vulnerability.
    ///
    /// Rooms had no membership concept. Any authenticated account could post into any room
    /// by id — including a private end-to-end encrypted one it had never been added to.
    /// Confirmed against the shipped code before the fix: the injected message was accepted
    /// as server_seq 2.
    #[test]
    fn a_non_member_cannot_write_to_a_private_room() {
        let inst = Instance::in_memory();
        let alice = TestSender::registered(&inst);
        let mallory = TestSender::registered(&inst);
        let room = private_room(&inst, alice.user);

        let e = mallory.envelope(room, EnvelopePayload::MlsApplication { ciphertext: vec![9] });
        assert!(matches!(inst.accept(e), Err(ServerError::NotAMember)));
    }

    /// The read half of the same vulnerability, and the worse one.
    ///
    /// A non-member could enumerate any room by id and learn who spoke and when. The
    /// ciphertext was useless to them, but the metadata was not — and
    /// `docs/01-threat-model.md` §3.1 concedes metadata to the *server*, not to other
    /// users. Confirmed before the fix: two messages returned, with both sender ids.
    #[test]
    fn a_non_member_cannot_read_a_private_room() {
        let inst = Instance::in_memory();
        let alice = TestSender::registered(&inst);
        let mallory = TestSender::registered(&inst);
        let room = private_room(&inst, alice.user);

        inst.accept(alice.envelope(room, EnvelopePayload::MlsApplication { ciphertext: vec![1] }))
            .unwrap();

        assert!(matches!(
            inst.messages_since(room, mallory.user, 0, 0),
            Err(ServerError::NotAMember)
        ));
        // The member still can, so the check is not simply refusing everyone.
        assert_eq!(inst.messages_since(room, alice.user, 0, 0).unwrap().len(), 1);
    }

    #[test]
    fn a_private_room_cannot_be_self_joined() {
        // Otherwise membership would be decorative: anyone holding the id could add
        // themselves and the T1/T2 badge would claim a confidentiality nothing enforces.
        let inst = Instance::in_memory();
        let alice = TestSender::registered(&inst);
        let mallory = TestSender::registered(&inst);
        let room = private_room(&inst, alice.user);

        assert!(matches!(inst.join_room(room, mallory.user), Err(ServerError::RoomNotOpen)));
    }

    #[test]
    fn a_member_can_add_someone_and_a_non_member_cannot() {
        let inst = Instance::in_memory();
        let alice = TestSender::registered(&inst);
        let bob = TestSender::registered(&inst);
        let mallory = TestSender::registered(&inst);
        let room = private_room(&inst, alice.user);

        // Mallory cannot add herself by asking on her own authority.
        assert!(matches!(
            inst.add_room_member(room, mallory.user, mallory.user),
            Err(ServerError::NotAMember)
        ));

        // Alice, a member, can add Bob — and then Bob can speak.
        inst.add_room_member(room, alice.user, bob.user).unwrap();
        assert!(inst
            .accept(bob.envelope(room, EnvelopePayload::MlsApplication { ciphertext: vec![2] }))
            .is_ok());
    }

    #[test]
    fn a_public_room_is_self_joinable() {
        let inst = Instance::in_memory();
        let alice = TestSender::registered(&inst);
        let newcomer = TestSender::registered(&inst);
        let (room, _) = inst.create_room(public_shape(), alice.user).unwrap();

        inst.join_room(room, newcomer.user).unwrap();
        assert!(inst
            .accept(newcomer.envelope(room, EnvelopePayload::Plaintext { body: "hello".into() }))
            .is_ok());
    }

    #[test]
    fn membership_respects_the_room_ceiling() {
        let inst = Instance::in_memory();
        let alice = TestSender::registered(&inst);
        let room = inst
            .create_room(
                RoomShape { is_direct: true, is_publicly_discoverable: false, member_ceiling: 2 },
                alice.user,
            )
            .unwrap()
            .0;

        inst.add_room_member(room, alice.user, UserId::new()).unwrap();
        assert!(matches!(
            inst.add_room_member(room, alice.user, UserId::new()),
            Err(ServerError::RoomFull)
        ));
    }

    #[test]
    fn signed_requests_authenticate_the_actor_and_bound_replay() {
        let inst = Instance::in_memory();
        let alice = TestSender::registered(&inst);
        let room = private_room(&inst, alice.user);

        let issued = 10_000i64;
        let sig = alice
            .session
            .sign(&cairn_proto::request_signing_bytes("read", Some(room.into()), issued))
            .unwrap();

        assert_eq!(
            inst.authenticate_request(
                alice.device,
                "read",
                Some(room.into()),
                issued,
                &sig,
                issued
            )
            .unwrap(),
            alice.user
        );

        // A read authorization must not also authorize a write.
        assert!(matches!(
            inst.authenticate_request(
                alice.device,
                "add_member",
                Some(room.into()),
                issued,
                &sig,
                issued
            ),
            Err(ServerError::BadRequestAuth)
        ));

        // …nor the same action against a different room.
        assert!(matches!(
            inst.authenticate_request(
                alice.device,
                "read",
                Some(RoomId::new().into()),
                issued,
                &sig,
                issued
            ),
            Err(ServerError::BadRequestAuth)
        ));

        // Outside the window it is refused, which bounds how long a captured request is
        // useful. It is a window, not a nonce — replay inside it is still possible.
        assert!(matches!(
            inst.authenticate_request(
                alice.device,
                "read",
                Some(room.into()),
                issued,
                &sig,
                issued + REQUEST_WINDOW_MS + 1
            ),
            Err(ServerError::RequestExpired)
        ));
    }

    #[test]
    fn room_membership_survives_a_restart() {
        let dir = std::env::temp_dir().join(format!("cairn-mem-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let storage = Arc::new(crate::storage::DbStorage::new(&dir).unwrap());

        let (room, member, outsider) = {
            let inst = Instance::open(storage.clone()).unwrap();
            let alice = TestSender::registered(&inst);
            let mallory = TestSender::registered(&inst);
            let room = private_room(&inst, alice.user);
            (room, alice.user, mallory.user)
        };

        let restarted = Instance::open(storage).unwrap();
        // A member must not be locked out by a restart…
        assert!(restarted.messages_since(room, member, 0, 0).is_ok());
        // …and an outsider must not be let in by one.
        assert!(matches!(
            restarted.messages_since(room, outsider, 0, 0),
            Err(ServerError::NotAMember)
        ));
        std::fs::remove_dir_all(&dir).ok();
    }
}

#[cfg(test)]
mod roles {
    use super::tests::*;
    use super::*;
    use cairn_proto::EnvelopePayload;

    fn room_with(inst: &Instance, owner: UserId) -> RoomId {
        inst.create_room(
            RoomShape { is_direct: true, is_publicly_discoverable: false, member_ceiling: 16 },
            owner,
        )
        .unwrap()
        .0
    }

    #[test]
    fn the_creator_owns_the_room() {
        let inst = Instance::in_memory();
        let alice = TestSender::registered(&inst);
        let room = room_with(&inst, alice.user);
        assert_eq!(inst.room_role(room, alice.user), Some(RoomRole::Owner));
    }

    #[test]
    fn an_ordinary_member_cannot_admit_anyone() {
        // Otherwise one compromised account can flood a private room with attackers, and
        // the tier badge stops meaning that membership was deliberate.
        let inst = Instance::in_memory();
        let alice = TestSender::registered(&inst);
        let bob = TestSender::registered(&inst);
        let room = room_with(&inst, alice.user);
        inst.add_room_member(room, alice.user, bob.user).unwrap();

        assert_eq!(inst.room_role(room, bob.user), Some(RoomRole::Member));
        assert!(matches!(
            inst.add_room_member(room, bob.user, UserId::new()),
            Err(ServerError::InsufficientRole)
        ));
    }

    #[test]
    fn an_owner_can_eject_a_member_who_then_cannot_read_or_write() {
        // The whole point: a room must be able to remove someone. Before roles existed
        // there was no removal path at all.
        let inst = Instance::in_memory();
        let alice = TestSender::registered(&inst);
        let mallory = TestSender::registered(&inst);
        let room = room_with(&inst, alice.user);
        inst.add_room_member(room, alice.user, mallory.user).unwrap();

        inst.accept(
            mallory.envelope(room, EnvelopePayload::MlsApplication { ciphertext: vec![1] }),
        )
        .unwrap();

        inst.remove_room_member(room, alice.user, mallory.user).unwrap();

        assert!(matches!(
            inst.accept(
                mallory.envelope(room, EnvelopePayload::MlsApplication { ciphertext: vec![2] })
            ),
            Err(ServerError::NotAMember)
        ));
        assert!(matches!(
            inst.messages_since(room, mallory.user, 0, 0),
            Err(ServerError::NotAMember)
        ));
    }

    #[test]
    fn removal_keeps_the_removed_members_messages() {
        // Erasing them on removal would let an abuser launder their own transcript by
        // getting themselves ejected.
        let inst = Instance::in_memory();
        let alice = TestSender::registered(&inst);
        let mallory = TestSender::registered(&inst);
        let room = room_with(&inst, alice.user);
        inst.add_room_member(room, alice.user, mallory.user).unwrap();
        inst.accept(
            mallory.envelope(room, EnvelopePayload::MlsApplication { ciphertext: vec![1] }),
        )
        .unwrap();

        inst.remove_room_member(room, alice.user, mallory.user).unwrap();

        let log = inst.messages_since(room, alice.user, 0, 0).unwrap();
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].envelope.sender, mallory.user);
    }

    #[test]
    fn a_moderator_cannot_depose_the_owner_or_a_peer() {
        let inst = Instance::in_memory();
        let alice = TestSender::registered(&inst);
        let mod1 = TestSender::registered(&inst);
        let mod2 = TestSender::registered(&inst);
        let room = room_with(&inst, alice.user);
        inst.add_room_member(room, alice.user, mod1.user).unwrap();
        inst.add_room_member(room, alice.user, mod2.user).unwrap();
        inst.set_room_role(room, alice.user, mod1.user, RoomRole::Moderator).unwrap();
        inst.set_room_role(room, alice.user, mod2.user, RoomRole::Moderator).unwrap();

        assert!(matches!(
            inst.remove_room_member(room, mod1.user, alice.user),
            Err(ServerError::InsufficientRole)
        ));
        assert!(matches!(
            inst.remove_room_member(room, mod1.user, mod2.user),
            Err(ServerError::InsufficientRole)
        ));
    }

    #[test]
    fn anyone_may_leave_but_the_last_owner_may_not() {
        // A room with no owner can never be moderated again.
        let inst = Instance::in_memory();
        let alice = TestSender::registered(&inst);
        let bob = TestSender::registered(&inst);
        let room = room_with(&inst, alice.user);
        inst.add_room_member(room, alice.user, bob.user).unwrap();

        inst.remove_room_member(room, bob.user, bob.user).unwrap();
        assert_eq!(inst.room_role(room, bob.user), None);

        assert!(matches!(
            inst.remove_room_member(room, alice.user, alice.user),
            Err(ServerError::LastOwner)
        ));
    }

    #[test]
    fn only_an_owner_changes_roles_and_cannot_orphan_the_room() {
        let inst = Instance::in_memory();
        let alice = TestSender::registered(&inst);
        let bob = TestSender::registered(&inst);
        let room = room_with(&inst, alice.user);
        inst.add_room_member(room, alice.user, bob.user).unwrap();

        assert!(matches!(
            inst.set_room_role(room, bob.user, bob.user, RoomRole::Owner),
            Err(ServerError::InsufficientRole)
        ));
        // Demoting the only owner would leave the room unmoderatable.
        assert!(matches!(
            inst.set_room_role(room, alice.user, alice.user, RoomRole::Member),
            Err(ServerError::LastOwner)
        ));
        // With a second owner it is allowed.
        inst.set_room_role(room, alice.user, bob.user, RoomRole::Owner).unwrap();
        inst.set_room_role(room, alice.user, alice.user, RoomRole::Member).unwrap();
        assert_eq!(inst.room_role(room, alice.user), Some(RoomRole::Member));
    }

    #[test]
    fn roles_survive_a_restart() {
        let dir = std::env::temp_dir().join(format!("cairn-roles-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let storage = Arc::new(crate::storage::DbStorage::new(&dir).unwrap());

        let (room, owner, member) = {
            let inst = Instance::open(storage.clone()).unwrap();
            let alice = TestSender::registered(&inst);
            let bob = TestSender::registered(&inst);
            let room = room_with(&inst, alice.user);
            inst.add_room_member(room, alice.user, bob.user).unwrap();
            (room, alice.user, bob.user)
        };

        let restarted = Instance::open(storage).unwrap();
        assert_eq!(restarted.room_role(room, owner), Some(RoomRole::Owner));
        assert_eq!(restarted.room_role(room, member), Some(RoomRole::Member));
        // A restart must not silently promote anyone.
        assert!(matches!(
            restarted.add_room_member(room, member, UserId::new()),
            Err(ServerError::InsufficientRole)
        ));
        std::fs::remove_dir_all(&dir).ok();
    }
}

#[cfg(test)]
mod claim_limits {
    use super::tests::*;
    use super::*;

    /// Publish `n` packages for a freshly registered account.
    fn victim_with(inst: &Instance, n: usize) -> TestSender {
        let victim = TestSender::registered(inst);
        inst.publish_key_packages(victim.user, victim.device, vec!["aa".into(); n]).unwrap();
        victim
    }

    #[test]
    fn an_attacker_cannot_drain_someone_elses_key_packages() {
        // Found by probing, not by reading. Before the limit, one authenticated account
        // emptied a victim's entire published supply in a tight loop, after which nobody
        // could add that victim to a room until they came back and published more — a
        // targeted denial of service that left no trace the victim could see.
        let inst = Instance::in_memory();
        let victim = victim_with(&inst, 10);
        let attacker = TestSender::registered(&inst);

        let mut claimed = 0;
        for _ in 0..50 {
            if inst.claim_key_packages(attacker.user, victim.user, 0).is_ok() {
                claimed += 1;
            }
        }

        assert_eq!(claimed, MAX_CLAIMS_PER_TARGET, "one account must not claim without bound");
        assert!(
            inst.key_packages_remaining(victim.device) > 0,
            "a single attacker must not be able to empty the supply"
        );

        // The property that actually matters to the victim.
        let honest = TestSender::registered(&inst);
        assert!(
            inst.claim_key_packages(honest.user, victim.user, 0).is_ok(),
            "an honest party must still be able to add the victim to a room"
        );
    }

    #[test]
    fn walking_a_list_of_user_ids_is_bounded_too() {
        // The per-target limit alone bounds nothing: user ids are on every message, so an
        // attacker can simply move on to the next victim.
        let inst = Instance::in_memory();
        let attacker = TestSender::registered(&inst);
        let victims: Vec<_> = (0..40).map(|_| victim_with(&inst, 2)).collect();

        let claimed = victims
            .iter()
            .filter(|v| inst.claim_key_packages(attacker.user, v.user, 0).is_ok())
            .count();

        assert_eq!(claimed, MAX_CLAIMS_TOTAL, "an actor's total claim budget must be capped");
    }

    #[test]
    fn the_budget_returns_after_the_window() {
        // Otherwise this is not a rate limit but a lifetime quota, and an ordinary user who
        // creates a lot of rooms one afternoon is locked out forever.
        let inst = Instance::in_memory();
        let victim = victim_with(&inst, 10);
        let actor = TestSender::registered(&inst);

        for _ in 0..MAX_CLAIMS_PER_TARGET {
            inst.claim_key_packages(actor.user, victim.user, 0).unwrap();
        }
        assert!(matches!(
            inst.claim_key_packages(actor.user, victim.user, 0),
            Err(ServerError::RateLimited)
        ));

        assert!(
            inst.claim_key_packages(actor.user, victim.user, CLAIM_WINDOW_MS).is_ok(),
            "the window must expire"
        );
    }

    #[test]
    fn a_refused_claim_does_not_consume_budget() {
        // A client that retries on a 429 would otherwise push its own window out
        // indefinitely and never recover.
        let inst = Instance::in_memory();
        let victim = victim_with(&inst, 10);
        let actor = TestSender::registered(&inst);

        for _ in 0..MAX_CLAIMS_PER_TARGET {
            inst.claim_key_packages(actor.user, victim.user, 0).unwrap();
        }
        // Hammer well past the total budget while refused.
        for _ in 0..MAX_CLAIMS_TOTAL * 2 {
            assert!(inst.claim_key_packages(actor.user, victim.user, 0).is_err());
        }

        // A different target is still within the untouched total budget.
        let other = victim_with(&inst, 4);
        assert!(
            inst.claim_key_packages(actor.user, other.user, 0).is_ok(),
            "rejections must not count against the actor's budget"
        );
    }

    #[test]
    fn claiming_your_own_key_packages_is_limited_the_same_way() {
        // No self-exemption: an account is not more trustworthy against itself, and an
        // exemption would be a free drain for anyone willing to register.
        let inst = Instance::in_memory();
        let me = victim_with(&inst, 10);
        for _ in 0..MAX_CLAIMS_PER_TARGET {
            inst.claim_key_packages(me.user, me.user, 0).unwrap();
        }
        assert!(matches!(
            inst.claim_key_packages(me.user, me.user, 0),
            Err(ServerError::RateLimited)
        ));
    }
}

#[cfg(test)]
mod username_rules {
    use super::tests::*;
    use super::*;

    fn name(s: &str) -> Username {
        Username::parse(s).unwrap()
    }

    #[test]
    fn a_handle_cannot_be_claimed_twice() {
        // The impersonation this guards: if a handle could be re-registered, someone who
        // remembers "@alice" reaches whoever holds it now, with no signal it changed hands.
        let inst = Instance::in_memory();
        let alice = TestSender::registered(&inst);
        let mallory = TestSender::registered(&inst);

        inst.claim_username(alice.user, name("alice")).unwrap();
        assert!(matches!(
            inst.claim_username(mallory.user, name("alice")),
            Err(ServerError::UsernameTaken)
        ));
        // And not by a different spelling of the same thing.
        assert!(matches!(
            inst.claim_username(mallory.user, name("ALICE")),
            Err(ServerError::UsernameTaken)
        ));
    }

    #[test]
    fn an_unregistered_account_cannot_reserve_a_handle() {
        // Registration is what costs an invite. A handle with no account behind it is
        // squatting, and on an invite-only instance it would be free squatting.
        let inst = Instance::in_memory();
        assert!(matches!(
            inst.claim_username(UserId::new(), name("ghost")),
            Err(ServerError::NoSuchAccount)
        ));
    }

    #[test]
    fn one_account_gets_one_handle() {
        let inst = Instance::in_memory();
        let alice = TestSender::registered(&inst);
        inst.claim_username(alice.user, name("alice")).unwrap();
        assert!(matches!(
            inst.claim_username(alice.user, name("alice2")),
            Err(ServerError::UsernameAlreadySet)
        ));
    }

    #[test]
    fn a_handle_resolves_to_its_account_and_nothing_else_does() {
        let inst = Instance::in_memory();
        let alice = TestSender::registered(&inst);
        let bob = TestSender::registered(&inst);
        inst.claim_username(alice.user, name("alice")).unwrap();

        assert_eq!(inst.lookup_username(bob.user, &name("alice"), 0).unwrap(), alice.user);
        // Case-insensitively, since Username normalises before it ever reaches the map.
        assert_eq!(inst.lookup_username(bob.user, &name("Alice"), 0).unwrap(), alice.user);
        assert!(matches!(
            inst.lookup_username(bob.user, &name("alicia"), 0),
            Err(ServerError::NoSuchUsername)
        ));
    }

    #[test]
    fn guessing_handles_is_bounded_even_though_listing_is_impossible() {
        // Exact-match resolution stops an attacker *listing* accounts. It does not stop
        // them *guessing*, and a dictionary of common handles is cheap — so without this
        // ceiling the roster that withholding search protects is rebuilt anyway.
        let inst = Instance::in_memory();
        let attacker = TestSender::registered(&inst);

        let mut answered = 0;
        for i in 0..MAX_LOOKUPS_TOTAL * 2 {
            match inst.lookup_username(attacker.user, &name(&format!("guess{i}")), 0) {
                Err(ServerError::RateLimited) => break,
                _ => answered += 1,
            }
        }
        assert_eq!(answered, MAX_LOOKUPS_TOTAL, "guessing must be capped, not merely slowed");
    }

    #[test]
    fn a_missed_guess_costs_the_same_as_a_hit() {
        // A limiter that only counted successes would let an attacker probe for free, which
        // is precisely the direction an attacker probes in.
        let inst = Instance::in_memory();
        let attacker = TestSender::registered(&inst);

        for i in 0..MAX_LOOKUPS_TOTAL {
            let _ = inst.lookup_username(attacker.user, &name(&format!("miss{i}")), 0);
        }
        assert!(matches!(
            inst.lookup_username(attacker.user, &name("miss0"), 0),
            Err(ServerError::RateLimited)
        ));
    }

    #[test]
    fn handles_survive_a_restart() {
        let dir = temp_dir("usernames");
        let storage = Arc::new(crate::storage::DbStorage::new(&dir).unwrap());
        let user = {
            let inst = Instance::open(storage.clone()).unwrap();
            let alice = TestSender::registered(&inst);
            inst.claim_username(alice.user, name("alice")).unwrap();
            alice.user
        };

        let restarted = Instance::open(storage).unwrap();
        assert_eq!(restarted.username_of(user), Some(name("alice")));
        // And it is still taken, which is what stops a restart handing it to someone else.
        let mallory = TestSender::registered(&restarted);
        assert!(matches!(
            restarted.claim_username(mallory.user, name("alice")),
            Err(ServerError::UsernameTaken)
        ));
        std::fs::remove_dir_all(&dir).ok();
    }
}

/// A fresh invite token: 32 random bytes, hex.
///
/// Random rather than derived from the room, so a token discloses nothing about what it
/// opens until it is redeemed, and so two invites to the same room are unlinkable to anyone
/// holding both.
fn mint_token() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Hash a token for storage and lookup.
///
/// The map is keyed by this, so the lookup itself is a hash comparison rather than a
/// string comparison against a stored secret — there is no stored secret to compare
/// against. Hashing is what makes a leaked database a list of hashes rather than a set of
/// working invitations.
fn hash_token(token: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    // Domain-separated, so a token hash can never collide with any other hash this project
    // computes over user-supplied bytes.
    hasher.update(b"cairn room invite v1\x00");
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod room_invites {
    use super::tests::*;
    use super::*;

    fn room_with_owner(inst: &Instance) -> (RoomId, TestSender) {
        let owner = TestSender::registered(inst);
        let (room, _) = inst.create_room(public_shape(), owner.user).unwrap();
        (room, owner)
    }

    #[test]
    fn an_invite_admits_its_holder_and_then_is_spent() {
        let inst = Instance::in_memory();
        let (room, owner) = room_with_owner(&inst);
        let bob = TestSender::registered(&inst);
        let carol = TestSender::registered(&inst);

        let token = inst.create_room_invite(owner.user, room, 1, None).unwrap();
        assert_eq!(inst.redeem_room_invite(bob.user, &token, 0).unwrap(), room);
        assert_eq!(inst.room_role(room, bob.user), Some(RoomRole::Member));

        assert!(
            matches!(
                inst.redeem_room_invite(carol.user, &token, 0),
                Err(ServerError::RoomInviteInvalid)
            ),
            "a single-use invite must not admit a second person"
        );
        assert_eq!(inst.room_role(room, carol.user), None);
    }

    #[test]
    fn an_expired_invite_is_refused() {
        let inst = Instance::in_memory();
        let (room, owner) = room_with_owner(&inst);
        let bob = TestSender::registered(&inst);

        let token = inst.create_room_invite(owner.user, room, 5, Some(1_000)).unwrap();
        assert!(inst.redeem_room_invite(bob.user, &token, 999).is_ok());

        let carol = TestSender::registered(&inst);
        assert!(matches!(
            inst.redeem_room_invite(carol.user, &token, 1_000),
            Err(ServerError::RoomInviteInvalid)
        ));
    }

    #[test]
    fn a_revoked_invite_stops_working_immediately() {
        // The reason revocation exists: a link that has escaped is otherwise live until it
        // is spent or expires, and neither may happen soon enough.
        let inst = Instance::in_memory();
        let (room, owner) = room_with_owner(&inst);
        let bob = TestSender::registered(&inst);

        let token = inst.create_room_invite(owner.user, room, 10, None).unwrap();
        inst.revoke_room_invite(owner.user, &token).unwrap();

        assert!(matches!(
            inst.redeem_room_invite(bob.user, &token, 0),
            Err(ServerError::RoomInviteInvalid)
        ));
    }

    #[test]
    fn an_ordinary_member_cannot_mint_or_revoke_an_invite() {
        // An invite is a deferred add, so it must need the same authority as adding someone
        // directly. Otherwise the role check on `add_room_member` is bypassed by anyone
        // willing to route around it.
        let inst = Instance::in_memory();
        let (room, owner) = room_with_owner(&inst);
        let bob = TestSender::registered(&inst);
        inst.add_room_member(room, owner.user, bob.user).unwrap();

        assert!(matches!(
            inst.create_room_invite(bob.user, room, 1, None),
            Err(ServerError::InsufficientRole)
        ));

        let token = inst.create_room_invite(owner.user, room, 1, None).unwrap();
        assert!(matches!(
            inst.revoke_room_invite(bob.user, &token),
            Err(ServerError::InsufficientRole)
        ));
    }

    #[test]
    fn a_non_member_cannot_mint_an_invite_to_a_room() {
        let inst = Instance::in_memory();
        let (room, _owner) = room_with_owner(&inst);
        let outsider = TestSender::registered(&inst);
        assert!(matches!(
            inst.create_room_invite(outsider.user, room, 1, None),
            Err(ServerError::NotAMember)
        ));
    }

    #[test]
    fn an_unlimited_invite_cannot_be_minted() {
        // The tier rule, enforced rather than documented. An uncapped link is a public
        // invite in all but name, and `may_mint_public_invite` forbids one for T1/T2
        // because discoverability feeds `derive_tier` and the tier cannot change.
        let inst = Instance::in_memory();
        let (room, owner) = room_with_owner(&inst);
        assert!(matches!(
            inst.create_room_invite(owner.user, room, u32::MAX, None),
            Err(ServerError::InviteUsesTooHigh)
        ));
        assert!(matches!(
            inst.create_room_invite(owner.user, room, 0, None),
            Err(ServerError::InviteUsesTooHigh)
        ));
        assert!(inst.create_room_invite(owner.user, room, MAX_INVITE_USES, None).is_ok());
    }

    #[test]
    fn redeeming_twice_as_the_same_person_does_not_burn_a_use() {
        // A shared link that someone opens twice must not cost the group a slot.
        let inst = Instance::in_memory();
        let (room, owner) = room_with_owner(&inst);
        let bob = TestSender::registered(&inst);
        let carol = TestSender::registered(&inst);

        let token = inst.create_room_invite(owner.user, room, 2, None).unwrap();
        inst.redeem_room_invite(bob.user, &token, 0).unwrap();
        inst.redeem_room_invite(bob.user, &token, 0).unwrap();

        assert!(
            inst.redeem_room_invite(carol.user, &token, 0).is_ok(),
            "the second use must still be available to someone new"
        );
    }

    #[test]
    fn an_invite_does_not_let_a_room_exceed_its_ceiling() {
        // The ceiling is what `derive_tier` was computed from, so an invite that could
        // exceed it would let a room outgrow the shape its tier was assigned for.
        let inst = Instance::in_memory();
        let owner = TestSender::registered(&inst);
        let shape =
            RoomShape { is_direct: true, is_publicly_discoverable: false, member_ceiling: 2 };
        let (room, _) = inst.create_room(shape, owner.user).unwrap();

        let bob = TestSender::registered(&inst);
        let carol = TestSender::registered(&inst);
        let token = inst.create_room_invite(owner.user, room, 5, None).unwrap();

        inst.redeem_room_invite(bob.user, &token, 0).unwrap();
        assert!(matches!(
            inst.redeem_room_invite(carol.user, &token, 0),
            Err(ServerError::RoomFull)
        ));
    }

    #[test]
    fn the_token_is_not_stored_anywhere() {
        // A database that held working invitations would turn any read access — an operator,
        // a backup, an exfiltration — into admission to every private room with a live link.
        let inst = Instance::in_memory();
        let (room, owner) = room_with_owner(&inst);
        let token = inst.create_room_invite(owner.user, room, 1, None).unwrap();

        let invites = inst.room_invites.lock().unwrap();
        assert!(!invites.contains_key(&token), "the raw token must never be a key");
        assert!(
            invites.keys().all(|k| *k != token),
            "the raw token must not appear in storage in any form"
        );
    }

    #[test]
    fn invites_survive_a_restart() {
        let dir = temp_dir("roominvites");
        let storage = Arc::new(crate::storage::DbStorage::new(&dir).unwrap());
        let (room, token) = {
            let inst = Instance::open(storage.clone()).unwrap();
            let (room, owner) = room_with_owner(&inst);
            let token = inst.create_room_invite(owner.user, room, 1, None).unwrap();
            (room, token)
        };

        let restarted = Instance::open(storage).unwrap();
        let bob = TestSender::registered(&restarted);
        assert_eq!(restarted.redeem_room_invite(bob.user, &token, 0).unwrap(), room);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_spent_invite_stays_spent_across_a_restart() {
        // The one that matters most: if a restart reset the counter, every link ever issued
        // would silently become live again.
        let dir = temp_dir("spentinvite");
        let storage = Arc::new(crate::storage::DbStorage::new(&dir).unwrap());
        let token = {
            let inst = Instance::open(storage.clone()).unwrap();
            let (room, owner) = room_with_owner(&inst);
            let token = inst.create_room_invite(owner.user, room, 1, None).unwrap();
            let bob = TestSender::registered(&inst);
            inst.redeem_room_invite(bob.user, &token, 0).unwrap();
            token
        };

        let restarted = Instance::open(storage).unwrap();
        let mallory = TestSender::registered(&restarted);
        assert!(
            matches!(
                restarted.redeem_room_invite(mallory.user, &token, 0),
                Err(ServerError::RoomInviteInvalid)
            ),
            "a restart must not resurrect a spent invite"
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}

#[cfg(test)]
mod add_after_invite {
    use super::tests::*;
    use super::*;

    #[test]
    fn adding_someone_who_joined_by_invite_is_not_room_full() {
        // The regression this defends. After redeeming an invite the joiner is already a
        // server-side member, so a DM at its ceiling of 2 is full — and the ceiling check
        // ran first, so the member's own client could never complete the MLS add. Invites
        // were useless for the case they exist for, and every unit test passed.
        let inst = Instance::in_memory();
        let alice = TestSender::registered(&inst);
        let bob = TestSender::registered(&inst);
        let shape =
            RoomShape { is_direct: true, is_publicly_discoverable: false, member_ceiling: 2 };
        let (room, _) = inst.create_room(shape, alice.user).unwrap();

        let token = inst.create_room_invite(alice.user, room, 1, None).unwrap();
        inst.redeem_room_invite(bob.user, &token, 0).unwrap();

        assert!(
            inst.add_room_member(room, alice.user, bob.user).is_ok(),
            "re-adding an existing member of a full room must be a no-op, not RoomFull"
        );
    }

    #[test]
    fn the_ceiling_still_refuses_a_genuinely_new_member() {
        // The counterfactual: the fix must not turn the ceiling off.
        let inst = Instance::in_memory();
        let alice = TestSender::registered(&inst);
        let bob = TestSender::registered(&inst);
        let carol = TestSender::registered(&inst);
        let shape =
            RoomShape { is_direct: true, is_publicly_discoverable: false, member_ceiling: 2 };
        let (room, _) = inst.create_room(shape, alice.user).unwrap();

        inst.add_room_member(room, alice.user, bob.user).unwrap();
        assert!(matches!(
            inst.add_room_member(room, alice.user, carol.user),
            Err(ServerError::RoomFull)
        ));
    }
}

#[cfg(test)]
mod disappearing {
    use super::tests::*;
    use super::*;
    use cairn_proto::{EnvelopePayload, Tier};

    fn room_with_message(inst: &Instance, sent_at: i64) -> (RoomId, TestSender) {
        let sender = TestSender::registered(inst);
        let (room, _) = inst.create_room(public_shape(), sender.user).unwrap();
        let e = cairn_proto::Envelope::new(
            Tier::PublicCommunity,
            room,
            sender.user,
            sender.device,
            sent_at,
            EnvelopePayload::Plaintext { body: "ephemeral".into() },
        )
        .unwrap();
        let signature = sender.session.sign(&e.signing_bytes()).unwrap();
        inst.accept(e.with_signature(hex::encode(signature))).unwrap();
        (room, sender)
    }

    #[test]
    fn an_expired_message_leaves_storage_rather_than_being_hidden() {
        // The property the whole feature rests on. Filtering on read would make the client
        // *look* right while the instance still held everything — and what the instance can
        // hand over is the entire point.
        let inst = Instance::in_memory();
        let (room, sender) = room_with_message(&inst, 0);
        inst.set_room_ttl(room, sender.user, Some(1_000)).unwrap();

        // Before expiry it is there.
        assert_eq!(inst.messages_since(room, sender.user, 0, 500).unwrap().len(), 1);

        // After expiry, gone from the caller's view...
        assert!(inst.messages_since(room, sender.user, 0, 1_001).unwrap().is_empty());
        // ...and gone from storage, which is the part that matters.
        assert!(
            inst.storage.messages_since(room, 0).unwrap().is_empty(),
            "an expired message must be deleted, not filtered"
        );
    }

    #[test]
    fn a_room_without_a_timer_keeps_everything() {
        // The counterfactual: without it, a purge bug that deleted unconditionally would
        // still pass the test above.
        let inst = Instance::in_memory();
        let (room, sender) = room_with_message(&inst, 0);
        assert_eq!(
            inst.messages_since(room, sender.user, 0, 10_000_000).unwrap().len(),
            1,
            "no timer means no expiry"
        );
    }

    #[test]
    fn the_timer_applies_to_future_messages_not_past_expectations() {
        // Setting a timer must not retroactively shorten the life of messages people
        // already sent — but it does apply to everything in the room from then on, which is
        // what users of every other product expect. The line being drawn is that turning it
        // *on* is a room-wide decision, not that old messages are exempt forever.
        let inst = Instance::in_memory();
        let (room, sender) = room_with_message(&inst, 0);
        inst.set_room_ttl(room, sender.user, Some(1_000)).unwrap();
        assert!(inst.messages_since(room, sender.user, 0, 2_000).unwrap().is_empty());
    }

    #[test]
    fn any_member_may_set_it_but_a_stranger_may_not() {
        let inst = Instance::in_memory();
        let (room, owner) = room_with_message(&inst, 0);
        let bob = TestSender::registered(&inst);
        inst.add_room_member(room, owner.user, bob.user).unwrap();

        assert!(inst.set_room_ttl(room, bob.user, Some(5_000)).is_ok(), "a member may set it");
        assert_eq!(inst.room_ttl(room), Some(5_000));

        let outsider = TestSender::registered(&inst);
        assert!(matches!(
            inst.set_room_ttl(room, outsider.user, Some(1)),
            Err(ServerError::NotAMember)
        ));
    }

    #[test]
    fn a_nonsense_timer_is_refused() {
        let inst = Instance::in_memory();
        let (room, owner) = room_with_message(&inst, 0);
        assert!(matches!(inst.set_room_ttl(room, owner.user, Some(0)), Err(ServerError::BadTtl)));
        assert!(matches!(inst.set_room_ttl(room, owner.user, Some(-1)), Err(ServerError::BadTtl)));
        assert!(inst.set_room_ttl(room, owner.user, None).is_ok(), "clearing must be allowed");
    }

    #[test]
    fn a_timer_survives_a_restart() {
        // Otherwise a restart quietly turns disappearing messages off, and nobody is told.
        let dir = temp_dir("ttl");
        let storage = Arc::new(crate::storage::DbStorage::new(&dir).unwrap());
        let room = {
            let inst = Instance::open(storage.clone()).unwrap();
            let (room, owner) = room_with_message(&inst, 0);
            inst.set_room_ttl(room, owner.user, Some(60_000)).unwrap();
            room
        };
        let restarted = Instance::open(storage).unwrap();
        assert_eq!(restarted.room_ttl(room), Some(60_000));
        std::fs::remove_dir_all(&dir).ok();
    }
}
