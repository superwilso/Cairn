//! Instance state and the rules the server enforces.
//!
//! Logic lives here rather than in the HTTP handlers so it can be tested without a
//! socket. The handlers in [`crate::http`] are a thin translation layer.
//!
//! State is held in memory and snapshotted through [`crate::storage`] on every mutation,
//! so rooms, the message log, and — critically — the franking key survive a restart.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use cairn_crypto::franking::{Commitment, Context as FrankingContext, ServerFrankingKey, Tag};
use cairn_crypto::TranscriptReport;
use cairn_proto::{DeviceId, Envelope, RoomId, RoomSeal, RoomShape, ShapeError, UserId};

use crate::storage::{Storage, StorageError};

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
    #[error("request signature is missing, malformed, or does not verify")]
    BadRequestAuth,
    #[error("request timestamp is outside the accepted window")]
    RequestExpired,
}

/// How far outside the present a signed request's timestamp may be.
///
/// Bounds replay without requiring server-side nonce storage. Generous enough to tolerate
/// ordinary clock skew, tight enough that a captured request is not indefinitely useful.
pub const REQUEST_WINDOW_MS: i64 = 60_000;

/// A room as the server knows it.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Room {
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
    members: Vec<UserId>,
    log: Vec<StoredMessage>,
}

impl Room {
    fn has_member(&self, user: UserId) -> bool {
        self.members.contains(&user)
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

/// Everything about an instance that must survive a restart.
///
/// A list rather than a map so the on-disk form does not depend on how map keys are
/// encoded, which is a needless way for a format to break between versions.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct PersistedState {
    pub rooms: Vec<PersistedRoom>,
    #[serde(default)]
    pub devices: Vec<PersistedDevice>,
    #[serde(default)]
    pub accounts: Vec<PersistedAccount>,
    #[serde(default)]
    pub invites: Vec<PersistedInvite>,
    #[serde(default)]
    pub registration_policy: RegistrationPolicy,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PersistedAccount {
    id: UserId,
    record: AccountRecord,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PersistedInvite {
    token: String,
    record: InviteRecord,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PersistedDevice {
    id: DeviceId,
    record: DeviceRecord,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PersistedRoom {
    id: RoomId,
    room: Room,
}

/// The instance.
pub struct Instance {
    rooms: Mutex<HashMap<RoomId, Room>>,
    devices: Mutex<HashMap<DeviceId, DeviceRecord>>,
    accounts: Mutex<HashMap<UserId, AccountRecord>>,
    invites: Mutex<HashMap<String, InviteRecord>>,
    registration_policy: Mutex<RegistrationPolicy>,
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
        let persisted = storage.load_state()?;
        let rooms = persisted.rooms.into_iter().map(|r| (r.id, r.room)).collect();
        let devices = persisted.devices.into_iter().map(|d| (d.id, d.record)).collect();
        let accounts = persisted.accounts.into_iter().map(|a| (a.id, a.record)).collect();
        let invites = persisted.invites.into_iter().map(|i| (i.token, i.record)).collect();
        Ok(Self {
            rooms: Mutex::new(rooms),
            devices: Mutex::new(devices),
            accounts: Mutex::new(accounts),
            invites: Mutex::new(invites),
            registration_policy: Mutex::new(persisted.registration_policy),
            franking_key,
            storage,
        })
    }

    /// An ephemeral instance backed by nothing. Tests and throwaway runs only.
    pub fn in_memory() -> Self {
        Self::open(Arc::new(crate::storage::MemoryStorage))
            .expect("memory storage cannot fail to open")
    }

    /// Snapshot to durable storage.
    ///
    /// Called while the caller still holds the rooms lock, so a save can never interleave
    /// with a mutation and record a torn view of the state.
    fn persist(&self, rooms: &HashMap<RoomId, Room>) -> Result<(), ServerError> {
        let devices = self.devices.lock().expect("devices mutex poisoned");
        let accounts = self.accounts.lock().expect("accounts mutex poisoned");
        let invites = self.invites.lock().expect("invites mutex poisoned");
        let state = PersistedState {
            rooms: rooms
                .iter()
                .map(|(id, room)| PersistedRoom { id: *id, room: room.clone() })
                .collect(),
            devices: devices
                .iter()
                .map(|(id, record)| PersistedDevice { id: *id, record: record.clone() })
                .collect(),
            accounts: accounts
                .iter()
                .map(|(id, record)| PersistedAccount { id: *id, record: record.clone() })
                .collect(),
            invites: invites
                .iter()
                .map(|(token, record)| PersistedInvite {
                    token: token.clone(),
                    record: record.clone(),
                })
                .collect(),
            registration_policy: *self.registration_policy.lock().expect("policy mutex poisoned"),
        };
        self.storage.save_state(&state)?;
        Ok(())
    }

    /// The instance's registration policy.
    pub fn registration_policy(&self) -> RegistrationPolicy {
        *self.registration_policy.lock().expect("policy mutex poisoned")
    }

    /// Set the registration policy. Operator action.
    pub fn set_registration_policy(&self, policy: RegistrationPolicy) -> Result<(), ServerError> {
        *self.registration_policy.lock().expect("policy mutex poisoned") = policy;
        let rooms = self.rooms.lock().expect("rooms mutex poisoned");
        self.persist(&rooms)
    }

    /// Mint a registration invite. Operator action.
    pub fn create_invite(
        &self,
        token: &str,
        expires_at_ms: Option<i64>,
    ) -> Result<(), ServerError> {
        self.invites
            .lock()
            .expect("invites mutex poisoned")
            .insert(token.to_owned(), InviteRecord { used_by: None, expires_at_ms });
        let rooms = self.rooms.lock().expect("rooms mutex poisoned");
        self.persist(&rooms)
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
        }

        devices.insert(device, DeviceRecord { user, public_key: hex::encode(public_key) });
        accounts.insert(user, AccountRecord { devices: vec![device] });

        drop(devices);
        drop(accounts);
        drop(invites);
        let rooms = self.rooms.lock().expect("rooms mutex poisoned");
        self.persist(&rooms)
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

        devices.insert(new_device, DeviceRecord { user, public_key: hex::encode(new_public_key) });
        account.devices.push(new_device);

        drop(devices);
        drop(accounts);
        let rooms = self.rooms.lock().expect("rooms mutex poisoned");
        self.persist(&rooms)
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
        let mut rooms = self.rooms.lock().expect("rooms mutex poisoned");
        rooms.insert(
            id,
            Room { seal, next_seq: 0, last_franked: None, members: vec![creator], log: Vec::new() },
        );
        self.persist(&rooms)?;
        Ok((id, seal))
    }

    /// Add an account to a room, at the request of an existing member.
    ///
    /// Only a member may extend membership. This is deliberately the *only* way into a
    /// non-public room: the tier model says a T1/T2 room cannot mint a public invite
    /// (`RoomSeal::may_mint_public_invite`), so there is no self-service path in.
    pub fn add_room_member(
        &self,
        room: RoomId,
        actor: UserId,
        new_member: UserId,
    ) -> Result<(), ServerError> {
        let mut rooms = self.rooms.lock().expect("rooms mutex poisoned");
        let r = rooms.get_mut(&room).ok_or(ServerError::NoSuchRoom)?;
        if !r.has_member(actor) {
            return Err(ServerError::NotAMember);
        }
        if r.members.len() as u32 >= r.seal.member_ceiling() {
            return Err(ServerError::RoomFull);
        }
        if !r.has_member(new_member) {
            r.members.push(new_member);
        }
        self.persist(&rooms)
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
            r.members.push(user);
        }
        self.persist(&rooms)
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
        resource: Option<RoomId>,
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
        room.log.push(stored.clone());
        self.persist(&rooms)?;
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
    ) -> Result<Vec<StoredMessage>, ServerError> {
        let rooms = self.rooms.lock().expect("rooms mutex poisoned");
        let room = rooms.get(&room).ok_or(ServerError::NoSuchRoom)?;
        if !room.has_member(actor) {
            return Err(ServerError::NotAMember);
        }
        Ok(room.log.iter().filter(|m| m.server_seq > after).cloned().collect())
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

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("cairn-state-{}-{}", name, uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_report_filed_before_a_restart_still_verifies_after_it() {
        // The property persistence exists for. If the franking key changed on restart,
        // every tag the instance ever issued would stop verifying — a moderation system
        // that forgets its own evidence.
        use cairn_crypto::franking::{Context, ReportedMessage, TranscriptReport};

        let dir = temp_dir("restart");
        let storage = Arc::new(crate::storage::FileStorage::new(&dir).unwrap());

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
        let storage = Arc::new(crate::storage::FileStorage::new(&dir).unwrap());

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
        assert_eq!(restarted.messages_since(room, user, 0).unwrap().len(), 3);

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
        inst.accept(sender.sign(e)).unwrap();

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
        assert_eq!(inst.messages_since(room, sender.user, 0).unwrap().len(), 3);
        assert_eq!(inst.messages_since(room, sender.user, 2).unwrap().len(), 1);
        assert_eq!(inst.messages_since(room, sender.user, 99).unwrap().len(), 0);
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
        let storage = Arc::new(crate::storage::FileStorage::new(&dir).unwrap());

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

        assert!(matches!(inst.messages_since(room, mallory.user, 0), Err(ServerError::NotAMember)));
        // The member still can, so the check is not simply refusing everyone.
        assert_eq!(inst.messages_since(room, alice.user, 0).unwrap().len(), 1);
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
            .sign(&cairn_proto::request_signing_bytes("read", Some(room), issued))
            .unwrap();

        assert_eq!(
            inst.authenticate_request(alice.device, "read", Some(room), issued, &sig, issued)
                .unwrap(),
            alice.user
        );

        // A read authorization must not also authorize a write.
        assert!(matches!(
            inst.authenticate_request(alice.device, "add_member", Some(room), issued, &sig, issued),
            Err(ServerError::BadRequestAuth)
        ));

        // …nor the same action against a different room.
        assert!(matches!(
            inst.authenticate_request(
                alice.device,
                "read",
                Some(RoomId::new()),
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
                Some(room),
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
        let storage = Arc::new(crate::storage::FileStorage::new(&dir).unwrap());

        let (room, member, outsider) = {
            let inst = Instance::open(storage.clone()).unwrap();
            let alice = TestSender::registered(&inst);
            let mallory = TestSender::registered(&inst);
            let room = private_room(&inst, alice.user);
            (room, alice.user, mallory.user)
        };

        let restarted = Instance::open(storage).unwrap();
        // A member must not be locked out by a restart…
        assert!(restarted.messages_since(room, member, 0).is_ok());
        // …and an outsider must not be let in by one.
        assert!(matches!(
            restarted.messages_since(room, outsider, 0),
            Err(ServerError::NotAMember)
        ));
        std::fs::remove_dir_all(&dir).ok();
    }
}
