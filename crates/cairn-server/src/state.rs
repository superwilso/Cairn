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
}

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
    log: Vec<StoredMessage>,
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
/// The `user` binding is fixed at registration and never rewritten. That is the whole
/// defence against impersonation: an attacker may register their own device, but they
/// cannot make it speak for somebody else's account.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceRecord {
    pub user: UserId,
    /// Hex-encoded signature public key.
    pub public_key: String,
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
        Ok(Self { rooms: Mutex::new(rooms), devices: Mutex::new(devices), franking_key, storage })
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
        let state = PersistedState {
            rooms: rooms
                .iter()
                .map(|(id, room)| PersistedRoom { id: *id, room: room.clone() })
                .collect(),
            devices: devices
                .iter()
                .map(|(id, record)| PersistedDevice { id: *id, record: record.clone() })
                .collect(),
        };
        self.storage.save_state(&state)?;
        Ok(())
    }

    /// Register a device's signing key against an account.
    ///
    /// Registration is **append-only**: an existing device cannot be re-registered with a
    /// different key or a different account. Allowing that would let anyone who learns a
    /// device ID overwrite its key and then send as its owner, which is exactly the attack
    /// signatures are here to stop. Rotating a key means registering a new device, which
    /// is visible to the account's other devices.
    pub fn register_device(
        &self,
        user: UserId,
        device: DeviceId,
        public_key: &[u8],
    ) -> Result<(), ServerError> {
        let mut devices = self.devices.lock().expect("devices mutex poisoned");
        if devices.contains_key(&device) {
            return Err(ServerError::DeviceAlreadyRegistered);
        }
        devices.insert(device, DeviceRecord { user, public_key: hex::encode(public_key) });
        drop(devices);
        let rooms = self.rooms.lock().expect("rooms mutex poisoned");
        self.persist(&rooms)?;
        Ok(())
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
    pub fn create_room(&self, shape: RoomShape) -> Result<(RoomId, RoomSeal), ServerError> {
        let seal = RoomSeal::new(shape)?;
        let id = RoomId::new();
        let mut rooms = self.rooms.lock().expect("rooms mutex poisoned");
        rooms.insert(id, Room { seal, next_seq: 0, last_franked: None, log: Vec::new() });
        self.persist(&rooms)?;
        Ok((id, seal))
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
    pub fn messages_since(
        &self,
        room: RoomId,
        after: u64,
    ) -> Result<Vec<StoredMessage>, ServerError> {
        let rooms = self.rooms.lock().expect("rooms mutex poisoned");
        let room = rooms.get(&room).ok_or(ServerError::NoSuchRoom)?;
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
mod tests {
    use super::*;
    use cairn_proto::{DeviceId, EnvelopePayload, Tier, UserId};

    fn dm_shape() -> RoomShape {
        RoomShape { is_direct: true, is_publicly_discoverable: false, member_ceiling: 2 }
    }

    fn public_shape() -> RoomShape {
        RoomShape { is_direct: false, is_publicly_discoverable: true, member_ceiling: 50_000 }
    }

    /// A registered device that can produce properly signed envelopes.
    struct TestSender {
        session: cairn_crypto::mls::Session,
        user: UserId,
        device: DeviceId,
    }

    impl TestSender {
        fn registered(inst: &Instance) -> Self {
            let s = Self {
                session: cairn_crypto::mls::Session::new(b"tester").unwrap(),
                user: UserId::new(),
                device: DeviceId::new(),
            };
            inst.register_device(s.user, s.device, s.session.public_key()).unwrap();
            s
        }

        fn envelope(&self, room: RoomId, payload: EnvelopePayload) -> Envelope {
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
        let (_, dm) = inst.create_room(dm_shape()).unwrap();
        assert_eq!(dm.tier(), Tier::Private);
        let (_, pubc) = inst.create_room(public_shape()).unwrap();
        assert_eq!(pubc.tier(), Tier::PublicCommunity);
    }

    #[test]
    fn server_rejects_plaintext_smuggled_into_an_encrypted_room() {
        // The defence that does not depend on the client behaving.
        let inst = Instance::in_memory();
        let sender = TestSender::registered(&inst);
        let (room, _) = inst.create_room(dm_shape()).unwrap();
        let e = sender.envelope(room, EnvelopePayload::Plaintext { body: "sneaky".into() });
        assert!(matches!(inst.accept(e), Err(ServerError::Rejected(_))));
    }

    #[test]
    fn server_accepts_ciphertext_in_an_encrypted_room() {
        let inst = Instance::in_memory();
        let sender = TestSender::registered(&inst);
        let (room, _) = inst.create_room(dm_shape()).unwrap();
        let e =
            sender.envelope(room, EnvelopePayload::MlsApplication { ciphertext: vec![1, 2, 3] });
        assert!(inst.accept(e).is_ok());
    }

    #[test]
    fn sequence_numbers_are_strictly_increasing() {
        let inst = Instance::in_memory();
        let sender = TestSender::registered(&inst);
        let (room, _) = inst.create_room(public_shape()).unwrap();
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
        let (room, _) = inst.create_room(dm_shape()).unwrap();
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
        let (room, _) = inst.create_room(dm_shape()).unwrap();
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
            let (room, _) = inst.create_room(dm_shape()).unwrap();
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
            let (room, _) = inst.create_room(public_shape()).unwrap();
            for i in 0..3 {
                let e = sender.envelope(room, EnvelopePayload::Plaintext { body: format!("m{i}") });
                inst.accept(e).unwrap();
            }
            (room, sender.user, sender.device, sender.session.public_key().to_vec())
        };

        let restarted = Instance::open(storage).unwrap();
        assert_eq!(restarted.room_seal(room).unwrap().tier(), Tier::PublicCommunity);
        assert_eq!(restarted.messages_since(room, 0).unwrap().len(), 3);

        // Device registrations must survive too, or every client is locked out after a
        // restart. Re-registering the same device must be refused, which proves the
        // record was actually restored rather than quietly recreated.
        assert!(matches!(
            restarted.register_device(user, device, &pubkey),
            Err(ServerError::DeviceAlreadyRegistered)
        ));

        // Sequence numbers must continue, not restart — a repeated server_seq would let
        // two different messages carry interchangeable franking contexts.
        let sender2 = TestSender::registered(&restarted);
        let e = sender2.envelope(room, EnvelopePayload::Plaintext { body: "after".into() });
        assert_eq!(restarted.accept(e).unwrap().server_seq, 4);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn unsigned_messages_are_rejected() {
        let inst = Instance::in_memory();
        let sender = TestSender::registered(&inst);
        let (room, _) = inst.create_room(public_shape()).unwrap();
        let e = sender.unsigned(room, EnvelopePayload::Plaintext { body: "hi".into() });
        assert!(matches!(inst.accept(e), Err(ServerError::Unsigned)));
    }

    #[test]
    fn an_unregistered_device_cannot_send() {
        let inst = Instance::in_memory();
        let (room, _) = inst.create_room(public_shape()).unwrap();
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
        let (room, _) = inst.create_room(public_shape()).unwrap();

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
        let (room, _) = inst.create_room(public_shape()).unwrap();

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
        let (room, _) = inst.create_room(public_shape()).unwrap();

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
            inst.register_device(alice.user, alice.device, attacker_key.public_key()),
            Err(ServerError::DeviceAlreadyRegistered)
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
        let (room, _) = inst.create_room(dm_shape()).unwrap();

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
        let (room, _) = inst.create_room(public_shape()).unwrap();

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
        let (room, _) = inst.create_room(public_shape()).unwrap();
        for i in 0..3 {
            let e = sender.envelope(room, EnvelopePayload::Plaintext { body: format!("m{i}") });
            inst.accept(e).unwrap();
        }
        assert_eq!(inst.messages_since(room, 0).unwrap().len(), 3);
        assert_eq!(inst.messages_since(room, 2).unwrap().len(), 1);
        assert_eq!(inst.messages_since(room, 99).unwrap().len(), 0);
    }
}
