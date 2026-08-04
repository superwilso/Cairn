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
use cairn_proto::{Envelope, RoomId, RoomSeal, RoomShape, ShapeError};

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

/// Everything about an instance that must survive a restart.
///
/// A list rather than a map so the on-disk form does not depend on how map keys are
/// encoded, which is a needless way for a format to break between versions.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct PersistedState {
    pub rooms: Vec<PersistedRoom>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PersistedRoom {
    id: RoomId,
    room: Room,
}

/// The instance.
pub struct Instance {
    rooms: Mutex<HashMap<RoomId, Room>>,
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
        Ok(Self { rooms: Mutex::new(rooms), franking_key, storage })
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
        let state = PersistedState {
            rooms: rooms
                .iter()
                .map(|(id, room)| PersistedRoom { id: *id, room: room.clone() })
                .collect(),
        };
        self.storage.save_state(&state)?;
        Ok(())
    }

    /// Create a room, deriving and sealing its tier.
    pub fn create_room(&self, shape: RoomShape) -> Result<(RoomId, RoomSeal), ServerError> {
        let seal = RoomSeal::new(shape)?;
        let id = RoomId::new();
        let mut rooms = self.rooms.lock().expect("rooms mutex poisoned");
        rooms.insert(id, Room { seal, next_seq: 0, log: Vec::new() });
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
        let mut rooms = self.rooms.lock().expect("rooms mutex poisoned");
        let room = rooms.get_mut(&envelope.room).ok_or(ServerError::NoSuchRoom)?;

        envelope.validate_for_tier(room.seal.tier())?;

        room.next_seq += 1;
        let server_seq = room.next_seq;

        let franking_tag = match &envelope.franking_commitment {
            Some(hex_commitment) => {
                let commitment =
                    decode_commitment(hex_commitment).ok_or(ServerError::BadCommitment)?;
                Some(self.franking_key.tag(&FrankingContext {
                    commitment,
                    room: envelope.room,
                    sender: envelope.sender,
                    sender_device: envelope.sender_device,
                    server_seq,
                }))
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

    fn envelope(room: RoomId, payload: EnvelopePayload) -> Envelope {
        Envelope {
            version: cairn_proto::PROTOCOL_VERSION,
            id: cairn_proto::MessageId::new(),
            room,
            sender: UserId::new(),
            sender_device: DeviceId::new(),
            sent_at_ms: 0,
            payload,
            franking_commitment: None,
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
        let (room, _) = inst.create_room(dm_shape()).unwrap();
        let e = envelope(room, EnvelopePayload::Plaintext { body: "sneaky".into() });
        assert!(matches!(inst.accept(e), Err(ServerError::Rejected(_))));
    }

    #[test]
    fn server_accepts_ciphertext_in_an_encrypted_room() {
        let inst = Instance::in_memory();
        let (room, _) = inst.create_room(dm_shape()).unwrap();
        let e = envelope(room, EnvelopePayload::MlsApplication { ciphertext: vec![1, 2, 3] });
        assert!(inst.accept(e).is_ok());
    }

    #[test]
    fn sequence_numbers_are_strictly_increasing() {
        let inst = Instance::in_memory();
        let (room, _) = inst.create_room(public_shape()).unwrap();
        let mut last = 0;
        for i in 0..5 {
            let e = envelope(room, EnvelopePayload::Plaintext { body: format!("m{i}") });
            let stored = inst.accept(e).unwrap();
            assert!(stored.server_seq > last);
            last = stored.server_seq;
        }
    }

    #[test]
    fn unknown_room_is_rejected() {
        let inst = Instance::in_memory();
        let e = envelope(RoomId::new(), EnvelopePayload::Plaintext { body: "x".into() });
        assert!(matches!(inst.accept(e), Err(ServerError::NoSuchRoom)));
    }

    #[test]
    fn messages_are_franked_when_a_commitment_is_present() {
        let inst = Instance::in_memory();
        let (room, _) = inst.create_room(dm_shape()).unwrap();
        let (commitment, _opening) = cairn_crypto::commit(b"hello", None);

        let e = envelope(room, EnvelopePayload::MlsApplication { ciphertext: vec![9] })
            .with_franking_commitment(commitment.to_hex());
        let stored = inst.accept(e).unwrap();

        let tag = stored.franking_tag.expect("a franked message must carry a tag");
        let ctx = FrankingContext {
            commitment,
            room,
            sender: stored.envelope.sender,
            sender_device: stored.envelope.sender_device,
            server_seq: stored.server_seq,
        };
        assert!(inst.franking_key().verify_tag(&ctx, &tag));
    }

    #[test]
    fn malformed_commitment_is_rejected() {
        let inst = Instance::in_memory();
        let (room, _) = inst.create_room(dm_shape()).unwrap();
        let e = envelope(room, EnvelopePayload::MlsApplication { ciphertext: vec![9] })
            .with_franking_commitment("not-hex");
        assert!(matches!(inst.accept(e), Err(ServerError::BadCommitment)));
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
            let (room, _) = inst.create_room(dm_shape()).unwrap();
            let (commitment, opening) = cairn_crypto::commit(b"evidence", None);
            let e = envelope(room, EnvelopePayload::MlsApplication { ciphertext: vec![1] })
                .with_franking_commitment(commitment.to_hex());
            let stored = inst.accept(e).unwrap();
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
                prev: None,
                context: Context {
                    commitment,
                    room,
                    sender,
                    sender_device: device,
                    server_seq: seq,
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

        let room = {
            let inst = Instance::open(storage.clone()).unwrap();
            let (room, _) = inst.create_room(public_shape()).unwrap();
            for i in 0..3 {
                let e = envelope(room, EnvelopePayload::Plaintext { body: format!("m{i}") });
                inst.accept(e).unwrap();
            }
            room
        };

        let restarted = Instance::open(storage).unwrap();
        assert_eq!(restarted.room_seal(room).unwrap().tier(), Tier::PublicCommunity);
        assert_eq!(restarted.messages_since(room, 0).unwrap().len(), 3);

        // Sequence numbers must continue, not restart — a repeated server_seq would let
        // two different messages carry interchangeable franking contexts.
        let e = envelope(room, EnvelopePayload::Plaintext { body: "after".into() });
        assert_eq!(restarted.accept(e).unwrap().server_seq, 4);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn messages_since_filters_by_sequence() {
        let inst = Instance::in_memory();
        let (room, _) = inst.create_room(public_shape()).unwrap();
        for i in 0..3 {
            let e = envelope(room, EnvelopePayload::Plaintext { body: format!("m{i}") });
            inst.accept(e).unwrap();
        }
        assert_eq!(inst.messages_since(room, 0).unwrap().len(), 3);
        assert_eq!(inst.messages_since(room, 2).unwrap().len(), 1);
        assert_eq!(inst.messages_since(room, 99).unwrap().len(), 0);
    }
}
