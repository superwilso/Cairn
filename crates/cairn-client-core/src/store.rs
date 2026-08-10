//! What a client must remember about its conversations, as opposed to its cryptography.
//!
//! `cairn_crypto::store` persists MLS group state, key package secrets, and the device
//! key. None of that says *which* group belongs to which room. MLS chooses group ids and
//! the server chooses room ids, and the mapping between them exists only on the client —
//! lose it and the group state is still on disk but unreachable, which is the same
//! practical outcome as losing it.
//!
//! Kept here rather than in `cairn-crypto` because it is conversation state, not key
//! material: the crypto crate should not need to know what a [`RoomId`] is to store a
//! group. Kept below the FFI line for the reason in ADR-006 — five platform clients each
//! inventing their own index would be five sets of "the room opens empty" bugs.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use cairn_proto::{RoomId, RoomSeal, Tier};

#[derive(Debug, thiserror::Error)]
pub enum IndexError {
    #[error("conversation index i/o error: {0}")]
    Io(#[from] io::Error),
    #[error("conversation index is corrupt or from an incompatible version: {0}")]
    Corrupt(#[from] serde_json::Error),
    #[error("stored group id for room {0} is not valid hex")]
    BadGroupId(RoomId),
    #[error(
        "room {0} is already recorded at a different encryption tier; \
         a tier is immutable after creation and this store would silently change it"
    )]
    TierMismatch(RoomId),
}

/// One room, as this client needs to find it again.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConversationRecord {
    /// Hex, because an MLS group id is arbitrary bytes and JSON is not.
    pub group_id: Option<String>,
    /// The room's tier, recorded so a resumed conversation is rebuilt at the tier it was
    /// created with rather than one inferred from whatever the server says today.
    pub tier: Tier,
    /// Highest server sequence number this device has already processed.
    ///
    /// Persisted because **a message cannot be processed twice**: MLS deletes each message
    /// key after use, so re-reading a room from the start after a restart does not replay
    /// the history, it produces `invalid generation` and `incorrect epoch` errors for
    /// traffic already consumed. A client that keeps this only in memory shows a wall of
    /// decryption failures on every launch and teaches its user that those are normal —
    /// which is the state in which a real failure goes unnoticed.
    ///
    /// `#[serde(default)]` so an index written before this field loads as 0 rather than
    /// failing, which for an old index means one final replay and then correctness.
    #[serde(default)]
    pub cursor: u64,
}

/// A room id → MLS group id index, persisted as one JSON file.
///
/// Deliberately boring, matching `cairn-server`'s storage: the whole file is rewritten on
/// every change. A client has tens of rooms, not millions, so the O(n) rewrite costs
/// nothing and buys atomicity for free.
#[derive(Debug)]
pub struct ConversationIndex {
    path: PathBuf,
    rooms: BTreeMap<RoomId, ConversationRecord>,
}

impl ConversationIndex {
    /// Open the index at `dir`, or start an empty one.
    ///
    /// A missing file is a first run. A *corrupt* file is an error, never an empty index:
    /// silently starting over would strand every existing group and present the user with
    /// an account that has apparently never spoken to anyone.
    pub fn open(dir: impl AsRef<Path>) -> Result<Self, IndexError> {
        let dir = dir.as_ref();
        fs::create_dir_all(dir)?;
        let path = dir.join("conversations.json");

        let rooms = match fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes)?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => BTreeMap::new(),
            Err(e) => return Err(e.into()),
        };

        Ok(Self { path, rooms })
    }

    /// Record a room, or confirm what is already recorded.
    ///
    /// Refuses to change a room's tier. `RoomSeal` has no tier setter precisely so that a
    /// tier cannot be weakened after creation (`docs/02-encryption-tiers.md` §4), and an
    /// index that let a second write reclassify a room would reintroduce that setter
    /// through the back door — a T1 room could come back as T3 and the client would render
    /// the badge the store told it to.
    pub fn record(
        &mut self,
        room: RoomId,
        seal: &RoomSeal,
        group_id: Option<&[u8]>,
    ) -> Result<(), IndexError> {
        if let Some(existing) = self.rooms.get(&room) {
            if existing.tier != seal.tier() {
                return Err(IndexError::TierMismatch(room));
            }
        }

        // Recording a room again must not rewind its cursor: `record` is called after a
        // join and after an add, both of which happen mid-conversation.
        let cursor = self.rooms.get(&room).map_or(0, |existing| existing.cursor);
        self.rooms.insert(
            room,
            ConversationRecord { group_id: group_id.map(hex::encode), tier: seal.tier(), cursor },
        );
        self.save()
    }

    /// Note that everything up to `seq` has been processed.
    ///
    /// Monotonic. Messages can arrive out of order within one fetch, and moving the cursor
    /// backwards would mean asking the server for traffic whose keys are already gone.
    pub fn advance(&mut self, room: RoomId, seq: u64) -> Result<(), IndexError> {
        let Some(record) = self.rooms.get_mut(&room) else {
            return Ok(());
        };
        if seq <= record.cursor {
            return Ok(());
        }
        record.cursor = seq;
        self.save()
    }

    /// Where to resume reading this room. Zero for a room never read.
    pub fn cursor(&self, room: &RoomId) -> u64 {
        self.rooms.get(room).map_or(0, |record| record.cursor)
    }

    pub fn get(&self, room: &RoomId) -> Option<&ConversationRecord> {
        self.rooms.get(room)
    }

    /// The MLS group id for a room, ready to hand to `Conversation::resume_encrypted`.
    pub fn group_id(&self, room: &RoomId) -> Result<Option<Vec<u8>>, IndexError> {
        let Some(record) = self.rooms.get(room) else {
            return Ok(None);
        };
        let Some(hex_id) = record.group_id.as_ref() else {
            return Ok(None);
        };
        hex::decode(hex_id).map(Some).map_err(|_| IndexError::BadGroupId(*room))
    }

    pub fn rooms(&self) -> impl Iterator<Item = (&RoomId, &ConversationRecord)> {
        self.rooms.iter()
    }

    pub fn forget(&mut self, room: &RoomId) -> Result<(), IndexError> {
        self.rooms.remove(room);
        self.save()
    }

    /// Temp file plus rename, so a crash leaves the old index rather than a truncated one.
    fn save(&self) -> Result<(), IndexError> {
        let tmp = self.path.with_extension("tmp");
        fs::write(&tmp, serde_json::to_vec_pretty(&self.rooms)?)?;
        fs::rename(&tmp, &self.path)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cairn_proto::RoomShape;

    #[test]
    fn a_read_cursor_survives_a_restart() {
        // Not a convenience. MLS discards each message key after use, so a client that
        // restarts at sequence 0 cannot re-read what it already read — it produces
        // decryption failures for its own history. Observed by restarting the interactive
        // client against a live server: "invalid generation 0", "incorrect epoch".
        let dir = scratch("cursor");
        let room = RoomId::new();
        let seal = RoomSeal::new(RoomShape {
            is_direct: true,
            is_publicly_discoverable: false,
            member_ceiling: 2,
        })
        .unwrap();

        {
            let mut index = ConversationIndex::open(&dir).unwrap();
            index.record(room, &seal, Some(b"group")).unwrap();
            assert_eq!(index.cursor(&room), 0);
            index.advance(room, 7).unwrap();
        }

        let index = ConversationIndex::open(&dir).unwrap();
        assert_eq!(index.cursor(&room), 7);
    }

    #[test]
    fn a_cursor_never_moves_backwards() {
        let dir = scratch("monotonic");
        let room = RoomId::new();
        let seal = RoomSeal::new(RoomShape {
            is_direct: true,
            is_publicly_discoverable: false,
            member_ceiling: 2,
        })
        .unwrap();

        let mut index = ConversationIndex::open(&dir).unwrap();
        index.record(room, &seal, Some(b"group")).unwrap();
        index.advance(room, 9).unwrap();

        // Out-of-order arrivals within one fetch must not rewind it.
        index.advance(room, 4).unwrap();
        assert_eq!(index.cursor(&room), 9);

        // Nor must re-recording the room, which happens on every join and add.
        index.record(room, &seal, Some(b"group")).unwrap();
        assert_eq!(index.cursor(&room), 9, "re-recording a room must not replay it");
    }

    fn direct() -> RoomSeal {
        RoomSeal::new(cairn_proto::RoomShape {
            is_direct: true,
            is_publicly_discoverable: false,
            member_ceiling: 2,
        })
        .unwrap()
    }

    fn public() -> RoomSeal {
        RoomSeal::new(cairn_proto::RoomShape {
            is_direct: false,
            is_publicly_discoverable: true,
            member_ceiling: 5_000,
        })
        .unwrap()
    }

    fn private_community() -> RoomSeal {
        RoomSeal::new(cairn_proto::RoomShape {
            is_direct: false,
            is_publicly_discoverable: false,
            member_ceiling: 50,
        })
        .unwrap()
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir()
            .join("cairn-index-tests")
            .join(format!("{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn a_room_is_findable_after_a_restart() {
        let dir = scratch("findable");
        let room = RoomId::new();
        let seal = direct();

        let mut index = ConversationIndex::open(&dir).unwrap();
        index.record(room, &seal, Some(b"mls-group-bytes")).unwrap();
        drop(index);

        let reopened = ConversationIndex::open(&dir).unwrap();
        assert_eq!(reopened.group_id(&room).unwrap().as_deref(), Some(&b"mls-group-bytes"[..]));
        assert_eq!(reopened.get(&room).unwrap().tier, Tier::Private);
    }

    #[test]
    fn an_unknown_room_has_no_group() {
        let dir = scratch("unknown");
        let index = ConversationIndex::open(&dir).unwrap();
        assert!(index.group_id(&RoomId::new()).unwrap().is_none());
    }

    #[test]
    fn a_public_room_records_no_group() {
        let dir = scratch("public");
        let room = RoomId::new();
        let mut index = ConversationIndex::open(&dir).unwrap();
        index.record(room, &public(), None).unwrap();
        assert!(index.group_id(&room).unwrap().is_none());
        assert_eq!(index.get(&room).unwrap().tier, Tier::PublicCommunity);
    }

    #[test]
    fn a_recorded_room_cannot_change_tier() {
        // The index must not become the tier setter that `RoomSeal` deliberately lacks.
        // A T1 room that came back as T3 would render a plaintext badge on an encrypted
        // room, or worse, an encrypted badge on a plaintext one.
        let dir = scratch("tier-immutable");
        let room = RoomId::new();
        let mut index = ConversationIndex::open(&dir).unwrap();
        index.record(room, &direct(), Some(b"g")).unwrap();

        let err = index
            .record(room, &public(), Some(b"g"))
            .expect_err("a room's tier must not be rewritable through the index");
        assert!(matches!(err, IndexError::TierMismatch(_)));

        // And the stored tier is unchanged, not left half-written.
        assert_eq!(index.get(&room).unwrap().tier, Tier::Private);
        let reopened = ConversationIndex::open(&dir).unwrap();
        assert_eq!(reopened.get(&room).unwrap().tier, Tier::Private);
    }

    #[test]
    fn a_corrupt_index_is_an_error_not_an_empty_account() {
        let dir = scratch("corrupt");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("conversations.json"), b"{ not json").unwrap();

        let err = ConversationIndex::open(&dir).expect_err("a corrupt index must surface");
        assert!(matches!(err, IndexError::Corrupt(_)));
    }

    #[test]
    fn re_recording_the_same_room_updates_the_group() {
        // A room can be re-keyed into a new MLS group (a rejoin), and the index has to
        // follow. Only the tier is frozen.
        let dir = scratch("rerecord");
        let room = RoomId::new();
        let seal = private_community();
        let mut index = ConversationIndex::open(&dir).unwrap();
        index.record(room, &seal, Some(b"first")).unwrap();
        index.record(room, &seal, Some(b"second")).unwrap();
        assert_eq!(index.group_id(&room).unwrap().as_deref(), Some(&b"second"[..]));
    }
}
