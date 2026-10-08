//! Local message history.
//!
//! MLS discards each message key once it is used, so a client that keeps nothing cannot
//! re-read its own conversation — a restart loses everything, permanently, and no server
//! can help because the server holds ciphertext this device can no longer open. Storing
//! plaintext locally is the only way a messenger can show you what was said yesterday.
//!
//! ## Written unencrypted, and said so
//!
//! **Decided (owner):** store it now, in the clear, at `0600`, beside the client state that
//! already sits there that way. This is not a claim that it is safe — it is strictly no
//! worse than today, because the group keys are already on disk in the same directory, and
//! anyone who can read them can read far more than a transcript. The platform keystores
//! (`docs/11-self-hosting.md`) supersede this when the native clients land, and the docs
//! must keep saying which of the two is in force.
//!
//! What this does mean: **a device that is taken is a conversation that is read.**
//! `docs/01-threat-model.md` §3.4 already declines to defend a compromised device, so this
//! widens the consequences of that concession rather than breaking a stated guarantee.
//!
//! ## Disappearing messages apply here too
//!
//! A room's timer would be a lie if the copy on this disk outlived it. [`History::replay`]
//! drops expired entries *and rewrites the file without them*, so a message past its timer
//! stops existing locally at the first opportunity rather than merely being hidden from the
//! screen — the same rule the server applies to its own copy.

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use cairn_proto::{RoomId, UserId};

#[derive(Debug, thiserror::Error)]
pub enum HistoryError {
    #[error("history i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("stored history is corrupt: {0}")]
    Corrupt(#[from] serde_json::Error),
}

/// One remembered message.
///
/// Not `PartialEq`: an entry can carry an attachment key, and a key type that offered
/// equality would invite comparing secrets with `==` rather than in constant time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    pub sender: UserId,
    /// The sender's clock, which is what a room's disappearing timer is measured against —
    /// the same value the server uses, so the two copies expire together.
    pub sent_at_ms: i64,
    pub body: Vec<u8>,
    /// The attachment's claimed filename, if the message carried one. A label, not a path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attachment_name: Option<String>,
    /// Everything needed to fetch and open the attachment again: blob id, key, claimed
    /// name, size and type.
    ///
    /// **The key is on disk here, and that is the decision, not an oversight.** Without it
    /// an image received yesterday is a grey box today: the key arrived once, inside a
    /// message MLS will not decrypt twice. It sits beside the plaintext transcript, at the
    /// same `0600`, and opens a file exactly as sensitive as that transcript — so it widens
    /// nothing the module note above has not already conceded. It also means a disappearing
    /// timer that drops this entry drops the only local key to the blob, which is what makes
    /// the timer true of attachments on this device even though the instance does not yet
    /// delete blobs at all.
    ///
    /// `default` so a transcript written before attachments existed still loads.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attachment: Option<crate::conversation::Attachment>,
    /// The message's franking commitment, in hex — what a reply or reaction names it by.
    /// Absent on entries written before replies existed; those can be read but not answered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// The message this one answered, unresolved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply_to: Option<crate::conversation::MessageRef>,
    /// Set when this entry is a reaction rather than a message.
    ///
    /// Stored as an entry of its own rather than folded into its target, so the transcript
    /// stays append-only and the timer deletes a reaction by its own clock, like any message.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reaction: Option<crate::conversation::Reaction>,
}

/// Per-room transcripts under a client's state directory.
#[derive(Debug)]
pub struct History {
    dir: PathBuf,
}

impl History {
    pub fn open(dir: impl AsRef<Path>) -> Result<Self, HistoryError> {
        let dir = dir.as_ref().join("history");
        fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    fn path(&self, room: RoomId) -> PathBuf {
        self.dir.join(format!("{}.jsonl", room.as_uuid()))
    }

    /// Append one message.
    ///
    /// Line-delimited JSON, appended rather than rewritten: a transcript grows with every
    /// message, and rewriting the file each time is the quadratic mistake ADR-007 was
    /// written to undo — repeating it on the client would be worse, since a phone has less
    /// to spare than a server.
    pub fn append(&self, room: RoomId, entry: &Entry) -> Result<(), HistoryError> {
        let path = self.path(room);
        let mut file = fs::OpenOptions::new().create(true).append(true).open(&path)?;
        restrict(&path)?;
        let mut line = serde_json::to_vec(entry)?;
        line.push(b'\n');
        file.write_all(&line)?;
        Ok(())
    }

    /// Everything remembered for a room, oldest first, minus anything past its timer.
    ///
    /// `ttl_ms` is the room's disappearing-message setting. Expired entries are removed from
    /// disk here, not merely skipped: a local copy outliving the timer would make the
    /// feature a lie on the one device its user actually controls.
    pub fn replay(
        &self,
        room: RoomId,
        ttl_ms: Option<i64>,
        now_ms: i64,
    ) -> Result<Vec<Entry>, HistoryError> {
        let path = self.path(room);
        let raw = match fs::read_to_string(&path) {
            Ok(raw) => raw,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };

        let all: Vec<Entry> = raw
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(serde_json::from_str)
            .collect::<Result<_, _>>()?;

        let Some(ttl) = ttl_ms else {
            return Ok(all);
        };

        let cutoff = now_ms.saturating_sub(ttl);
        let live: Vec<Entry> = all.iter().filter(|e| e.sent_at_ms > cutoff).cloned().collect();

        if live.len() != all.len() {
            let mut rewritten = Vec::new();
            for entry in &live {
                rewritten.extend_from_slice(&serde_json::to_vec(entry)?);
                rewritten.push(b'\n');
            }
            fs::write(&path, &rewritten)?;
            restrict(&path)?;
        }
        Ok(live)
    }

    /// Forget a room entirely — on leaving it, or being removed from it.
    pub fn forget(&self, room: RoomId) -> Result<(), HistoryError> {
        match fs::remove_file(self.path(room)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}

#[cfg(unix)]
fn restrict(path: &Path) -> Result<(), HistoryError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

/// No portable equivalent on Windows; the same gap the client's other state has.
#[cfg(not(unix))]
fn restrict(_path: &Path) -> Result<(), HistoryError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("cairn-history-{name}-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn entry(at: i64, body: &str) -> Entry {
        Entry {
            sender: UserId::new(),
            sent_at_ms: at,
            body: body.as_bytes().to_vec(),
            attachment_name: None,
            attachment: None,
            id: None,
            reply_to: None,
            reaction: None,
        }
    }

    #[test]
    fn a_conversation_survives_a_restart() {
        // The property this exists for. MLS discards each message key after use, so without
        // a local copy a restart loses the conversation permanently — the server cannot
        // help, because it holds ciphertext this device can no longer open.
        let dir = scratch("restart");
        let room = RoomId::new();
        {
            let history = History::open(&dir).unwrap();
            history.append(room, &entry(1, "first")).unwrap();
            history.append(room, &entry(2, "second")).unwrap();
        }

        let reopened = History::open(&dir).unwrap();
        let replayed = reopened.replay(room, None, 10_000).unwrap();
        assert_eq!(replayed.len(), 2);
        assert_eq!(replayed[0].body, b"first");
        assert_eq!(replayed[1].body, b"second", "order must be preserved");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn an_expired_message_is_removed_from_disk_not_just_hidden() {
        // A room's timer would be a lie if the copy on this disk outlived it. Checked by
        // re-reading the file with no timer at all, so a filter-on-read implementation
        // cannot pass.
        let dir = scratch("expiry");
        let room = RoomId::new();
        let history = History::open(&dir).unwrap();
        history.append(room, &entry(0, "old")).unwrap();
        history.append(room, &entry(5_000, "recent")).unwrap();

        let live = history.replay(room, Some(1_000), 5_500).unwrap();
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].body, b"recent");

        let everything = history.replay(room, None, 5_500).unwrap();
        assert_eq!(everything.len(), 1, "the expired entry must be gone from the file itself");
    }

    #[test]
    fn a_room_without_a_timer_keeps_everything() {
        // Counterfactual: without this, a purge that dropped entries unconditionally would
        // still pass the test above.
        let dir = scratch("nottl");
        let room = RoomId::new();
        let history = History::open(&dir).unwrap();
        history.append(room, &entry(0, "ancient")).unwrap();
        assert_eq!(history.replay(room, None, 10_000_000).unwrap().len(), 1);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rooms_do_not_leak_into_each_other() {
        let dir = scratch("rooms");
        let history = History::open(&dir).unwrap();
        let a = RoomId::new();
        let b = RoomId::new();
        history.append(a, &entry(1, "for a")).unwrap();
        history.append(b, &entry(1, "for b")).unwrap();

        assert_eq!(history.replay(a, None, 0).unwrap()[0].body, b"for a");
        assert_eq!(history.replay(b, None, 0).unwrap()[0].body, b"for b");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn an_unknown_room_replays_as_empty_rather_than_failing() {
        let dir = scratch("missing");
        let history = History::open(&dir).unwrap();
        assert!(history.replay(RoomId::new(), None, 0).unwrap().is_empty());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn forgetting_a_room_removes_its_transcript() {
        let dir = scratch("forget");
        let room = RoomId::new();
        let history = History::open(&dir).unwrap();
        history.append(room, &entry(1, "gone soon")).unwrap();
        history.forget(room).unwrap();
        assert!(history.replay(room, None, 0).unwrap().is_empty());
        // Forgetting twice is not an error; being removed from a room can race a leave.
        assert!(history.forget(room).is_ok());
        fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn a_transcript_is_not_world_readable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("perms");
        let room = RoomId::new();
        let history = History::open(&dir).unwrap();
        history.append(room, &entry(1, "private")).unwrap();
        let mode = fs::metadata(history.path(room)).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0, "a transcript must not be readable by other users");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_transcript_written_before_attachments_existed_still_loads() {
        // The `attachment` field is `serde(default)`. Without that, every transcript on
        // every existing install would read as corrupt the day it shipped.
        let dir = scratch("pre-attachments");
        let room = RoomId::new();
        let history = History::open(&dir).unwrap();
        let old =
            serde_json::json!({ "sender": UserId::new(), "sent_at_ms": 1, "body": [104, 105] });
        fs::write(history.path(room), format!("{old}\n")).unwrap();
        let replayed = history.replay(room, None, 0).unwrap();
        assert_eq!(replayed[0].body, b"hi");
        assert!(replayed[0].attachment.is_none());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn corrupt_history_is_an_error_rather_than_a_silent_empty_room() {
        // Returning nothing would look exactly like a conversation that never happened.
        let dir = scratch("corrupt");
        let room = RoomId::new();
        let history = History::open(&dir).unwrap();
        history.append(room, &entry(1, "real")).unwrap();
        fs::write(history.path(room), "{not json\n").unwrap();
        assert!(matches!(history.replay(room, None, 0), Err(HistoryError::Corrupt(_))));
        fs::remove_dir_all(&dir).ok();
    }
}
