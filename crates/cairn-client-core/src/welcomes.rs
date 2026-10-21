//! Welcomes this device owes to people it is adding to a room, kept on disk.
//!
//! A commit that adds someone is staged, uploaded, and only applied once the instance has
//! it (see `cairn_crypto::mls::GroupHandle::stage_add`). Its welcome is held until then, and
//! sent once nothing is pending. Both the staged commit and the welcome must survive a
//! restart: `mls-rs` already saves the commit with the group, and this saves the welcome.
//! Before it did, a client that restarted between the upload and the send found its own
//! commit in the log, followed it — and had nothing to send the newcomer, who was then in
//! the group, no longer listed as waiting, and never able to read it.
//!
//! A welcome is sealed to the newcomer's key package and crosses the instance anyway, so
//! keeping it on disk exposes nothing the instance does not see.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use cairn_proto::RoomId;
use serde::{Deserialize, Serialize};

/// One room's owed welcomes. Every change is written before the call returns.
#[derive(Debug)]
pub struct Welcomes {
    path: PathBuf,
    state: State,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct State {
    /// The welcome for this device's pending commit, hex. Sent only if the commit lands.
    held: Option<String>,
    /// Welcomes whose commits landed, oldest first, hex.
    unsent: Vec<String>,
}

impl Welcomes {
    /// The welcomes owed in `room`, as the last run left them. Unreadable means none: the
    /// failure that leaves is one newcomer to admit again, not a corrupt room.
    pub fn open(dir: &Path, room: RoomId) -> Self {
        let path = dir.join("welcomes").join(format!("{}.json", room.as_uuid()));
        let state = fs::read(&path)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default();
        Self { path, state }
    }

    /// Hold `welcome` for the commit about to be uploaded. Must be on disk before the
    /// upload starts, or a crash during it loses the only copy.
    pub fn hold(&mut self, welcome: Option<Vec<u8>>) -> io::Result<()> {
        self.state.held = welcome.map(hex::encode);
        self.save()
    }

    /// The pending commit landed: its welcome is now owed.
    pub fn landed(&mut self) -> io::Result<()> {
        if let Some(held) = self.state.held.take() {
            self.state.unsent.push(held);
        }
        self.save()
    }

    /// The pending commit did not land, so whoever it added was not added.
    pub fn drop_held(&mut self) -> io::Result<()> {
        if self.state.held.take().is_some() {
            self.save()?;
        }
        Ok(())
    }

    /// The oldest welcome owed, if any.
    pub fn next_unsent(&self) -> Option<Vec<u8>> {
        self.state.unsent.first().and_then(|h| hex::decode(h).ok())
    }

    /// The oldest welcome owed has been sent.
    ///
    /// Written after the send, so a crash in between sends it twice. A duplicate is
    /// harmless — a device already in the group ignores welcomes — where a lost one is not.
    pub fn sent(&mut self) -> io::Result<()> {
        if !self.state.unsent.is_empty() {
            self.state.unsent.remove(0);
            self.save()?;
        }
        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        self.state.held.is_none() && self.state.unsent.is_empty()
    }

    /// Temp file plus rename, so a crash leaves the old state rather than a truncated one.
    /// Nothing owed leaves no file.
    fn save(&self) -> io::Result<()> {
        if self.is_empty() {
            return match fs::remove_file(&self.path) {
                Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
                _ => Ok(()),
            };
        }
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let tmp = self.path.with_extension("tmp");
        fs::write(&tmp, serde_json::to_vec(&self.state)?)?;
        fs::rename(&tmp, &self.path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("cairn-welcomes-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_held_welcome_survives_a_restart_and_is_owed_once_its_commit_lands() {
        let dir = dir();
        let room = RoomId::new();
        Welcomes::open(&dir, room).hold(Some(b"welcome".to_vec())).unwrap();

        let mut after = Welcomes::open(&dir, room);
        assert_eq!(after.next_unsent(), None, "held, not owed, until the commit lands");
        after.landed().unwrap();
        assert_eq!(Welcomes::open(&dir, room).next_unsent().as_deref(), Some(&b"welcome"[..]));

        let mut owed = Welcomes::open(&dir, room);
        owed.sent().unwrap();
        assert!(Welcomes::open(&dir, room).is_empty());
        assert!(!dir.join("welcomes").join(format!("{}.json", room.as_uuid())).exists());
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn a_commit_that_never_landed_owes_nobody_a_welcome() {
        let dir = dir();
        let room = RoomId::new();
        let mut w = Welcomes::open(&dir, room);
        w.hold(Some(b"welcome".to_vec())).unwrap();
        w.drop_held().unwrap();
        let mut after = Welcomes::open(&dir, room);
        after.landed().unwrap();
        assert_eq!(after.next_unsent(), None);
        fs::remove_dir_all(dir).ok();
    }
}
