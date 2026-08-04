//! Durable instance state.
//!
//! ## Why this exists
//!
//! Before this, the franking key was regenerated on every restart. That is not an
//! inconvenience — it silently invalidates **every franking tag the instance ever
//! issued**, so a report a user filed yesterday cannot be verified today. A moderation
//! mechanism that forgets its own evidence on restart does not work.
//!
//! ## Deliberately boring
//!
//! A JSON snapshot written atomically, with no new dependencies. That is enough for a
//! scaffold, and it keeps the supply chain of a security product small. The [`Storage`]
//! trait is the seam: a real embedded database slots in behind it without touching
//! [`crate::state::Instance`].
//!
//! Its limits are real and should be fixed before this holds anyone's data: the whole
//! state is rewritten on every save, which is O(messages) per message, and there is no
//! write-ahead log, so a crash mid-save loses everything since the last successful write
//! (though never a *partial* file — see `write_atomic`).

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use cairn_crypto::franking::ServerFrankingKey;

use crate::state::PersistedState;

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("storage i/o error: {0}")]
    Io(#[from] io::Error),
    #[error("stored state is corrupt or from an incompatible version: {0}")]
    Corrupt(#[from] serde_json::Error),
    #[error("stored franking key is malformed: expected 32 bytes")]
    BadKey,
}

/// Where an instance keeps what must survive a restart.
pub trait Storage: Send + Sync + std::fmt::Debug {
    /// Load the franking key, generating and persisting one on first run.
    ///
    /// Generating a *new* key when one should exist would silently invalidate history, so
    /// implementations must distinguish "no key yet" from "could not read the key" and
    /// fail loudly on the latter.
    fn load_or_create_franking_key(&self) -> Result<ServerFrankingKey, StorageError>;

    fn load_state(&self) -> Result<PersistedState, StorageError>;

    fn save_state(&self, state: &PersistedState) -> Result<(), StorageError>;
}

/// A JSON-file-backed store.
#[derive(Debug)]
pub struct FileStorage {
    dir: PathBuf,
}

#[derive(Serialize, Deserialize)]
struct KeyFile {
    /// Hex, so the file is inspectable by an operator who needs to back it up.
    franking_key: String,
}

impl FileStorage {
    pub fn new(dir: impl Into<PathBuf>) -> Result<Self, StorageError> {
        let dir = dir.into();
        fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    fn key_path(&self) -> PathBuf {
        self.dir.join("franking.key")
    }

    fn state_path(&self) -> PathBuf {
        self.dir.join("state.json")
    }

    /// Write via a temporary file and rename.
    ///
    /// `rename` is atomic within a filesystem, so a crash mid-write leaves either the old
    /// file or the new one — never a half-written file that fails to parse on restart and
    /// takes the instance's history with it.
    fn write_atomic(path: &Path, bytes: &[u8], secret: bool) -> Result<(), StorageError> {
        let tmp = path.with_extension("tmp");
        fs::write(&tmp, bytes)?;
        if secret {
            restrict_permissions(&tmp)?;
        }
        fs::rename(&tmp, path)?;
        Ok(())
    }
}

/// Restrict a secret file to its owner.
#[cfg(unix)]
fn restrict_permissions(path: &Path) -> Result<(), StorageError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

/// No portable equivalent on Windows.
///
/// The default ACL on a user-profile directory is usually adequate, but this is weaker
/// than the Unix path and an operator should know it. Tracked as a gap rather than
/// silently ignored.
#[cfg(not(unix))]
fn restrict_permissions(_path: &Path) -> Result<(), StorageError> {
    Ok(())
}

impl Storage for FileStorage {
    fn load_or_create_franking_key(&self) -> Result<ServerFrankingKey, StorageError> {
        let path = self.key_path();
        match fs::read_to_string(&path) {
            Ok(contents) => {
                let parsed: KeyFile = serde_json::from_str(&contents)?;
                let bytes = hex::decode(&parsed.franking_key).map_err(|_| StorageError::BadKey)?;
                let bytes: [u8; 32] = bytes.try_into().map_err(|_| StorageError::BadKey)?;
                Ok(ServerFrankingKey::from_bytes(bytes))
            }
            // Only a genuinely absent file justifies minting a new key. Any other error —
            // permissions, a corrupt file, a full disk — must surface, because silently
            // generating a replacement would discard the ability to verify past reports.
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let key = ServerFrankingKey::generate();
                let file = KeyFile { franking_key: hex::encode(key.to_bytes()) };
                Self::write_atomic(&path, serde_json::to_string(&file)?.as_bytes(), true)?;
                Ok(key)
            }
            Err(e) => Err(e.into()),
        }
    }

    fn load_state(&self) -> Result<PersistedState, StorageError> {
        match fs::read_to_string(self.state_path()) {
            Ok(contents) => Ok(serde_json::from_str(&contents)?),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(PersistedState::default()),
            Err(e) => Err(e.into()),
        }
    }

    fn save_state(&self, state: &PersistedState) -> Result<(), StorageError> {
        let bytes = serde_json::to_vec(state)?;
        Self::write_atomic(&self.state_path(), &bytes, false)
    }
}

/// Non-persistent storage, for tests and ephemeral instances.
#[derive(Debug, Default)]
pub struct MemoryStorage;

impl Storage for MemoryStorage {
    fn load_or_create_franking_key(&self) -> Result<ServerFrankingKey, StorageError> {
        Ok(ServerFrankingKey::generate())
    }

    fn load_state(&self) -> Result<PersistedState, StorageError> {
        Ok(PersistedState::default())
    }

    fn save_state(&self, _state: &PersistedState) -> Result<(), StorageError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("cairn-test-{}-{}", name, uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn franking_key_survives_a_restart() {
        // The property this module exists for. A different key after restart means every
        // previously issued franking tag stops verifying.
        let dir = temp_dir("key");
        let first = FileStorage::new(&dir).unwrap().load_or_create_franking_key().unwrap();
        let second = FileStorage::new(&dir).unwrap().load_or_create_franking_key().unwrap();
        assert_eq!(first.to_bytes(), second.to_bytes());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_corrupt_key_file_is_an_error_not_a_silent_new_key() {
        // Silently minting a replacement would discard the ability to verify history,
        // and would do it without telling the operator.
        let dir = temp_dir("corrupt");
        let storage = FileStorage::new(&dir).unwrap();
        storage.load_or_create_franking_key().unwrap();
        fs::write(dir.join("franking.key"), "not json at all").unwrap();

        assert!(matches!(
            storage.load_or_create_franking_key(),
            Err(StorageError::Corrupt(_)) | Err(StorageError::BadKey)
        ));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_wrong_length_key_is_rejected() {
        let dir = temp_dir("shortkey");
        let storage = FileStorage::new(&dir).unwrap();
        fs::write(dir.join("franking.key"), r#"{"franking_key":"abcd"}"#).unwrap();
        assert!(matches!(storage.load_or_create_franking_key(), Err(StorageError::BadKey)));
        fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn the_key_file_is_not_world_readable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("perms");
        FileStorage::new(&dir).unwrap().load_or_create_franking_key().unwrap();
        let mode = fs::metadata(dir.join("franking.key")).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0, "the franking key must not be readable by other users");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn missing_state_loads_as_empty_rather_than_failing() {
        let dir = temp_dir("empty");
        let state = FileStorage::new(&dir).unwrap().load_state().unwrap();
        assert!(state.rooms.is_empty());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn corrupt_state_surfaces_rather_than_starting_blank() {
        // Starting blank would look like data loss to the operator and would silently
        // discard the message log.
        let dir = temp_dir("badstate");
        let storage = FileStorage::new(&dir).unwrap();
        fs::write(dir.join("state.json"), "{{{").unwrap();
        assert!(matches!(storage.load_state(), Err(StorageError::Corrupt(_))));
        fs::remove_dir_all(&dir).ok();
    }
}
