//! Taking a backup, and proving it is one.
//!
//! ## What the documented procedure actually did
//!
//! `docs/11-self-hosting.md` used to say: stop the instance, `cp` two files, start it again.
//! The instruction is correct, and it rests entirely on the operator remembering the first
//! step. Probing what happens when they do not:
//!
//! - On a **busy** instance, the copy cannot be opened at all: `Failed to repair database.
//!   All roots are corrupted`.
//! - On an **idle** instance — a Raspberry Pi with five friends on it, which is the
//!   deployment `11-self-hosting.md` §7 describes — the copy opens cleanly, holds every row,
//!   and looks like a perfectly good backup.
//!
//! So the failure mode is not "cp is unreliable". It is that **`cp` succeeds under exactly
//! the conditions in which an operator tests their backup procedure, and fails under exactly
//! the conditions in which they need it** — and the failure surfaces at restore time, which
//! is the worst possible moment to discover it.
//!
//! [`run`] therefore opens the database rather than copying the file. redb holds a
//! cross-process lock, so against a live instance this **refuses** with a message naming the
//! problem, instead of producing the quietly-broken copy. Turning a silent bad backup into a
//! loud refusal is the point of the command.
//!
//! ## The pair
//!
//! `franking.key` and `cairn.redb` must be restored together. That was previously the
//! operator's responsibility, backed by a check that caught only an *absent* key — probing
//! found that a **mismatched** one started cleanly while every report filed before the
//! restore silently stopped verifying (`StorageError::FrankingKeyMismatch`).
//!
//! A backup therefore carries both files plus a manifest binding them, and [`verify`]
//! re-opens what was just written and checks it. A backup nobody has ever opened is a
//! hypothesis, not a backup.
//!
//! Note which layer catches what: the *pair* is checked by the storage layer when the key is
//! loaded, so a wrong `franking.key` fails before this module compares anything. The
//! manifest comparison here catches a manifest that has drifted from its own directory —
//! useful, but accident and corruption rather than an adversary. See
//! [`BackupError::ManifestDisagrees`].

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::storage::{DbStorage, SnapshotCounts, Storage, StorageError};

/// Written beside the two files, describing what they are.
///
/// Deliberately plain JSON: an operator staring at a directory six months from now should be
/// able to read it without this binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    /// Bumped if the backup layout changes, so a future build can refuse rather than guess.
    pub backup_format: u32,
    pub taken_at_ms: i64,
    /// Hex hash of the franking key, matching what the database records internally.
    ///
    /// Not the thing that catches a separated pair — the storage layer does that when it
    /// loads the key. This lets an operator confirm by eye that two directories belong to
    /// the same instance without running anything.
    pub franking_fingerprint: String,
    pub counts: SnapshotCounts,
}

/// What this build writes.
const BACKUP_FORMAT: u32 = 1;

pub const DB_FILE: &str = "cairn.redb";
pub const KEY_FILE: &str = "franking.key";
pub const MANIFEST_FILE: &str = "backup.json";

#[derive(Debug, thiserror::Error)]
pub enum BackupError {
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error("backup i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("backup manifest is unreadable: {0}")]
    Manifest(#[from] serde_json::Error),
    #[error(
        "the instance appears to be running — its database is locked. Stop it and run this \
         again. (Copying a live database produces a file that opens fine on an idle instance \
         and cannot be opened at all on a busy one, which is why this refuses rather than \
         trying.)"
    )]
    InstanceRunning,
    #[error("{0} already exists and is not empty; refusing to write a backup over it")]
    DestinationNotEmpty(PathBuf),
    #[error("{0} does not look like a Cairn backup: no {MANIFEST_FILE}")]
    NotABackup(PathBuf),
    #[error(
        "backup format {found} is newer than this build understands ({known}); \
         restore it with the version that wrote it"
    )]
    FormatTooNew { found: u32, known: u32 },
    /// The manifest disagrees with the files beside it.
    ///
    /// Narrower than it first looks, and worth stating precisely: a genuinely separated pair
    /// — the wrong `franking.key` next to a database — is caught one layer down, by
    /// `StorageError::FrankingKeyMismatch`, before this comparison is reached. What is left
    /// for this to catch is a manifest that no longer describes its own directory: edited,
    /// truncated, or copied in from a different backup.
    ///
    /// It is an integrity check, **not** a security control. Anyone who can rewrite the
    /// manifest can rewrite the database too, so this detects accident and corruption rather
    /// than an adversary.
    #[error(
        "this backup's manifest does not describe the files beside it — the manifest \
         records a different franking key than the backup actually carries"
    )]
    ManifestDisagrees,
    #[error("refusing to restore over {0}, which already holds instance data")]
    RestoreOverData(PathBuf),
}

/// Take a backup of `data_dir` into `dest`.
///
/// Verifies what it wrote before returning, so a success here means the backup has been
/// opened at least once.
pub fn run(data_dir: &Path, dest: &Path, now_ms: i64) -> Result<Manifest, BackupError> {
    if dest.exists() && fs::read_dir(dest)?.next().is_some() {
        return Err(BackupError::DestinationNotEmpty(dest.to_path_buf()));
    }
    fs::create_dir_all(dest)?;

    let storage = open_exclusive(data_dir)?;
    // Loading the key is what checks the pair — a data directory whose key does not match
    // its database must not be turned into a backup that carries the mismatch forward.
    let key = storage.load_or_create_franking_key()?;
    let counts = storage.snapshot_into(&dest.join(DB_FILE))?;

    fs::copy(data_dir.join(KEY_FILE), dest.join(KEY_FILE))?;
    restrict(&dest.join(KEY_FILE))?;

    let fingerprint = storage
        .franking_fingerprint()?
        .map(hex::encode)
        .unwrap_or_else(|| hex::encode(DbStorage::fingerprint_of(&key)));
    let manifest = Manifest {
        backup_format: BACKUP_FORMAT,
        taken_at_ms: now_ms,
        franking_fingerprint: fingerprint,
        counts,
    };
    fs::write(dest.join(MANIFEST_FILE), serde_json::to_vec_pretty(&manifest)?)?;

    // Release the source before verifying, so the check below is not competing with our own
    // lock, and so a failure here is about the backup rather than about us.
    drop(storage);
    verify(dest)?;
    Ok(manifest)
}

/// Open a backup and confirm it is restorable.
///
/// This is the half an operator can run on a schedule. It answers the only question that
/// matters — *would this restore?* — by doing the parts of a restore that have no effect.
pub fn verify(dir: &Path) -> Result<Manifest, BackupError> {
    let manifest_path = dir.join(MANIFEST_FILE);
    if !manifest_path.exists() {
        return Err(BackupError::NotABackup(dir.to_path_buf()));
    }
    let manifest: Manifest = serde_json::from_slice(&fs::read(&manifest_path)?)?;
    if manifest.backup_format > BACKUP_FORMAT {
        return Err(BackupError::FormatTooNew {
            found: manifest.backup_format,
            known: BACKUP_FORMAT,
        });
    }

    // Opening the database is the substantive check: it parses the schema version, and
    // loading the key compares the pair. A corrupt copy fails here rather than at 3am.
    let storage = open_exclusive(dir)?;
    let key = storage.load_or_create_franking_key()?;
    let actual = hex::encode(DbStorage::fingerprint_of(&key));
    if actual != manifest.franking_fingerprint {
        return Err(BackupError::ManifestDisagrees);
    }
    // And the directory itself must load, not merely open — a database that opens but whose
    // records cannot be parsed is not a backup of anything.
    storage.load_directory()?;
    Ok(manifest)
}

/// Restore a verified backup into `dest`.
///
/// Refuses to write over a directory that already holds instance data. An operator reaching
/// for restore is usually having a bad day, and "restored over the good copy" is the way
/// that day gets worse.
pub fn restore(src: &Path, dest: &Path) -> Result<Manifest, BackupError> {
    let manifest = verify(src)?;

    if dest.exists() {
        let occupied = [DB_FILE, KEY_FILE].iter().any(|f| dest.join(f).exists());
        if occupied {
            return Err(BackupError::RestoreOverData(dest.to_path_buf()));
        }
    }
    fs::create_dir_all(dest)?;
    fs::copy(src.join(DB_FILE), dest.join(DB_FILE))?;
    fs::copy(src.join(KEY_FILE), dest.join(KEY_FILE))?;
    restrict(&dest.join(KEY_FILE))?;

    // Prove the restored directory opens, for the same reason `run` verifies: reporting
    // success for something never opened is how a backup procedure develops a hole.
    let storage = open_exclusive(dest)?;
    storage.load_or_create_franking_key()?;
    storage.load_directory()?;
    Ok(manifest)
}

/// Open a data directory, translating redb's lock into an operator-legible refusal.
fn open_exclusive(dir: &Path) -> Result<DbStorage, BackupError> {
    match DbStorage::new(dir) {
        Ok(s) => Ok(s),
        Err(e) if is_lock_error(&e) => Err(BackupError::InstanceRunning),
        Err(e) => Err(e.into()),
    }
}

/// redb reports the lock as a plain `DatabaseAlreadyOpen` I/O-ish error with no distinct
/// variant reachable from here, so this matches on the message. Fragile by nature, which is
/// why the fallback is the underlying error rather than a wrong diagnosis.
fn is_lock_error(e: &StorageError) -> bool {
    e.to_string().contains("Database already open")
}

#[cfg(unix)]
fn restrict(path: &Path) -> Result<(), BackupError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

/// No portable equivalent; the same gap the data directory's own key file has on Windows.
#[cfg(not(unix))]
fn restrict(_path: &Path) -> Result<(), BackupError> {
    Ok(())
}
