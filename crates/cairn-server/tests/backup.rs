//! Backup and restore, against real directories on a real filesystem.
//!
//! The properties here are all ones an operator only finds out about at restore time, which
//! is why they are tested rather than documented: a backup nobody has opened is a hypothesis.

use std::fs;
use std::path::PathBuf;

use cairn_proto::{DeviceId, Envelope, EnvelopePayload, RoomId, Tier, UserId};
use cairn_server::backup::{self, BackupError, DB_FILE, KEY_FILE, MANIFEST_FILE};
use cairn_server::state::{AccountRecord, DeviceRecord, StoredMessage};
use cairn_server::storage::{DbStorage, Storage, StorageError, Write};

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("cairn-backup-{name}-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn message(room: RoomId, seq: u64) -> StoredMessage {
    StoredMessage {
        envelope: Envelope::new(
            Tier::Private,
            room,
            UserId::new(),
            DeviceId::new(),
            0,
            EnvelopePayload::MlsApplication { ciphertext: vec![seq as u8; 32] },
        )
        .unwrap(),
        server_seq: seq,
        franking_tag: None,
    }
}

/// A data directory with something worth losing in it.
///
/// No room: `Room` has no constructor reachable from an integration test, and rooms are
/// covered where the coverage actually matters — `every_table_is_included_in_a_backup`
/// asserts that *whatever* tables a full instance writes are all copied, which is the
/// property a hand-written fixture here would only approximate.
fn populated(dir: &PathBuf) -> (RoomId, UserId) {
    let storage = DbStorage::new(dir).unwrap();
    storage.load_or_create_franking_key().unwrap();
    let room = RoomId::new();
    let user = UserId::new();
    let device = DeviceId::new();
    storage
        .commit(&[
            Write::Account(user, AccountRecord { devices: vec![device] }),
            Write::Device(device, DeviceRecord { user, public_key: "ab".into() }),
        ])
        .unwrap();
    for seq in 1..=25 {
        storage.commit(&[Write::Message(room, message(room, seq))]).unwrap();
    }
    (room, user)
}

#[test]
fn a_restored_instance_holds_what_the_original_held() {
    let src = scratch("src");
    let (room, user) = populated(&src);

    let backup_dir = scratch("out").join("backup");
    backup::run(&src, &backup_dir, 1_700_000_000_000).unwrap();

    let dest = scratch("dest").join("data");
    let manifest = backup::restore(&backup_dir, &dest).unwrap();
    assert_eq!(manifest.counts.messages, 25);

    let restored = DbStorage::new(&dest).unwrap();
    let dir = restored.load_directory().unwrap();
    assert_eq!(dir.accounts.len(), 1);
    assert_eq!(dir.accounts[0].0, user, "an account id must survive the round trip unchanged");
    assert_eq!(dir.devices.len(), 1);

    let messages = restored.messages_since(room, 0).unwrap();
    assert_eq!(messages.len(), 25, "every message must come back");
    for (i, m) in messages.iter().enumerate() {
        assert_eq!(m.server_seq, i as u64 + 1, "and in order, with no holes");
    }
}

#[test]
fn a_restore_keeps_the_franking_key_so_old_reports_still_verify() {
    // The property the whole backup story exists for. A restore that brings back the
    // messages but not the key produces an instance that looks healthy while every report
    // filed before it silently stops verifying.
    let src = scratch("keysrc");
    populated(&src);
    let original = DbStorage::new(&src).unwrap().load_or_create_franking_key().unwrap();

    let backup_dir = scratch("keyout").join("backup");
    backup::run(&src, &backup_dir, 0).unwrap();
    let dest = scratch("keydest").join("data");
    backup::restore(&backup_dir, &dest).unwrap();

    let restored = DbStorage::new(&dest).unwrap().load_or_create_franking_key().unwrap();
    assert_eq!(
        original.to_bytes(),
        restored.to_bytes(),
        "the restored instance must hold the same franking key"
    );
}

#[test]
fn a_backup_of_a_live_instance_is_refused_rather_than_quietly_broken() {
    // Probing the documented `cp` found the trap this replaces: copying a live database
    // yields a file that opens cleanly on an idle instance and is unopenable on a busy one —
    // so the procedure works when an operator tests it and fails when they need it. Holding
    // the database open here stands in for the running server; a separate process was
    // confirmed to hit the same lock.
    let src = scratch("live");
    populated(&src);
    let _held = DbStorage::new(&src).unwrap();

    let dest = scratch("liveout").join("backup");
    assert!(
        matches!(backup::run(&src, &dest, 0), Err(BackupError::InstanceRunning)),
        "a backup taken while the instance is up must refuse, not produce a copy"
    );
}

#[test]
fn a_backup_whose_pair_was_separated_does_not_verify() {
    // A backup can be broken after it is taken — someone copies the database somewhere and
    // brings the wrong key along. `verify` is where that must surface, not the restore.
    let src = scratch("pairsrc");
    populated(&src);
    let backup_dir = scratch("pairout").join("backup");
    backup::run(&src, &backup_dir, 0).unwrap();

    // Another instance's key, which is what a mixed-up restore actually looks like.
    let other = scratch("othersrc");
    populated(&other);
    fs::copy(other.join(KEY_FILE), backup_dir.join(KEY_FILE)).unwrap();

    // Caught by the storage layer, when the key is loaded against the database's recorded
    // fingerprint — not by the manifest comparison, which never sees it. Asserted precisely
    // rather than as "some error", so that if the check ever moves, this says so.
    let err = backup::verify(&backup_dir).unwrap_err();
    assert!(
        matches!(err, BackupError::Storage(StorageError::FrankingKeyMismatch)),
        "a separated pair must be caught as a mismatch, got {err:?}"
    );

    let dest = scratch("pairdest").join("data");
    assert!(backup::restore(&backup_dir, &dest).is_err(), "and must not restore");
}

#[test]
fn a_manifest_that_no_longer_describes_its_directory_is_caught() {
    // The narrow thing `ManifestDisagrees` actually catches — a manifest edited or copied in
    // from elsewhere, with the pair itself intact. Without this test the variant would be
    // unreachable in practice and its message would be describing a case it never sees.
    let src = scratch("manifestsrc");
    populated(&src);
    let backup_dir = scratch("manifestout").join("backup");
    backup::run(&src, &backup_dir, 0).unwrap();

    let mut manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(backup_dir.join(MANIFEST_FILE)).unwrap()).unwrap();
    manifest["franking_fingerprint"] = serde_json::json!("00".repeat(32));
    fs::write(backup_dir.join(MANIFEST_FILE), serde_json::to_vec(&manifest).unwrap()).unwrap();

    assert!(matches!(backup::verify(&backup_dir), Err(BackupError::ManifestDisagrees)));
}

#[test]
fn a_good_backup_verifies() {
    // Counterfactual for the test above: a verifier that refused everything would pass it
    // and be worthless.
    let src = scratch("goodsrc");
    populated(&src);
    let backup_dir = scratch("goodout").join("backup");
    backup::run(&src, &backup_dir, 42).unwrap();

    let manifest = backup::verify(&backup_dir).unwrap();
    assert_eq!(manifest.taken_at_ms, 42);
    assert_eq!(manifest.counts.messages, 25);
}

#[test]
fn a_restore_will_not_write_over_an_instance_that_already_has_data() {
    // An operator reaching for restore is having a bad day; "restored over the good copy" is
    // how that day gets worse.
    let src = scratch("oversrc");
    populated(&src);
    let backup_dir = scratch("overout").join("backup");
    backup::run(&src, &backup_dir, 0).unwrap();

    let occupied = scratch("occupied");
    populated(&occupied);

    assert!(
        matches!(backup::restore(&backup_dir, &occupied), Err(BackupError::RestoreOverData(_))),
        "restoring over a populated data directory must be refused"
    );
}

#[test]
fn a_backup_will_not_write_into_a_directory_that_already_holds_something() {
    let src = scratch("destsrc");
    populated(&src);
    let dest = scratch("destfull");
    fs::write(dest.join("something-else"), b"important").unwrap();

    assert!(matches!(backup::run(&src, &dest, 0), Err(BackupError::DestinationNotEmpty(_))));
    assert!(dest.join("something-else").exists(), "and must leave what was there alone");
}

#[test]
fn a_directory_that_is_not_a_backup_is_named_as_such() {
    let dir = scratch("notabackup");
    assert!(matches!(backup::verify(&dir), Err(BackupError::NotABackup(_))));
}

#[test]
fn a_backup_from_a_newer_build_is_refused_rather_than_guessed_at() {
    let src = scratch("fmtsrc");
    populated(&src);
    let backup_dir = scratch("fmtout").join("backup");
    backup::run(&src, &backup_dir, 0).unwrap();

    let mut manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(backup_dir.join(MANIFEST_FILE)).unwrap()).unwrap();
    manifest["backup_format"] = serde_json::json!(99);
    fs::write(backup_dir.join(MANIFEST_FILE), serde_json::to_vec(&manifest).unwrap()).unwrap();

    assert!(matches!(
        backup::verify(&backup_dir),
        Err(BackupError::FormatTooNew { found: 99, .. })
    ));
}

#[test]
fn a_backup_carries_both_files_and_a_manifest() {
    // The pair is the artifact. A backup directory holding only the database is the failure
    // mode `11-self-hosting.md` warns about, pre-made.
    let src = scratch("filessrc");
    populated(&src);
    let backup_dir = scratch("filesout").join("backup");
    backup::run(&src, &backup_dir, 0).unwrap();

    for f in [DB_FILE, KEY_FILE, MANIFEST_FILE] {
        assert!(backup_dir.join(f).exists(), "a backup must contain {f}");
    }
}

#[cfg(unix)]
#[test]
fn the_backed_up_franking_key_is_not_world_readable() {
    // It is the same secret as the original, so it deserves the same permissions — a backup
    // dropped in a shared directory should not be how it leaks.
    use std::os::unix::fs::PermissionsExt;
    let src = scratch("permsrc");
    populated(&src);
    let backup_dir = scratch("permout").join("backup");
    backup::run(&src, &backup_dir, 0).unwrap();

    let mode = fs::metadata(backup_dir.join(KEY_FILE)).unwrap().permissions().mode();
    assert_eq!(mode & 0o077, 0, "a backed-up franking key must not be readable by other users");
}

#[test]
fn a_snapshot_is_a_point_in_time_not_a_moving_target() {
    // Writes that land after the backup starts belong to the next backup. What must never
    // happen is a *partial* record of one — the reason this copies inside a read
    // transaction rather than iterating tables one at a time.
    let src = scratch("pit");
    let (room, _) = populated(&src);
    let backup_dir = scratch("pitout").join("backup");
    backup::run(&src, &backup_dir, 0).unwrap();

    // The original keeps going after the backup was taken.
    let storage = DbStorage::new(&src).unwrap();
    for seq in 26..=40 {
        storage.commit(&[Write::Message(room, message(room, seq))]).unwrap();
    }
    drop(storage);

    let restored = DbStorage::new(&backup_dir).unwrap();
    assert_eq!(
        restored.messages_since(room, 0).unwrap().len(),
        25,
        "the backup holds the instant it was taken, not whatever happened later"
    );
}
