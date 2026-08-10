//! Where a client keeps its identity.
//!
//! ## Why this is not a UI decision
//!
//! This directory holds the device key, MLS group state, the contact store, and the
//! plaintext message history. Per ADR-006 a platform UI must never decide where a key
//! lives, so the choice is made once, here, below the FFI line — five native clients each
//! picking their own location would be five different answers to "is my account safe on
//! disk", and at least one of them would be wrong.
//!
//! ## The bug this replaces
//!
//! `cairn-cli` defaulted to `std::env::temp_dir()/cairn/<name>`. Probing what that means on
//! a real machine rather than in a test:
//!
//! - On most Linux systems `/tmp` is **cleared on reboot** — frequently it is `tmpfs`, so it
//!   is RAM and never touches a disk at all — and `systemd-tmpfiles-clean` prunes what
//!   survives on a timer, ten days by default.
//! - So a reboot destroys the device key, the MLS group state, the contacts, and the whole
//!   message history. The account is gone and every conversation with it.
//!
//! That undermined the feature it sat under. "History survives a restart" was verified by
//! restarting *processes*; it was never true across a restart of the *machine*, which is the
//! one users actually do. A test that used a temp directory deliberately could never have
//! caught it, because the temp directory was the bug.
//!
//! `/tmp` is also world-writable, so the parent was listable: `ls /tmp/cairn` enumerated
//! every account name on the machine. The per-account directory itself was `0700`, so its
//! *contents* were never exposed — that part worked.

use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum StateDirError {
    #[error("could not create the client state directory {path}: {source}")]
    Create {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error(
        "no home directory found — set CAIRN_HOME to a directory that survives a reboot. \
         Refusing to fall back to a temporary directory, which is cleared on restart and \
         would take this account's keys and history with it"
    )]
    NoHome,
}

/// The directory a client with this profile name should use.
///
/// Resolution order, first match wins:
///
/// 1. `CAIRN_HOME` — an explicit override, for testing and for operators who keep state on
///    a specific volume.
/// 2. `XDG_DATA_HOME` on Unix, honouring the spec rather than assuming `~/.local/share`.
/// 3. The platform default: `~/.local/share` on Linux, `~/Library/Application Support` on
///    macOS, `%APPDATA%` on Windows.
///
/// There is deliberately **no temp-directory fallback**. A messenger that quietly stores an
/// identity somewhere the OS deletes is worse than one that refuses to start, because the
/// failure arrives later and looks like data loss rather than a configuration error.
pub fn default_state_dir(profile: &str) -> Result<PathBuf, StateDirError> {
    resolve(profile, &|key| std::env::var(key).ok())
}

/// The resolution itself, with the environment passed in.
///
/// Split out so it is testable: `std::env::set_var` is `unsafe` under edition 2024 — it can
/// race another thread's read — and every crate here forbids `unsafe`. Threading the lookup
/// through as a parameter tests the actual branch logic on every platform rather than only
/// the one the test happens to run on.
fn resolve(profile: &str, env: &dyn Fn(&str) -> Option<String>) -> Result<PathBuf, StateDirError> {
    let get = |key: &str| match env(key) {
        Some(v) if !v.trim().is_empty() => Some(PathBuf::from(v)),
        _ => None,
    };
    let base = if let Some(explicit) = get("CAIRN_HOME") {
        explicit
    } else {
        platform_data_dir(&get)?.join("cairn")
    };
    Ok(base.join(profile))
}

type Getter<'a> = dyn Fn(&str) -> Option<PathBuf> + 'a;

/// Create the directory and everything above it, restricted to this user.
///
/// The per-account directory was already `0700`; the **parent** was not, so `ls` on it
/// listed every account name on the machine. Restricting both means the enumeration stops
/// at a directory the caller cannot open.
pub fn prepare(dir: &Path) -> Result<(), StateDirError> {
    let create = |p: &Path| -> Result<(), StateDirError> {
        fs::create_dir_all(p)
            .map_err(|source| StateDirError::Create { path: p.to_path_buf(), source })
    };
    if let Some(parent) = dir.parent() {
        create(parent)?;
        restrict(parent)?;
    }
    create(dir)?;
    restrict(dir)?;
    Ok(())
}

/// Where a previous build put things, so a caller can notice and say so.
///
/// Not migrated automatically. The old location is a temp directory: anything found there
/// may already be a partial survivor of a cleanup, and silently adopting half an identity is
/// a worse failure than telling someone their old state is there and letting them move it.
pub fn legacy_temp_dir(profile: &str) -> PathBuf {
    std::env::temp_dir().join("cairn").join(profile)
}

#[cfg(target_os = "macos")]
fn platform_data_dir(get: &Getter<'_>) -> Result<PathBuf, StateDirError> {
    // Deliberately not XDG on macOS: `~/Library/Application Support` is where a Mac user's
    // backup tooling expects application state to be.
    Ok(get("HOME").ok_or(StateDirError::NoHome)?.join("Library").join("Application Support"))
}

#[cfg(target_os = "windows")]
fn platform_data_dir(get: &Getter<'_>) -> Result<PathBuf, StateDirError> {
    // `APPDATA` rather than `LOCALAPPDATA`: this is an identity worth carrying between
    // machines on a roaming profile, not a cache.
    get("APPDATA")
        .or_else(|| get("USERPROFILE").map(|p| p.join("AppData").join("Roaming")))
        .ok_or(StateDirError::NoHome)
}

#[cfg(all(unix, not(target_os = "macos")))]
fn platform_data_dir(get: &Getter<'_>) -> Result<PathBuf, StateDirError> {
    if let Some(xdg) = get("XDG_DATA_HOME") {
        return Ok(xdg);
    }
    Ok(get("HOME").ok_or(StateDirError::NoHome)?.join(".local").join("share"))
}

#[cfg(unix)]
fn restrict(path: &Path) -> Result<(), StateDirError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|source| StateDirError::Create { path: path.to_path_buf(), source })
}

/// On Windows the protection comes from the directory this now lives in.
///
/// `%APPDATA%` sits inside the user's profile, whose ACL already grants the user, SYSTEM and
/// Administrators and nobody else — inherited by everything created beneath it. That is the
/// rough equivalent of `0700`, and it is why moving out of the temp directory improves
/// Windows too rather than merely Linux. It is **not** identical: an Administrator can read
/// it, though so can `root` on Unix.
///
/// Setting a Windows ACL explicitly would mean calling Win32 through `unsafe`, which every
/// crate here forbids, or taking a dependency for it. Inheritance is doing the work, so
/// this records why rather than pretending nothing is needed.
#[cfg(not(unix))]
fn restrict(_path: &Path) -> Result<(), StateDirError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// A fake environment, so these test the branch logic rather than the machine they run on.
    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> =
            pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        move |k: &str| map.get(k).cloned()
    }

    #[test]
    fn state_never_defaults_into_a_directory_the_os_deletes() {
        // The property this module exists for. `/tmp` is cleared on reboot on most Linux
        // systems — often it is tmpfs, so it is RAM — and pruned on a timer otherwise. The
        // old default put the device key, the MLS group state and the whole message history
        // there, so a reboot took the account with it.
        let e = env(&[
            ("HOME", "/home/alice"),
            ("APPDATA", r"C:\Users\alice\AppData\Roaming"),
            ("USERPROFILE", r"C:\Users\alice"),
        ]);
        let dir = resolve("alice", &e).unwrap();
        let temp = std::env::temp_dir();
        assert!(
            !dir.starts_with(&temp),
            "the default must not sit under {}: got {}",
            temp.display(),
            dir.display()
        );
        assert!(dir.ends_with("alice"), "each profile gets its own directory");
    }

    #[test]
    fn there_is_no_temp_directory_fallback_when_home_is_missing() {
        // Refusing beats guessing. A messenger that quietly stores an identity somewhere the
        // OS deletes fails later and looks like data loss rather than a misconfiguration.
        let e = env(&[]);
        assert!(matches!(resolve("alice", &e), Err(StateDirError::NoHome)));
    }

    #[test]
    fn an_explicit_home_overrides_the_platform_default() {
        let e = env(&[("CAIRN_HOME", "/mnt/keys"), ("HOME", "/home/alice")]);
        assert_eq!(resolve("alice", &e).unwrap(), PathBuf::from("/mnt/keys/alice"));
    }

    #[test]
    fn an_empty_override_is_ignored_rather_than_making_a_relative_path() {
        // `CAIRN_HOME=` in a shell script is a common accident. Treating it as set would
        // resolve state to a bare relative path, which lands wherever the client happened to
        // be started from — a different directory each time.
        let e = env(&[("CAIRN_HOME", "   "), ("HOME", "/home/alice")]);
        let dir = resolve("alice", &e).unwrap();
        assert!(
            dir.is_absolute(),
            "state must not land in the working directory: {}",
            dir.display()
        );
    }

    #[test]
    fn two_profiles_do_not_share_a_directory() {
        let e = env(&[("CAIRN_HOME", "/mnt/keys")]);
        assert_ne!(
            resolve("alice", &e).unwrap(),
            resolve("bob", &e).unwrap(),
            "one machine holding two accounts must keep them apart"
        );
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    #[test]
    fn xdg_data_home_is_honoured_before_the_assumed_default() {
        let e = env(&[("XDG_DATA_HOME", "/home/alice/.data"), ("HOME", "/home/alice")]);
        assert_eq!(resolve("alice", &e).unwrap(), PathBuf::from("/home/alice/.data/cairn/alice"));
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    #[test]
    fn linux_falls_back_to_the_xdg_default_location() {
        let e = env(&[("HOME", "/home/alice")]);
        assert_eq!(
            resolve("alice", &e).unwrap(),
            PathBuf::from("/home/alice/.local/share/cairn/alice")
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_uses_application_support_rather_than_xdg() {
        // A Mac user's backup tooling looks in Application Support; XDG paths are invisible
        // to it.
        let e = env(&[("HOME", "/Users/alice"), ("XDG_DATA_HOME", "/Users/alice/.data")]);
        assert_eq!(
            resolve("alice", &e).unwrap(),
            PathBuf::from("/Users/alice/Library/Application Support/cairn/alice")
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_uses_appdata_and_falls_back_to_the_user_profile() {
        let e = env(&[("APPDATA", r"C:\Users\alice\AppData\Roaming")]);
        assert_eq!(
            resolve("alice", &e).unwrap(),
            PathBuf::from(r"C:\Users\alice\AppData\Roaming\cairn\alice")
        );

        let e = env(&[("USERPROFILE", r"C:\Users\alice")]);
        assert_eq!(
            resolve("alice", &e).unwrap(),
            PathBuf::from(r"C:\Users\alice\AppData\Roaming\cairn\alice")
        );
    }

    #[cfg(unix)]
    #[test]
    fn the_parent_directory_does_not_list_every_account_on_the_machine() {
        // `/tmp/cairn` was 755, so `ls` on it enumerated every profile name. The per-account
        // directory was already 0700, so contents were never exposed — but the *names* were,
        // and on a shared machine a name is a person.
        use std::os::unix::fs::PermissionsExt;
        let root = std::env::temp_dir().join(format!("cairn-sd-{}", uuid::Uuid::new_v4()));
        let dir = root.join("cairn").join("alice");
        prepare(&dir).unwrap();
        for path in [dir.parent().unwrap(), dir.as_path()] {
            let mode = fs::metadata(path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "{} must not be readable by other users", path.display());
        }
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn preparing_an_existing_directory_is_not_an_error() {
        // Every start after the first takes this path.
        let root = std::env::temp_dir().join(format!("cairn-sd-{}", uuid::Uuid::new_v4()));
        let dir = root.join("cairn").join("alice");
        prepare(&dir).unwrap();
        prepare(&dir).unwrap();
        fs::remove_dir_all(&root).ok();
    }
}
