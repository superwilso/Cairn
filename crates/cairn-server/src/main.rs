//! Cairn instance server.
//!
//! Cross-platform by construction: pure Rust with no platform-specific dependencies, so
//! the same source builds and runs on Linux, Windows, and macOS
//! (`docs/09-platform-strategy.md`). Linux is the primary supported target.
//!
//! ## Status
//!
//! Pre-alpha scaffold. No authentication and no TLS termination. **Not deployable.** It
//! exists to make the vertical slice exercisable end to end. State is now persisted, so
//! the franking key and message log survive a restart.

#![forbid(unsafe_code)]

use cairn_server::{backup, http, state, storage};

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use tracing_subscriber::EnvFilter;

const USAGE: &str = "\
usage:
  cairn-server                          run the instance
  cairn-server backup  <dest>           snapshot the data directory into <dest>
  cairn-server verify  <backup-dir>     open a backup and confirm it would restore
  cairn-server restore <backup> <dest>  restore a verified backup into <dest>

The data directory is $CAIRN_DATA_DIR (default ./data).

backup, verify and restore all open a database, so they refuse to run against an instance
that is still up rather than producing a copy that cannot be restored.
";

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        // `Display`, and the whole `source` chain with it. Returning the error from `main`
        // prints its `Debug` form instead: an operator who restored a database beside the
        // wrong key would see `Error: Storage(FrankingKeyMismatch)` rather than the sentence
        // telling them what happened and what to do — which is the one moment that message
        // exists for.
        eprintln!("{e}");
        let mut source = std::error::Error::source(&*e);
        while let Some(cause) = source {
            eprintln!("  caused by: {cause}");
            source = cause.source();
        }
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let data_dir = std::env::var("CAIRN_DATA_DIR").unwrap_or_else(|_| "./data".to_string());
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        None => {}
        Some("backup") => return Ok(run_backup(&data_dir, &args)?),
        Some("verify") => return Ok(run_verify(&args)?),
        Some("restore") => return Ok(run_restore(&args)?),
        Some("--help" | "-h" | "help") => {
            print!("{USAGE}");
            return Ok(());
        }
        Some(other) => {
            eprint!("unknown command '{other}'\n\n{USAGE}");
            std::process::exit(2);
        }
    }

    let bind: SocketAddr =
        std::env::var("CAIRN_BIND").unwrap_or_else(|_| "127.0.0.1:8080".to_string()).parse()?;

    let storage = Arc::new(storage::DbStorage::new(&data_dir)?);
    let instance = Arc::new(state::Instance::open(storage)?);

    // Operator controls are configured at startup rather than exposed over HTTP. An
    // unauthenticated endpoint for minting invites would defeat invite-only registration
    // entirely, and there is no admin authentication yet to gate one properly.
    if let Ok(policy) = std::env::var("CAIRN_REGISTRATION_POLICY") {
        let policy = match policy.as_str() {
            "open" => state::RegistrationPolicy::Open,
            "invite_only" => state::RegistrationPolicy::InviteOnly,
            other => {
                return Err(format!(
                    "CAIRN_REGISTRATION_POLICY must be 'open' or 'invite_only', got '{other}'"
                )
                .into())
            }
        };
        instance.set_registration_policy(policy)?;
        if policy == state::RegistrationPolicy::Open {
            tracing::warn!(
                "registration is OPEN: anyone can claim any unused user id, including one \
                 a legitimate user intended to take. Use invite_only unless this instance \
                 is disposable."
            );
        }
    }
    tracing::info!(policy = ?instance.registration_policy(), "registration policy");

    // Comma-separated tokens to mint on boot, so an operator can bootstrap without an
    // admin API. Existing tokens are re-minted as unused, so do not reuse a spent token.
    if let Ok(tokens) = std::env::var("CAIRN_INVITES") {
        for token in tokens.split(',').map(str::trim).filter(|t| !t.is_empty()) {
            instance.create_invite(token, None)?;
            tracing::info!(token, "invite created");
        }
    }
    let app = http::router(instance);

    tracing::warn!("pre-alpha scaffold: no auth, no TLS. Do not expose this.");
    tracing::info!(%data_dir, "state directory");
    tracing::info!(%bind, "cairn-server listening");

    let listener = tokio::net::TcpListener::bind(bind).await?;
    axum::serve(listener, app).with_graceful_shutdown(shutdown_signal()).await?;
    Ok(())
}

fn now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

fn run_backup(data_dir: &str, args: &[String]) -> Result<(), backup::BackupError> {
    let Some(dest) = args.get(1) else {
        eprint!("backup needs a destination\n\n{USAGE}");
        std::process::exit(2);
    };
    let manifest = backup::run(Path::new(data_dir), Path::new(dest), now_ms())?;
    println!(
        "backed up {} rows and {} messages to {dest}, verified",
        manifest.counts.rows, manifest.counts.messages
    );
    // Said every time rather than in the docs only: the two files are one artifact, and
    // separating them is the failure this command exists to make hard.
    println!(
        "keep {} and {} together — a database without its key is not a restore",
        backup::DB_FILE,
        backup::KEY_FILE
    );
    Ok(())
}

fn run_verify(args: &[String]) -> Result<(), backup::BackupError> {
    let Some(dir) = args.get(1) else {
        eprint!("verify needs a backup directory\n\n{USAGE}");
        std::process::exit(2);
    };
    let manifest = backup::verify(Path::new(dir))?;
    println!(
        "{dir} would restore: {} rows, {} messages, taken at {}ms",
        manifest.counts.rows, manifest.counts.messages, manifest.taken_at_ms
    );
    Ok(())
}

fn run_restore(args: &[String]) -> Result<(), backup::BackupError> {
    let (Some(src), Some(dest)) = (args.get(1), args.get(2)) else {
        eprint!("restore needs a backup directory and a destination\n\n{USAGE}");
        std::process::exit(2);
    };
    let manifest = backup::restore(Path::new(src), Path::new(dest))?;
    println!(
        "restored {} rows and {} messages into {dest}",
        manifest.counts.rows, manifest.counts.messages
    );
    Ok(())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("shutting down");
}
