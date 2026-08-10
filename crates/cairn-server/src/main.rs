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

use cairn_server::{http, state, storage};

use std::net::SocketAddr;
use std::sync::Arc;

use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let bind: SocketAddr =
        std::env::var("CAIRN_BIND").unwrap_or_else(|_| "127.0.0.1:8080".to_string()).parse()?;

    let data_dir = std::env::var("CAIRN_DATA_DIR").unwrap_or_else(|_| "./data".to_string());
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

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("shutting down");
}
