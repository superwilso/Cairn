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

mod http;
mod state;
mod storage;

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
    let storage = Arc::new(storage::FileStorage::new(&data_dir)?);
    let instance = Arc::new(state::Instance::open(storage)?);
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
