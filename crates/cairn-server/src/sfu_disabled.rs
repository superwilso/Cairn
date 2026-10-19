//! The SFU's interface in a build without the `sfu` feature: it refuses to start.
//!
//! The real module (`sfu.rs`) is built on `str0m`, whose tree depends on `time`, and `time`
//! needs rustc 1.88 from the release that fixed RUSTSEC-2026-0009. So the SFU cannot build
//! on the project's 1.85 floor, while everything else in this crate can — and the MSRV job
//! checks exactly that, with `--no-default-features`. Keeping the same names here means no
//! other file carries a `cfg`: an instance built this way simply has no voice channels, as
//! one with `CAIRN_SFU_BIND` unset does.

use std::net::SocketAddr;
use std::sync::Arc;

use cairn_proto::RoomId;

use crate::state::{SharedVoice, VoiceSessionId, MAX_VOICE_PARTICIPANTS};

/// As in the real module.
pub const RECEIVE_SLOTS: usize = MAX_VOICE_PARTICIPANTS - 1;

/// As in the real module.
#[derive(Debug, Clone, Copy)]
pub struct SfuConfig {
    pub bind: SocketAddr,
    pub advertise: SocketAddr,
}

/// Never constructed: [`Sfu::start`] always fails in this build.
#[derive(Debug)]
pub struct Sfu {
    never: std::convert::Infallible,
}

impl Sfu {
    pub fn start(_config: SfuConfig, _voice: SharedVoice) -> std::io::Result<Arc<Self>> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "this build of cairn-server has no SFU (built without the `sfu` feature)",
        ))
    }

    pub fn local_addr(&self) -> SocketAddr {
        match self.never {}
    }

    pub fn open(
        &self,
        _session: VoiceSessionId,
        _room: RoomId,
        _offer: &str,
    ) -> Result<String, String> {
        match self.never {}
    }

    pub fn close(&self, _session: VoiceSessionId) {
        match self.never {}
    }

    pub fn slots(&self, _session: VoiceSessionId) -> Vec<(String, VoiceSessionId)> {
        match self.never {}
    }
}
