//! The SFU's interface in a build without the `sfu` feature: it refuses to start.
//!
//! The feature exists so an operator can build an instance without the SFU and its WebRTC
//! dependency tree; CI checks that build with `--no-default-features`. Keeping the same names here means no
//! other file carries a `cfg`: an instance built this way simply has no voice channels, as
//! one with `CAIRN_SFU_BIND` unset does.

use std::net::SocketAddr;
use std::sync::Arc;

use cairn_proto::RoomId;

pub use crate::state::VoiceTrack;
use crate::state::{SharedVoice, VoiceSessionId, MAX_VOICE_PARTICIPANTS};

/// As in the real module.
pub const RECEIVE_SLOTS: usize = 2 * (MAX_VOICE_PARTICIPANTS - 1);

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

    pub fn slots(&self, _session: VoiceSessionId) -> Vec<(String, VoiceSessionId, VoiceTrack)> {
        match self.never {}
    }
}
