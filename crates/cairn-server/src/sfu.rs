//! The instance's selective forwarding unit, for voice channels.
//!
//! ## What it is
//!
//! An in-process SFU built on [`str0m`], a sans-IO WebRTC library: one UDP socket, one
//! thread, one `Rtc` per connected device. Each client offers **two** audio tracks it sends —
//! its microphone, then its soundboard ([`VoiceTrack`]) — and [`RECEIVE_SLOTS`] audio tracks
//! it receives, all in its first offer, so nobody ever renegotiates as people come and go —
//! the same trick the mesh uses with its empty video line, and for the same reason:
//! renegotiation is where call bugs live. The SFU assigns each other participant's track to a
//! free receive slot the first time it carries anything.
//!
//! ## What it sees, stated rather than implied
//!
//! It terminates DTLS-SRTP from every participant, so it holds each RTP payload. In an
//! end-to-end encrypted room that payload is a frame sealed by [`cairn_crypto::media`] in the
//! sender's webview, which this process has no key for. What it *does* hold, by construction:
//!
//! - **Who is connected, from which IP address and port, from when until when.**
//! - **Packet sizes and timing per sender.** Opus at a steady frame rate still varies in
//!   size with speech, so who is talking, and when, is visible without decrypting anything.
//! - **When each participant plays a soundboard clip**, because clips arrive on their own
//!   track. The price of letting each listener turn one person's clips down separately.
//! - **The SDP offer**: codecs, the client's ICE candidates (its addresses), its DTLS
//!   fingerprint.
//! - **The frame trailer**: the MLS epoch's low bits and the sender's leaf index.
//!
//! What it deliberately does not negotiate: the `ssrc-audio-level` RTP header extension.
//! Browsers fill it with a per-packet loudness value *outside* the encryption, which would
//! hand the SFU a voice-activity meter for free. The answer omits it, so browsers do not
//! send it. Timing still leaks most of the same signal; this removes the explicit version.
//!
//! ## Who may send to whom
//!
//! Not decided here. Every forwarding decision asks [`crate::state::VoiceRegistry`] whether
//! both ends still hold a seat in the same room, and a connection whose seat has gone is
//! closed. The registry is changed only by `state.rs`'s rules, so removing someone from a
//! room removes them from its voice channel without this module knowing why.

use std::collections::HashMap;
#[cfg(feature = "test-tap")]
use std::collections::VecDeque;
use std::io::ErrorKind;
use std::net::{SocketAddr, UdpSocket};
use std::sync::mpsc::{self, Receiver, Sender, SyncSender, TryRecvError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use cairn_proto::RoomId;
use str0m::change::SdpOffer;
use str0m::media::{Direction, MediaData, MediaKind, Mid};
use str0m::net::{Protocol, Receive};
use str0m::rtp::{Extension, ExtensionMap};
use str0m::{Candidate, Event, IceConnectionState, Input, Output, Rtc, RtcConfig};

pub use crate::state::VoiceTrack;
use crate::state::{SharedVoice, VoiceSessionId, MAX_VOICE_PARTICIPANTS};

/// How many audio tracks each client offers to receive: a voice and a soundboard from
/// everyone but itself.
pub const RECEIVE_SLOTS: usize = 2 * (MAX_VOICE_PARTICIPANTS - 1);

/// A connection that has not completed ICE and DTLS by now never will. Its seat is given
/// back, so a client that asked and never connected does not linger in the roster.
const CONNECT_DEADLINE: Duration = Duration::from_secs(15);

/// Where the SFU listens and what address it tells clients to send to.
#[derive(Debug, Clone, Copy)]
pub struct SfuConfig {
    pub bind: SocketAddr,
    /// The address in the ICE candidate. The bind address unless it is unspecified
    /// (`0.0.0.0`), which no client can send to.
    pub advertise: SocketAddr,
}

/// One frame as the SFU saw it. Test builds only: production has no way to record media.
#[cfg(feature = "test-tap")]
#[derive(Debug, Clone)]
pub struct TappedFrame {
    pub session: VoiceSessionId,
    pub track: VoiceTrack,
    pub room: RoomId,
    pub payload: Vec<u8>,
}

enum Command {
    Open {
        session: VoiceSessionId,
        room: RoomId,
        offer: SdpOffer,
        reply: SyncSender<Result<String, String>>,
    },
    Close {
        session: VoiceSessionId,
    },
    Slots {
        session: VoiceSessionId,
        reply: SyncSender<Vec<(String, VoiceSessionId, VoiceTrack)>>,
    },
}

/// A handle on the running SFU. Dropping every handle stops its thread.
#[derive(Debug)]
pub struct Sfu {
    commands: Mutex<Sender<Command>>,
    local: SocketAddr,
    #[cfg(feature = "test-tap")]
    tap: Arc<Mutex<VecDeque<TappedFrame>>>,
}

impl std::fmt::Debug for Command {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Command")
    }
}

impl Sfu {
    /// Bind the socket and start the media thread.
    pub fn start(config: SfuConfig, voice: SharedVoice) -> std::io::Result<Arc<Self>> {
        let socket = UdpSocket::bind(config.bind)?;
        let local = socket.local_addr()?;
        let mut advertise = config.advertise;
        if advertise.port() == 0 {
            advertise.set_port(local.port());
        }
        if advertise.ip().is_unspecified() {
            return Err(std::io::Error::new(
                ErrorKind::InvalidInput,
                "the SFU needs an address clients can reach: set CAIRN_SFU_ADVERTISE",
            ));
        }
        let (tx, rx) = mpsc::channel();
        #[cfg(feature = "test-tap")]
        let tap = Arc::new(Mutex::new(VecDeque::new()));
        let mut worker = Worker {
            socket,
            advertise,
            voice,
            peers: Vec::new(),
            #[cfg(feature = "test-tap")]
            tap: Arc::clone(&tap),
        };
        std::thread::Builder::new().name("cairn-sfu".into()).spawn(move || worker.run(rx))?;
        Ok(Arc::new(Self {
            commands: Mutex::new(tx),
            local,
            #[cfg(feature = "test-tap")]
            tap,
        }))
    }

    /// The socket the SFU is bound to.
    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }

    fn send(&self, command: Command) -> Result<(), String> {
        self.commands
            .lock()
            .expect("sfu mutex poisoned")
            .send(command)
            .map_err(|_| "the SFU has stopped".to_string())
    }

    /// Accept a client's offer for a seat that `state.rs` has already granted. Blocking —
    /// call it off the async runtime.
    pub fn open(
        &self,
        session: VoiceSessionId,
        room: RoomId,
        offer: &str,
    ) -> Result<String, String> {
        let offer =
            SdpOffer::from_sdp_string(offer).map_err(|e| format!("unreadable offer: {e}"))?;
        let (reply, answer) = mpsc::sync_channel(1);
        self.send(Command::Open { session, room, offer, reply })?;
        answer.recv().map_err(|_| "the SFU has stopped".to_string())?
    }

    /// Drop a connection now, rather than at the next seat check.
    pub fn close(&self, session: VoiceSessionId) {
        let _ = self.send(Command::Close { session });
    }

    /// Which receive slot (by MID) carries which other session's which track, for
    /// `session`'s own connection. The SFU's claim, not an authenticated one: in an E2EE call
    /// a client trusts the key a frame opens under, and its sealed soundboard flag, instead.
    /// Blocking.
    pub fn slots(&self, session: VoiceSessionId) -> Vec<(String, VoiceSessionId, VoiceTrack)> {
        let (reply, slots) = mpsc::sync_channel(1);
        if self.send(Command::Slots { session, reply }).is_err() {
            return Vec::new();
        }
        slots.recv().unwrap_or_default()
    }

    /// Frames as the SFU received them, most recent last. Test builds only.
    #[cfg(feature = "test-tap")]
    pub fn tapped(&self) -> Vec<TappedFrame> {
        self.tap.lock().expect("tap mutex poisoned").iter().cloned().collect()
    }

    /// Forget what was tapped, so a test can look at one phase of a call. Test builds only.
    #[cfg(feature = "test-tap")]
    pub fn clear_tap(&self) {
        self.tap.lock().expect("tap mutex poisoned").clear();
    }
}

struct Peer {
    session: VoiceSessionId,
    room: RoomId,
    rtc: Rtc,
    created: Instant,
    connected: bool,
    /// The tracks this client sends: its microphone, then its soundboard, in offer order.
    sends: Vec<(Mid, VoiceTrack)>,
    /// The tracks it receives, and whose voice or soundboard each carries.
    slots: Vec<(Mid, Option<(VoiceSessionId, VoiceTrack)>)>,
}

struct Worker {
    socket: UdpSocket,
    advertise: SocketAddr,
    voice: SharedVoice,
    peers: Vec<Peer>,
    #[cfg(feature = "test-tap")]
    tap: Arc<Mutex<VecDeque<TappedFrame>>>,
}

impl Worker {
    fn run(&mut self, commands: Receiver<Command>) {
        let mut buf = vec![0u8; 2000];
        loop {
            loop {
                match commands.try_recv() {
                    Ok(c) => self.command(c),
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => return,
                }
            }
            self.enforce_seats();

            let mut timeout = Instant::now() + Duration::from_millis(50);
            let mut forwards = Vec::new();
            for peer in &mut self.peers {
                timeout = timeout.min(drive(peer, &self.socket, &mut forwards));
            }
            for (from, track, data) in forwards {
                self.forward(from, track, data);
            }

            let wait =
                timeout.saturating_duration_since(Instant::now()).max(Duration::from_millis(1));
            let _ = self.socket.set_read_timeout(Some(wait));
            buf.resize(2000, 0);
            match self.socket.recv_from(&mut buf) {
                Ok((n, source)) => {
                    let destination = self.socket.local_addr().unwrap_or(self.advertise);
                    if let Ok(contents) = buf[..n].try_into() {
                        let input = Input::Receive(
                            Instant::now(),
                            Receive { proto: Protocol::Udp, source, destination, contents },
                        );
                        if let Some(peer) = self.peers.iter_mut().find(|p| p.rtc.accepts(&input)) {
                            if peer.rtc.handle_input(input).is_err() {
                                peer.rtc.disconnect();
                            }
                        }
                    }
                }
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
                Err(e) => tracing::warn!(error = %e, "sfu socket read failed"),
            }
            let now = Instant::now();
            for peer in &mut self.peers {
                if peer.rtc.is_alive() && peer.rtc.handle_input(Input::Timeout(now)).is_err() {
                    peer.rtc.disconnect();
                }
            }
        }
    }

    fn command(&mut self, command: Command) {
        match command {
            Command::Open { session, room, offer, reply } => {
                let _ = reply.send(self.open(session, room, offer));
            }
            Command::Close { session } => {
                for p in self.peers.iter_mut().filter(|p| p.session == session) {
                    p.rtc.disconnect();
                }
            }
            Command::Slots { session, reply } => {
                let slots = self
                    .peers
                    .iter()
                    .find(|p| p.session == session)
                    .map(|p| {
                        p.slots
                            .iter()
                            .filter_map(|(mid, src)| src.map(|(s, t)| (mid.to_string(), s, t)))
                            .collect()
                    })
                    .unwrap_or_default();
                let _ = reply.send(slots);
            }
        }
    }

    fn open(
        &mut self,
        session: VoiceSessionId,
        room: RoomId,
        offer: SdpOffer,
    ) -> Result<String, String> {
        // No audio-level extension; see the module docs.
        let mut exts = ExtensionMap::empty();
        exts.set(2, Extension::AbsoluteSendTime);
        exts.set(3, Extension::TransportSequenceNumber);
        exts.set(4, Extension::RtpMid);
        let mut rtc = RtcConfig::new()
            .set_crypto_provider(Arc::new(str0m::crypto::from_feature_flags()))
            .set_ice_lite(true)
            .clear_codecs()
            .enable_opus(true, false)
            .set_extension_map(exts)
            .build(Instant::now());
        let candidate = Candidate::host(self.advertise, "udp").map_err(|e| e.to_string())?;
        rtc.add_local_candidate(candidate);
        let answer =
            rtc.sdp_api().accept_offer(offer).map_err(|e| format!("offer refused: {e}"))?;
        // A reconnect from the same seat replaces the old connection.
        self.peers.retain(|p| p.session != session);
        self.peers.push(Peer {
            session,
            room,
            rtc,
            created: Instant::now(),
            connected: false,
            sends: Vec::new(),
            slots: Vec::new(),
        });
        Ok(answer.to_sdp_string())
    }

    /// Close every connection whose seat has gone, or that never connected; give dead ones'
    /// seats back; free the slots they occupied in everyone else.
    fn enforce_seats(&mut self) {
        let mut voice = self.voice.lock().expect("voice mutex poisoned");
        for p in &mut self.peers {
            let seated = voice.room_of(p.session) == Some(p.room);
            let stalled = !p.connected && p.created.elapsed() > CONNECT_DEADLINE;
            if p.rtc.is_alive() && (!seated || stalled) {
                p.rtc.disconnect();
            }
        }
        let dead: Vec<VoiceSessionId> =
            self.peers.iter().filter(|p| !p.rtc.is_alive()).map(|p| p.session).collect();
        for session in &dead {
            voice.vacate(*session);
        }
        drop(voice);
        if dead.is_empty() {
            return;
        }
        self.peers.retain(|p| p.rtc.is_alive());
        for p in &mut self.peers {
            for (_, src) in &mut p.slots {
                if src.is_some_and(|(s, _)| dead.contains(&s)) {
                    *src = None;
                }
            }
        }
    }

    fn forward(&mut self, from: VoiceSessionId, track: VoiceTrack, data: MediaData) {
        // Chromium sends padding-only packets, which depacketise to an empty payload. They
        // carry no media and no frame to seal; found when the browser test's tap counted 12
        // "unsealed frames" in 1000 and every one was zero bytes. Not forwarded.
        if data.data.is_empty() {
            return;
        }
        // Asked per packet, not per seat check: between two checks a removed member's
        // packets would otherwise still reach the room.
        let voice = self.voice.lock().expect("voice mutex poisoned");
        let Some(room) = voice.room_of(from) else { return };
        let seated: HashMap<VoiceSessionId, RoomId> = self
            .peers
            .iter()
            .filter_map(|p| voice.room_of(p.session).map(|r| (p.session, r)))
            .collect();
        drop(voice);

        #[cfg(feature = "test-tap")]
        {
            let mut tap = self.tap.lock().expect("tap mutex poisoned");
            tap.push_back(TappedFrame { session: from, track, room, payload: data.data.to_vec() });
            while tap.len() > 2000 {
                tap.pop_front();
            }
        }

        for p in &mut self.peers {
            if p.session == from || seated.get(&p.session) != Some(&room) || p.room != room {
                continue;
            }
            let slot = match p.slots.iter().position(|(_, s)| *s == Some((from, track))) {
                Some(i) => i,
                None => match p.slots.iter().position(|(_, s)| s.is_none()) {
                    Some(i) => {
                        p.slots[i].1 = Some((from, track));
                        i
                    }
                    None => continue,
                },
            };
            let mid = p.slots[slot].0;
            let Some(writer) = p.rtc.writer(mid) else { continue };
            let Some(pt) = writer.match_params(data.params) else { continue };
            if writer.write(pt, data.network_time, data.time, data.data.clone()).is_err() {
                p.rtc.disconnect();
            }
        }
    }
}

/// Run one connection until it wants time to pass, collecting the media it produced.
fn drive(
    peer: &mut Peer,
    socket: &UdpSocket,
    forwards: &mut Vec<(VoiceSessionId, VoiceTrack, MediaData)>,
) -> Instant {
    loop {
        if !peer.rtc.is_alive() {
            return Instant::now();
        }
        match peer.rtc.poll_output() {
            Ok(Output::Timeout(t)) => return t,
            Ok(Output::Transmit(t)) => {
                let _ = socket.send_to(&t.contents, t.destination);
            }
            Ok(Output::Event(e)) => match e {
                Event::Connected => peer.connected = true,
                Event::IceConnectionStateChange(IceConnectionState::Disconnected) => {
                    peer.rtc.disconnect()
                }
                Event::MediaAdded(m) if m.kind == MediaKind::Audio => match m.direction {
                    // Directions are the SFU's: RecvOnly is what the client sends. The first is
                    // its microphone and the second its soundboard; a third is ignored.
                    Direction::RecvOnly | Direction::SendRecv if peer.sends.len() < 2 => {
                        let track = if peer.sends.is_empty() {
                            VoiceTrack::Voice
                        } else {
                            VoiceTrack::Board
                        };
                        peer.sends.push((m.mid, track))
                    }
                    Direction::SendOnly if peer.slots.len() < RECEIVE_SLOTS => {
                        peer.slots.push((m.mid, None))
                    }
                    _ => {}
                },
                Event::MediaData(d) => {
                    if let Some(&(_, track)) = peer.sends.iter().find(|(mid, _)| *mid == d.mid) {
                        forwards.push((peer.session, track, d));
                    }
                }
                _ => {}
            },
            Err(_) => peer.rtc.disconnect(),
        }
    }
}
