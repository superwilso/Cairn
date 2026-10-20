//! Call signalling — the part of a call that is not media.
//!
//! ## Where this sits
//!
//! [`docs/12-realtime-media.md`](../../../docs/12-realtime-media.md) describes the finished
//! thing: an MLS group per call, SFrame on the media, an SFU in the middle. This is not that.
//! It is the rung below, and the one that gets a call working at all:
//!
//! - **Mesh WebRTC**, every participant connected directly to every other. §10 of the design
//!   already notes 1:1 can skip the SFU entirely; a small group is the same trick repeated.
//!   Media is encrypted by DTLS-SRTP between the peers and **never reaches the instance**.
//! - **No SFU**, so nothing to deploy and nothing for an operator to pay for.
//!
//! The cost is the reason an SFU exists: each participant uploads their stream once *per
//! other participant*, so upstream cost grows with the group. Four people is comfortable on
//! a domestic connection; eight is not. [`MAX_MESH_PARTICIPANTS`] is where this refuses
//! rather than letting a call degrade into something unusable and blaming the network.
//!
//! ## Signalling rides inside the encrypted body
//!
//! An SDP offer describes your codecs, your network candidates and your IP addresses. It is
//! carried as a field of the encrypted message body — the same place a link card and an
//! attachment key already travel — so **the instance never sees it**. It relays ciphertext
//! and learns only that a message went to the room, which it knew anyway.
//!
//! That is a real improvement over how most products do this, and it costs nothing: the
//! transport already exists. What it does *not* hide is that a call is happening — §6 of the
//! design document is explicit that who is in a call, with whom and for how long is visible
//! to the instance, and that is unchanged here.

use serde::{Deserialize, Serialize};

/// How many people a mesh call will admit.
///
/// Each participant sends their own stream to every other, so upload scales with the number
/// of peers. Six is already asking for ~5x a single stream's upstream from every person in
/// the call. Refusing past this is honest; letting the seventh person in and having everyone
/// blame their broadband is not.
///
/// Raising it is not a matter of changing this number — it is the point at which
/// `docs/12-realtime-media.md`'s SFU becomes the answer.
pub const MAX_MESH_PARTICIPANTS: usize = 6;

/// One signalling message between two participants.
///
/// Deliberately opaque to Rust: `payload` is an SDP blob or an ICE candidate, produced and
/// consumed by WebRTC in the client. Parsing it here would mean this crate taking a position
/// on SDP, which it has no reason to have — it carries the bytes and enforces who they are
/// addressed to.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CallSignal {
    /// Which call. A room can only host one at a time, but a stale signal from a previous
    /// call must not be applied to the current one — that is how a call ends up half-joined
    /// to something that already finished.
    pub call: String,
    pub kind: SignalKind,
    /// The intended recipient, for the point-to-point parts of the handshake.
    ///
    /// `None` means everyone in the call: joining and leaving are announcements. An offer or
    /// an answer is always addressed, because it describes one specific peer connection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
    /// SDP or an ICE candidate, as WebRTC produced it.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub payload: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalKind {
    /// "I am in this call." Everyone already in it answers with an offer.
    Join,
    /// "I have left." Sent on hang-up so peers tear down rather than waiting for a timeout.
    Leave,
    Offer,
    Answer,
    /// A single ICE candidate. There are many per connection and they arrive over time.
    Ice,
    /// "I am not answering." Sent by someone who was rung and said no, addressed to whoever
    /// rang them, so a caller in a DM sees "declined" instead of ringing into silence.
    ///
    /// It goes through the room like every other signal: the instance learns that a message
    /// went from one member to the room, and not what it said.
    Decline,
    /// "In this room's voice channel, my media is `payload`": [`VOICE_E2EE`] or
    /// [`VOICE_TRANSPORT_ONLY`]. Not part of a rung call — `call` is [`VOICE_CHANNEL`].
    ///
    /// **This is how a voice channel falls back**, per `docs/12-realtime-media.md` §5, and it
    /// rides the room's MLS encryption for a reason: the instance cannot forge it. A
    /// downgrade the instance could trigger would be a downgrade the instance could use to
    /// hear the call. See `docs/adr/012-sfu-voice-channels.md` §4.
    VoiceMedia,
}

/// The `call` field of a [`SignalKind::VoiceMedia`] signal. A room has one voice channel.
pub const VOICE_CHANNEL: &str = "voice";
/// The device seals its frames end to end.
pub const VOICE_E2EE: &str = "e2ee";
/// The device's webview cannot transform frames, so it sends and needs plaintext media.
pub const VOICE_TRANSPORT_ONLY: &str = "transport_only";

/// Where the client should look for its NAT-traversal helpers.
///
/// ## Why this is not a constant in the JavaScript
///
/// Two people behind home routers cannot reach each other by their own addresses; ICE needs
/// a STUN server to discover the public one, and a TURN relay when even that fails. Which
/// servers those are is an **operator** decision — a self-hosted instance should be able to
/// run its own and never touch a third party — so it lives here, where an instance-supplied
/// config can replace the default without a frontend change.
///
/// ## What STUN discloses, stated plainly
///
/// Asking a STUN server for your public address tells that server your IP and that you are
/// about to make a call. The default below is a public STUN service, so **the default leaks
/// that much to a third party**. It does not carry media or signalling — those stay between
/// the peers and the instance respectively — but it is a real disclosure and the UI says so
/// rather than implying otherwise.
///
/// A mesh call also shows every participant every other participant's IP address, because
/// the media flows directly between them. That is inherent to peer-to-peer media, not a
/// property of this default: routing through a TURN relay is the only thing that hides it,
/// and that costs an operator bandwidth. See `docs/12-realtime-media.md` §6.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IceServer {
    pub urls: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential: Option<String>,
}

// The credential is a relay password: short-lived, but usable by whoever holds it until it
// expires, so it stays out of logs.
impl std::fmt::Debug for IceServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IceServer")
            .field("urls", &self.urls)
            .field("username", &self.username)
            .field("credential", &self.credential.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// Everything the WebRTC layer needs before it builds a peer connection, for one call.
///
/// Sent to the frontend as data so the servers, and the honest caveats, come from here
/// rather than being baked into JavaScript.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CallConfig {
    pub ice_servers: Vec<IceServer>,
    /// False on STUN alone. The UI says so: without a relay a minority of users behind
    /// symmetric NATs will find calls simply do not connect, and "it is your network" is
    /// not something a client should leave them to work out themselves. It also decides
    /// whether "always use the relay" can connect anything at all.
    pub has_relay: bool,
    pub max_participants: usize,
    /// Whether the open room is a two-person direct conversation. A declined or unanswered
    /// call there ends, the way a phone call does; in a group it stays open for whoever
    /// joins next.
    pub direct: bool,
}

/// The servers a call uses, given what the instance offered.
///
/// The instance's own servers come first. The public STUN default is added **only if the
/// instance offered no STUN of its own**: an operator who runs coturn and lists its `stun:`
/// URL has calls that never touch a third party, which is the point of self-hosting it. An
/// operator who listed only `turn:` still gets direct connections where they work, at the
/// cost of the disclosure [`default_ice_servers`] describes.
pub fn ice_servers_with(instance: Vec<IceServer>) -> Vec<IceServer> {
    let has_stun = instance.iter().flat_map(|s| &s.urls).any(|u| {
        let u = u.to_ascii_lowercase();
        u.starts_with("stun:") || u.starts_with("stuns:")
    });
    let mut servers = instance;
    if !has_stun {
        servers.extend(default_ice_servers());
    }
    servers
}

/// The ICE servers a call should use.
///
/// `Default` is public STUN only. There is deliberately no default TURN server: a relay
/// carries every participant's media, so pointing it at somebody else's box by default would
/// be both a bandwidth theft and a disclosure nobody asked for.
pub fn default_ice_servers() -> Vec<IceServer> {
    vec![IceServer {
        urls: vec![
            "stun:stun.l.google.com:19302".to_string(),
            "stun:stun1.l.google.com:19302".to_string(),
        ],
        username: None,
        credential: None,
    }]
}

/// Whether this configuration can traverse a symmetric NAT.
///
/// STUN alone cannot: both ends learn their public addresses and still cannot open a path.
/// A client that promised "calls work" on STUN alone would be wrong for a minority of users
/// in a way they could not diagnose, so the UI is told which case it is in.
pub fn has_relay(servers: &[IceServer]) -> bool {
    servers.iter().flat_map(|s| &s.urls).any(|u| {
        let u = u.to_ascii_lowercase();
        u.starts_with("turn:") || u.starts_with("turns:")
    })
}

impl CallSignal {
    /// Is this signal meant for `me`?
    ///
    /// Every participant receives every signal — they all travel through the room — so each
    /// client has to discard the ones addressed to somebody else. Applying another peer's
    /// offer would tear down a working connection and replace it with a broken one.
    pub fn is_for(&self, me: &str) -> bool {
        match &self.to {
            None => true,
            Some(target) => target == me,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signal(kind: SignalKind, to: Option<&str>) -> CallSignal {
        CallSignal {
            call: "call-1".into(),
            kind,
            to: to.map(str::to_string),
            payload: "v=0...".into(),
        }
    }

    #[test]
    fn an_offer_addressed_to_someone_else_is_not_for_me() {
        // Every signal reaches every participant, because they all ride the room. A client
        // that applied another pair's offer would replace a working peer connection with a
        // broken one — and it would look like a network problem, not a bug.
        let mine = signal(SignalKind::Offer, Some("usr_me"));
        assert!(mine.is_for("usr_me"));
        assert!(!mine.is_for("usr_someone_else"));
    }

    #[test]
    fn a_join_announcement_is_for_everyone() {
        // Counterfactual for the test above: if addressing were required, nobody would ever
        // learn that a new participant had arrived.
        let announcement = signal(SignalKind::Join, None);
        assert!(announcement.is_for("usr_a"));
        assert!(announcement.is_for("usr_b"));
    }

    #[test]
    fn a_signal_round_trips_through_json() {
        // It travels inside the encrypted body, so it has to survive serde exactly.
        let original = signal(SignalKind::Ice, Some("usr_x"));
        let encoded = serde_json::to_vec(&original).unwrap();
        assert_eq!(serde_json::from_slice::<CallSignal>(&encoded).unwrap(), original);
    }

    #[test]
    fn the_default_ice_configuration_has_no_relay() {
        // Not a limitation to fix silently: it is the difference between "calls work" and
        // "calls work unless you are behind a symmetric NAT". The client has to be able to
        // tell a user which of those they are getting.
        assert!(!has_relay(&default_ice_servers()));
    }

    #[test]
    fn a_turn_server_is_recognised_as_a_relay() {
        // Counterfactual: if has_relay always said false, the assertion above would pass
        // while telling every user their calls cannot traverse anything.
        let with_turn = vec![IceServer {
            urls: vec!["TURNS:relay.example:5349".into()],
            username: Some("u".into()),
            credential: Some("p".into()),
        }];
        assert!(has_relay(&with_turn), "scheme matching must not be case-sensitive");
    }

    #[test]
    fn an_instance_with_its_own_stun_never_sends_a_call_to_the_public_default() {
        let own = vec![IceServer {
            urls: vec!["stun:turn.example:3478".into(), "turn:turn.example:3478".into()],
            username: Some("1:usr_x".into()),
            credential: Some("c".into()),
        }];
        let servers = ice_servers_with(own.clone());
        assert_eq!(servers, own, "the operator's own STUN replaces the third-party one");
        assert!(has_relay(&servers));

        // Counterfactual: a relay listed without STUN keeps the default, so direct paths
        // are still found where they exist.
        let relay_only = vec![IceServer { urls: vec!["turn:t.example".into()], ..own[0].clone() }];
        let servers = ice_servers_with(relay_only);
        assert!(servers.iter().any(|s| s.urls.iter().any(|u| u.contains("l.google.com"))));

        // And no instance servers at all is exactly the default.
        assert_eq!(ice_servers_with(Vec::new()), default_ice_servers());
    }

    #[test]
    fn a_relay_password_is_not_printed() {
        let server = IceServer {
            urls: vec!["turn:t.example".into()],
            username: Some("1:usr_x".into()),
            credential: Some("hunter2-relay".into()),
        };
        assert!(!format!("{server:?}").contains("hunter2"));
    }

    #[test]
    fn a_decline_round_trips_through_json() {
        let decline = signal(SignalKind::Decline, Some("usr_caller"));
        let encoded = serde_json::to_string(&decline).unwrap();
        assert!(encoded.contains(r#""decline""#), "{encoded}");
        assert_eq!(serde_json::from_str::<CallSignal>(&encoded).unwrap(), decline);
    }

    #[test]
    fn the_mesh_ceiling_is_small_on_purpose() {
        // A number worth defending rather than tuning: every participant uploads to every
        // other, so this is the point where the design document's SFU becomes the answer
        // instead of a bigger constant.
        const { assert!(MAX_MESH_PARTICIPANTS <= 8, "a mesh beyond this asks too much of upstream") };
    }
}
