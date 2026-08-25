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
}

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
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IceServer {
    pub urls: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential: Option<String>,
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
    fn the_mesh_ceiling_is_small_on_purpose() {
        // A number worth defending rather than tuning: every participant uploads to every
        // other, so this is the point where the design document's SFU becomes the answer
        // instead of a bigger constant.
        const { assert!(MAX_MESH_PARTICIPANTS <= 8, "a mesh beyond this asks too much of upstream") };
    }
}
