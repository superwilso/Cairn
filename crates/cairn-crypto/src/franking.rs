//! Message franking, with transcript support.
//!
//! Franking lets a recipient prove to the server "this account sent me exactly this
//! message", without the server ever seeing plaintext. See
//! `docs/04-safety-architecture.md`.
//!
//! ## Why this is transcript-shaped from day one
//!
//! The commonly described franking scheme covers a **single** message in a **1-to-1**
//! conversation. Both limits are problems for real moderation:
//!
//! - A moderator handed one decontextualised line usually cannot judge it. Abuse is a
//!   pattern, and the reported message is often the *response* to the abuse.
//! - Retrofitting causality into a deployed report format is very expensive, because old
//!   clients keep producing the old format forever.
//!
//! So a report carries a **chain**: each message's server attestation names its
//! predecessor. A [`TranscriptReport`] can therefore carry a contiguous run whose ordering
//! a moderator verifies cryptographically rather than trusting. v1 may populate only one
//! message; the format does not have to change when it stops doing so.
//!
//! ## Why the server anchors the chain, not the sender
//!
//! An earlier design had each sender commit to the predecessor *it had seen*. That works
//! in a 1-to-1 conversation and breaks in a group: two members sending concurrently both
//! believe they follow the same message, the chain forks, and the resulting transcript
//! cannot be reported at all — an honest-participant failure, not an attack.
//!
//! Causality therefore lives in the server's tag. The server assigns `server_seq` and is
//! already the ordering authority, so it is the only party that knows the true order at
//! the time a message is accepted. This costs nothing in trust: the threat model
//! (`docs/01-threat-model.md` §4) already concedes that a malicious server can reorder and
//! drop messages, so making it the ordering witness grants it no new power.
//!
//! ## What this deliberately gives up
//!
//! Deniability. Franking exists to make sending provable, which is the opposite of what
//! a deniable protocol provides. This trade is stated in `docs/01-threat-model.md` §3.6
//! rather than hidden.
//!
//! ## Unframeability
//!
//! Nobody — including the server — can produce a valid report against a message that was
//! never sent. The commitment binds the plaintext, and the server's tag binds the
//! commitment to a specific sender, room, and sequence number. A server *can* refuse to
//! tag, or discard tags; it cannot forge one for a message that does not exist, because
//! it never learns an opening for a plaintext it has not been shown.

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use cairn_proto::{DeviceId, RoomId, UserId};

type HmacSha256 = Hmac<Sha256>;

/// Domain separation. Reusing one key across constructions without distinct labels is a
/// classic way to turn two sound primitives into one unsound one.
const DOMAIN_COMMITMENT: &[u8] = b"cairn/franking/commitment/v1";
const DOMAIN_TAG: &[u8] = b"cairn/franking/tag/v1";

/// Binding commitment to a message and its position in a conversation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Commitment(#[serde(with = "hex_array")] pub [u8; 32]);

impl Commitment {
    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }
}

/// The secret that opens a [`Commitment`].
///
/// Travels to the recipient **inside the encrypted envelope**, never to the server. A
/// recipient who wants to report a message discloses it deliberately; that disclosure is
/// what makes the report verifiable.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(transparent)]
pub struct Opening(#[serde(with = "hex_array")] pub [u8; 32]);

impl Opening {
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        Self(bytes)
    }
}

impl std::fmt::Debug for Opening {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print an opening: it appears in logs, and disclosing it makes a message
        // reportable by anyone who reads them.
        f.write_str("Opening(<redacted>)")
    }
}

/// The server's HMAC over a commitment, binding it to a sender and position.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Tag(#[serde(with = "hex_array")] pub [u8; 32]);

/// The server's long-term franking key. Never leaves the server.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ServerFrankingKey([u8; 32]);

impl ServerFrankingKey {
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Expose the raw key so it can be persisted.
    ///
    /// Named bluntly because that is what it is. The key must outlive restarts — losing
    /// it invalidates every franking tag the instance ever issued — but anything holding
    /// these bytes holds the ability to forge tags, so keep them on disk with restricted
    /// permissions and nowhere else.
    pub const fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    /// Tag a commitment, binding it to who sent it, where, and in what order.
    pub fn tag(&self, ctx: &Context) -> Tag {
        let mut mac = HmacSha256::new_from_slice(&self.0).expect("hmac accepts any key length");
        mac.update(DOMAIN_TAG);
        mac.update(&ctx.commitment.0);
        mac.update(ctx.room.as_uuid().as_bytes());
        mac.update(ctx.sender.as_uuid().as_bytes());
        mac.update(ctx.sender_device.as_uuid().as_bytes());
        mac.update(&ctx.server_seq.to_be_bytes());
        match &ctx.prev_commitment {
            Some(p) => {
                mac.update(&[1u8]);
                mac.update(&p.0);
            }
            None => mac.update(&[0u8]),
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&mac.finalize().into_bytes());
        Tag(out)
    }

    /// Constant-time tag verification.
    pub fn verify_tag(&self, ctx: &Context, tag: &Tag) -> bool {
        self.tag(ctx).0.ct_eq(&tag.0).into()
    }
}

impl std::fmt::Debug for ServerFrankingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ServerFrankingKey(<redacted>)")
    }
}

/// What the server attests to when it tags a message.
///
/// Every field is something the server already sees in every tier — franking adds no new
/// metadata exposure beyond what `docs/01-threat-model.md` §3.1 already concedes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Context {
    pub commitment: Commitment,
    pub room: RoomId,
    pub sender: UserId,
    pub sender_device: DeviceId,
    /// Server-assigned, strictly increasing per room. Gives the moderator an ordering
    /// that does not depend on the sender's self-reported clock.
    pub server_seq: u64,
    /// The commitment of the previous *franked* message in this room, as the server
    /// ordered it. `None` for the first.
    ///
    /// This is what makes a multi-message report verifiable as a sequence, and it is
    /// supplied by the server precisely because a sender in a group cannot know it.
    pub prev_commitment: Option<Commitment>,
}

/// Commit to a message.
///
/// Deliberately covers only the message. Ordering is attested by the server in
/// [`ServerFrankingKey::tag`] — see the module docs for why a sender cannot supply it
/// correctly in a group.
pub fn commit(plaintext: &[u8]) -> (Commitment, Opening) {
    let opening = Opening::generate();
    let commitment = commit_with_opening(plaintext, &opening);
    (commitment, opening)
}

/// Recompute a commitment from a known opening. Used by verifiers.
pub fn commit_with_opening(plaintext: &[u8], opening: &Opening) -> Commitment {
    // HMAC keyed by the opening is a standard commitment: hiding (the opening is
    // uniformly random and secret) and binding (finding a second preimage means breaking
    // HMAC-SHA256).
    let mut mac = HmacSha256::new_from_slice(&opening.0).expect("hmac accepts any key length");
    mac.update(DOMAIN_COMMITMENT);
    mac.update(&(plaintext.len() as u64).to_be_bytes());
    mac.update(plaintext);
    let mut out = [0u8; 32];
    out.copy_from_slice(&mac.finalize().into_bytes());
    Commitment(out)
}

/// Constant-time commitment check.
pub fn verify_commitment(plaintext: &[u8], opening: &Opening, commitment: &Commitment) -> bool {
    commit_with_opening(plaintext, opening).0.ct_eq(&commitment.0).into()
}

/// One message in a report: everything a moderator needs to verify it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportedMessage {
    pub plaintext: Vec<u8>,
    pub opening: Opening,
    pub context: Context,
    pub tag: Tag,
}

/// A contiguous run of messages disclosed by a recipient.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TranscriptReport {
    pub messages: Vec<ReportedMessage>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReportError {
    #[error("report contains no messages")]
    Empty,
    #[error("message {0}: commitment does not match the disclosed plaintext")]
    BadCommitment(usize),
    #[error("message {0}: server tag is invalid")]
    BadTag(usize),
    #[error("message {0}: breaks the transcript chain; not contiguous with its predecessor")]
    BrokenChain(usize),
    #[error("message {0}: not in the same room as the rest of the report")]
    RoomMismatch(usize),
    #[error("message {0}: sequence numbers are not strictly increasing")]
    OutOfOrder(usize),
}

impl TranscriptReport {
    /// Verify the whole report against the server's franking key.
    ///
    /// On success, every message is proven to have been sent by the named account in the
    /// named room, and the run is proven contiguous and correctly ordered.
    pub fn verify(&self, key: &ServerFrankingKey) -> Result<(), ReportError> {
        let first = self.messages.first().ok_or(ReportError::Empty)?;
        let room = first.context.room;
        let mut last: Option<(&Commitment, u64)> = None;

        for (i, m) in self.messages.iter().enumerate() {
            if m.context.room != room {
                return Err(ReportError::RoomMismatch(i));
            }
            // The commitment must actually open to the disclosed plaintext at this
            // position. This is what stops a reporter fabricating message content.
            let recomputed = commit_with_opening(&m.plaintext, &m.opening);
            if !bool::from(recomputed.0.ct_eq(&m.context.commitment.0)) {
                return Err(ReportError::BadCommitment(i));
            }
            // The server's tag must cover exactly this commitment and sender. This is
            // what stops a reporter attributing a real message to a different account.
            if !key.verify_tag(&m.context, &m.tag) {
                return Err(ReportError::BadTag(i));
            }
            if let Some((prev_commitment, prev_seq)) = last {
                // Causality: the server's attestation for this message must name the
                // message before it. A reporter cannot drop the one supplying context.
                match &m.context.prev_commitment {
                    Some(p) if bool::from(p.0.ct_eq(&prev_commitment.0)) => {}
                    _ => return Err(ReportError::BrokenChain(i)),
                }
                if m.context.server_seq <= prev_seq {
                    return Err(ReportError::OutOfOrder(i));
                }
            }
            last = Some((&m.context.commitment, m.context.server_seq));
        }
        Ok(())
    }
}

pub(crate) mod hex_array {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        let v = hex::decode(&s).map_err(serde::de::Error::custom)?;
        v.try_into().map_err(|_| serde::de::Error::custom("expected 32 bytes"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Harness {
        key: ServerFrankingKey,
        room: RoomId,
        sender: UserId,
        device: DeviceId,
        prev: Option<Commitment>,
        seq: u64,
    }

    impl Harness {
        fn new() -> Self {
            Self {
                key: ServerFrankingKey::generate(),
                room: RoomId::new(),
                sender: UserId::new(),
                device: DeviceId::new(),
                prev: None,
                seq: 0,
            }
        }

        /// Client commits, server orders and tags — the normal send path.
        fn send(&mut self, msg: &[u8]) -> ReportedMessage {
            self.send_as(self.sender, msg)
        }

        /// Same, from a specific account, so group cases can be exercised.
        fn send_as(&mut self, sender: UserId, msg: &[u8]) -> ReportedMessage {
            // Client: commits to the message only. It does not know the order.
            let (commitment, opening) = commit(msg);

            // Server: assigns the position and attests to what precedes it.
            self.seq += 1;
            let context = Context {
                commitment,
                room: self.room,
                sender,
                sender_device: self.device,
                server_seq: self.seq,
                prev_commitment: self.prev,
            };
            let tag = self.key.tag(&context);
            self.prev = Some(commitment);
            ReportedMessage { plaintext: msg.to_vec(), opening, context, tag }
        }
    }

    #[test]
    fn honest_single_message_report_verifies() {
        let mut h = Harness::new();
        let report = TranscriptReport { messages: vec![h.send(b"hello")] };
        assert_eq!(report.verify(&h.key), Ok(()));
    }

    #[test]
    fn honest_transcript_verifies() {
        let mut h = Harness::new();
        let report = TranscriptReport {
            messages: vec![h.send(b"first"), h.send(b"second"), h.send(b"third")],
        };
        assert_eq!(report.verify(&h.key), Ok(()));
    }

    #[test]
    fn tampered_plaintext_is_rejected() {
        // The core property: a reporter cannot change what the message said.
        let mut h = Harness::new();
        let mut m = h.send(b"i said something innocuous");
        m.plaintext = b"i said something appalling".to_vec();
        let report = TranscriptReport { messages: vec![m] };
        assert_eq!(report.verify(&h.key), Err(ReportError::BadCommitment(0)));
    }

    #[test]
    fn reattributing_to_another_account_is_rejected() {
        // Unframeability: a reporter cannot pin a real message on an innocent user.
        let mut h = Harness::new();
        let mut m = h.send(b"hello");
        m.context.sender = UserId::new();
        let report = TranscriptReport { messages: vec![m] };
        assert_eq!(report.verify(&h.key), Err(ReportError::BadTag(0)));
    }

    #[test]
    fn a_forged_message_cannot_be_tagged_without_the_server_key() {
        let mut h = Harness::new();
        let m = h.send(b"real");
        let attacker_key = ServerFrankingKey::generate();
        let report = TranscriptReport { messages: vec![m] };
        assert_eq!(report.verify(&attacker_key), Err(ReportError::BadTag(0)));
    }

    #[test]
    fn omitting_a_middle_message_breaks_the_chain() {
        // This is the property single-message franking cannot give you: a reporter
        // cannot quietly drop the message that supplies the context.
        let mut h = Harness::new();
        let first = h.send(b"what did you call me?");
        let _hidden = h.send(b"the provocation");
        let third = h.send(b"the angry reply");
        let report = TranscriptReport { messages: vec![first, third] };
        assert_eq!(report.verify(&h.key), Err(ReportError::BrokenChain(1)));
    }

    #[test]
    fn reordering_is_rejected() {
        let mut h = Harness::new();
        let a = h.send(b"one");
        let b = h.send(b"two");
        let report = TranscriptReport { messages: vec![b, a] };
        assert!(matches!(
            report.verify(&h.key),
            Err(ReportError::BrokenChain(1)) | Err(ReportError::OutOfOrder(1))
        ));
    }

    #[test]
    fn splicing_messages_from_another_room_is_rejected() {
        let mut h1 = Harness::new();
        let mut h2 = Harness::new();
        let a = h1.send(b"one");
        let b = h2.send(b"from elsewhere");
        let report = TranscriptReport { messages: vec![a, b] };
        assert_eq!(report.verify(&h1.key), Err(ReportError::RoomMismatch(1)));
    }

    #[test]
    fn empty_report_is_rejected() {
        let key = ServerFrankingKey::generate();
        let report = TranscriptReport { messages: vec![] };
        assert_eq!(report.verify(&key), Err(ReportError::Empty));
    }

    #[test]
    fn commitment_hides_the_message() {
        // Two identical plaintexts must not produce equal commitments, or the server
        // could detect repeated messages by comparing commitments.
        let (c1, _) = commit(b"same message");
        let (c2, _) = commit(b"same message");
        assert_ne!(c1, c2);
    }

    #[test]
    fn concurrent_group_senders_still_produce_a_reportable_transcript() {
        // The case that broke the previous design. Two members send without having seen
        // each other's message; the server orders them. Because the server supplies the
        // chain, honest concurrent senders no longer produce an unreportable transcript.
        let mut h = Harness::new();
        let alice = h.sender;
        let bob = UserId::new();

        let first = h.send_as(alice, b"shared context");
        let from_alice = h.send_as(alice, b"alice speaks");
        let from_bob = h.send_as(bob, b"bob speaks, unaware of alice");

        let report = TranscriptReport { messages: vec![first, from_alice, from_bob] };
        assert_eq!(report.verify(&h.key), Ok(()));
    }

    #[test]
    fn a_report_from_a_group_attributes_each_message_to_its_own_sender() {
        let mut h = Harness::new();
        let alice = h.sender;
        let bob = UserId::new();
        let a = h.send_as(alice, b"from alice");
        let b = h.send_as(bob, b"from bob");
        assert_eq!(a.context.sender, alice);
        assert_eq!(b.context.sender, bob);
        let report = TranscriptReport { messages: vec![a, b] };
        assert_eq!(report.verify(&h.key), Ok(()));
    }

    #[test]
    fn a_reporter_cannot_forge_the_chain_the_server_attested() {
        // The chain now lives inside the server's tag, so rewriting it invalidates the
        // tag rather than merely changing a client-supplied field.
        let mut h = Harness::new();
        let first = h.send(b"one");
        let mut second = h.send(b"two");
        second.context.prev_commitment = None;
        let report = TranscriptReport { messages: vec![first, second] };
        assert!(matches!(
            report.verify(&h.key),
            Err(ReportError::BadTag(1)) | Err(ReportError::BrokenChain(1))
        ));
    }

    #[test]
    fn opening_does_not_leak_via_debug() {
        let o = Opening::generate();
        assert_eq!(format!("{o:?}"), "Opening(<redacted>)");
        let k = ServerFrankingKey::generate();
        assert_eq!(format!("{k:?}"), "ServerFrankingKey(<redacted>)");
    }

    #[test]
    fn report_survives_json_roundtrip() {
        let mut h = Harness::new();
        let report = TranscriptReport { messages: vec![h.send(b"a"), h.send(b"b")] };
        let json = serde_json::to_string(&report).unwrap();
        let back: TranscriptReport = serde_json::from_str(&json).unwrap();
        assert_eq!(back.verify(&h.key), Ok(()));
    }
}
