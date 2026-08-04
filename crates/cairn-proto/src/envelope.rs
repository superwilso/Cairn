//! The message envelope.
//!
//! An envelope is what actually crosses the wire. The invariant this module exists to
//! enforce is that **the payload variant must match the room's tier**: an E2EE room must
//! never carry a plaintext payload, and the type system plus [`Envelope::new`] are what
//! make that hard to get wrong.
//!
//! Note what the envelope does *not* hide: sender, room, and timestamp are all visible to
//! the server in every tier. That is the metadata exposure conceded in
//! `docs/01-threat-model.md` §3.1, and it is visible here rather than buried.

use serde::{Deserialize, Serialize};

use crate::ids::{DeviceId, MessageId, RoomId, UserId};
use crate::tier::Tier;

/// The body of an envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EnvelopePayload {
    /// An MLS application message. Opaque to the server.
    ///
    /// The bytes are an RFC 9420 `MLSMessage`; the server relays them without parsing
    /// anything beyond what routing requires.
    MlsApplication {
        #[serde(with = "hex_bytes")]
        ciphertext: Vec<u8>,
    },

    /// An MLS handshake message — a commit, proposal, or welcome.
    ///
    /// The server *does* care about these: it sequences commits, which is what gives a
    /// single-instance deployment the strict ordering MLS requires. See ADR-002.
    MlsHandshake {
        #[serde(with = "hex_bytes")]
        message: Vec<u8>,
        /// Server-assigned sequence number establishing commit order within the room.
        /// `None` until the server assigns it.
        #[serde(skip_serializing_if = "Option::is_none")]
        epoch_seq: Option<u64>,
    },

    /// Plaintext content. **Only legal in [`Tier::PublicCommunity`].**
    Plaintext { body: String },
}

impl EnvelopePayload {
    /// Whether this payload keeps content from the server.
    pub const fn is_opaque_to_server(&self) -> bool {
        match self {
            EnvelopePayload::MlsApplication { .. } | EnvelopePayload::MlsHandshake { .. } => true,
            EnvelopePayload::Plaintext { .. } => false,
        }
    }
}

/// Rejections at the tier/payload boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum EnvelopeError {
    #[error("plaintext payload is not permitted in an end-to-end encrypted room")]
    PlaintextInEncryptedRoom,
}

/// A message as it crosses the wire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    pub version: u16,
    pub id: MessageId,
    pub room: RoomId,
    /// Visible to the server in every tier. See `docs/01-threat-model.md` §3.1.
    pub sender: UserId,
    /// The specific device that sent this, so per-device revocation is meaningful.
    pub sender_device: DeviceId,
    /// Milliseconds since the Unix epoch, as claimed by the sender.
    ///
    /// Sender-claimed and therefore not trustworthy on its own; the server records its
    /// own receive time separately. Never use this for ordering decisions that matter.
    pub sent_at_ms: i64,
    pub payload: EnvelopePayload,
    /// Franking commitment, present when the message is frankable.
    ///
    /// See `cairn-crypto::franking`. Absent in [`Tier::PublicCommunity`], where the
    /// server holds the plaintext anyway and franking would prove nothing it cannot
    /// already show.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub franking_commitment: Option<String>,
}

impl Envelope {
    /// Build an envelope, enforcing the tier/payload invariant.
    ///
    /// This is the only constructor. Constructing an `Envelope` with a mismatched payload
    /// requires deliberately building the struct literal, which is why the check lives
    /// here and is also re-run by [`Envelope::validate_for_tier`] on receipt.
    pub fn new(
        tier: Tier,
        room: RoomId,
        sender: UserId,
        sender_device: DeviceId,
        sent_at_ms: i64,
        payload: EnvelopePayload,
    ) -> Result<Self, EnvelopeError> {
        let envelope = Self {
            version: crate::PROTOCOL_VERSION,
            id: MessageId::new(),
            room,
            sender,
            sender_device,
            sent_at_ms,
            payload,
            franking_commitment: None,
        };
        envelope.validate_for_tier(tier)?;
        Ok(envelope)
    }

    /// Attach a franking commitment.
    pub fn with_franking_commitment(mut self, commitment: impl Into<String>) -> Self {
        self.franking_commitment = Some(commitment.into());
        self
    }

    /// Re-check the tier/payload invariant.
    ///
    /// The server must call this on every received envelope. A client that sends
    /// plaintext into an E2EE room is either broken or hostile — per
    /// `docs/01-threat-model.md` §7 we assume modified clients exist, so this is
    /// enforced server-side and not merely at construction.
    pub const fn validate_for_tier(&self, tier: Tier) -> Result<(), EnvelopeError> {
        if tier.is_e2ee() && !self.payload.is_opaque_to_server() {
            return Err(EnvelopeError::PlaintextInEncryptedRoom);
        }
        Ok(())
    }
}

/// Hex encoding for byte fields, so envelopes stay readable in logs and fixtures.
///
/// A binary wire format will replace this before the protocol freezes; JSON plus hex is
/// a development convenience, not the intended encoding.
mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        hex::decode(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ct() -> EnvelopePayload {
        EnvelopePayload::MlsApplication { ciphertext: vec![1, 2, 3] }
    }

    fn pt() -> EnvelopePayload {
        EnvelopePayload::Plaintext { body: "hello".into() }
    }

    fn build(tier: Tier, payload: EnvelopePayload) -> Result<Envelope, EnvelopeError> {
        Envelope::new(tier, RoomId::new(), UserId::new(), DeviceId::new(), 0, payload)
    }

    #[test]
    fn ciphertext_is_accepted_in_encrypted_rooms() {
        assert!(build(Tier::Private, ct()).is_ok());
        assert!(build(Tier::PrivateCommunity, ct()).is_ok());
    }

    #[test]
    fn plaintext_is_rejected_in_encrypted_rooms() {
        // The invariant that makes the T1/T2 badge mean something.
        assert_eq!(build(Tier::Private, pt()), Err(EnvelopeError::PlaintextInEncryptedRoom));
        assert_eq!(
            build(Tier::PrivateCommunity, pt()),
            Err(EnvelopeError::PlaintextInEncryptedRoom)
        );
    }

    #[test]
    fn public_rooms_accept_both() {
        assert!(build(Tier::PublicCommunity, pt()).is_ok());
        assert!(build(Tier::PublicCommunity, ct()).is_ok());
    }

    #[test]
    fn server_side_validation_catches_a_hostile_client() {
        // Simulates a modified client hand-rolling the struct to smuggle plaintext into
        // an encrypted room. The server re-validates and rejects it.
        let smuggled = Envelope {
            version: crate::PROTOCOL_VERSION,
            id: MessageId::new(),
            room: RoomId::new(),
            sender: UserId::new(),
            sender_device: DeviceId::new(),
            sent_at_ms: 0,
            payload: pt(),
            franking_commitment: None,
        };
        assert_eq!(
            smuggled.validate_for_tier(Tier::Private),
            Err(EnvelopeError::PlaintextInEncryptedRoom)
        );
    }

    #[test]
    fn envelope_roundtrips_through_json() {
        let e = build(Tier::Private, ct()).unwrap().with_franking_commitment("abcd");
        let json = serde_json::to_string(&e).unwrap();
        let back: Envelope = serde_json::from_str(&json).unwrap();
        assert_eq!(e, back);
        assert_eq!(back.franking_commitment.as_deref(), Some("abcd"));
    }

    #[test]
    fn handshake_is_opaque_but_sequenced() {
        let h = EnvelopePayload::MlsHandshake { message: vec![9], epoch_seq: Some(7) };
        assert!(h.is_opaque_to_server());
    }
}
