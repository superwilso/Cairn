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
    /// Hex signature over [`Envelope::signing_bytes`], made by the sending device's key.
    ///
    /// This is what makes `sender` and `sender_device` claims rather than assertions the
    /// server has to take on faith. Without it the franking tag is worthless: a tag binds
    /// a commitment to a *claimed* sender, so if anyone may claim to be anyone, the tag
    /// proves nothing and unframeability collapses.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
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
            signature: None,
        };
        envelope.validate_for_tier(tier)?;
        Ok(envelope)
    }

    /// Attach a franking commitment.
    pub fn with_franking_commitment(mut self, commitment: impl Into<String>) -> Self {
        self.franking_commitment = Some(commitment.into());
        self
    }

    /// Attach a signature.
    pub fn with_signature(mut self, signature: impl Into<String>) -> Self {
        self.signature = Some(signature.into());
        self
    }

    /// The exact bytes a sender signs and the server verifies.
    ///
    /// Built by explicit length-prefixed concatenation rather than by serialising the
    /// struct. Serialisation formats are free to reorder fields or change encodings
    /// between versions; a signature scheme whose input can shift underneath it is a
    /// signature scheme that silently stops working — or worse, one where two different
    /// envelopes can produce identical signing input.
    ///
    /// Covers every field the server acts on. The signature itself is excluded, obviously.
    pub fn signing_bytes(&self) -> Vec<u8> {
        fn push(out: &mut Vec<u8>, bytes: &[u8]) {
            out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
            out.extend_from_slice(bytes);
        }

        let mut out = Vec::new();
        push(&mut out, b"cairn/envelope/v1");
        out.extend_from_slice(&self.version.to_be_bytes());
        push(&mut out, self.id.as_uuid().as_bytes());
        push(&mut out, self.room.as_uuid().as_bytes());
        push(&mut out, self.sender.as_uuid().as_bytes());
        push(&mut out, self.sender_device.as_uuid().as_bytes());
        out.extend_from_slice(&self.sent_at_ms.to_be_bytes());

        // A discriminant so a payload of one kind can never be reinterpreted as another
        // with the same bytes.
        match &self.payload {
            EnvelopePayload::MlsApplication { ciphertext } => {
                out.push(1);
                push(&mut out, ciphertext);
            }
            EnvelopePayload::MlsHandshake { message, epoch_seq } => {
                out.push(2);
                push(&mut out, message);
                out.extend_from_slice(&epoch_seq.unwrap_or(0).to_be_bytes());
            }
            EnvelopePayload::Plaintext { body } => {
                out.push(3);
                push(&mut out, body.as_bytes());
            }
        }

        match &self.franking_commitment {
            Some(c) => {
                out.push(1);
                push(&mut out, c.as_bytes());
            }
            None => out.push(0),
        }
        out
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
            signature: None,
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
    fn signing_bytes_are_stable_and_cover_every_acted_on_field() {
        let e = build(Tier::Private, ct()).unwrap();
        assert_eq!(e.signing_bytes(), e.signing_bytes(), "must be deterministic");

        // Changing any covered field must change the signed input, or that field is
        // unauthenticated and an attacker can rewrite it in transit.
        let mut other = e.clone();
        other.sender = UserId::new();
        assert_ne!(e.signing_bytes(), other.signing_bytes(), "sender must be covered");

        let mut other = e.clone();
        other.room = RoomId::new();
        assert_ne!(e.signing_bytes(), other.signing_bytes(), "room must be covered");

        let mut other = e.clone();
        other.sender_device = DeviceId::new();
        assert_ne!(e.signing_bytes(), other.signing_bytes(), "device must be covered");

        let mut other = e.clone();
        other.sent_at_ms = 999;
        assert_ne!(e.signing_bytes(), other.signing_bytes(), "timestamp must be covered");

        let mut other = e.clone();
        other.payload = EnvelopePayload::MlsApplication { ciphertext: vec![9, 9, 9] };
        assert_ne!(e.signing_bytes(), other.signing_bytes(), "payload must be covered");

        let other = e.clone().with_franking_commitment("abcd");
        assert_ne!(e.signing_bytes(), other.signing_bytes(), "commitment must be covered");
    }

    #[test]
    fn the_signature_itself_is_not_signed() {
        // Otherwise signing would be circular and could never verify.
        let e = build(Tier::Private, ct()).unwrap();
        let signed = e.clone().with_signature("deadbeef");
        assert_eq!(e.signing_bytes(), signed.signing_bytes());
    }

    #[test]
    fn length_prefixing_prevents_field_boundary_confusion() {
        // Without length prefixes, two different (room, sender) pairs could concatenate
        // to the same bytes and share a signature.
        let a = Envelope::new(
            Tier::PublicCommunity,
            RoomId::new(),
            UserId::new(),
            DeviceId::new(),
            0,
            EnvelopePayload::Plaintext { body: "ab".into() },
        )
        .unwrap();
        let mut b = a.clone();
        b.payload = EnvelopePayload::Plaintext { body: "a".into() };
        assert_ne!(a.signing_bytes(), b.signing_bytes());
    }

    #[test]
    fn handshake_is_opaque_but_sequenced() {
        let h = EnvelopePayload::MlsHandshake { message: vec![9], epoch_seq: Some(7) };
        assert!(h.is_opaque_to_server());
    }
}

/// Canonical bytes a device signs to authorize *another* device to join its account.
///
/// Adding a device to an existing account must be authorized by a device that already
/// belongs to it. Without this, anyone who learns a user id — which is public, it appears
/// on every message that account sends — can register their own device against it and
/// speak as that account.
///
/// Length-prefixed for the same reason as [`Envelope::signing_bytes`]: so no two distinct
/// authorizations can share a byte encoding.
pub fn device_authorization_bytes(
    user: crate::UserId,
    new_device: crate::DeviceId,
    new_public_key: &[u8],
) -> Vec<u8> {
    fn push(out: &mut Vec<u8>, bytes: &[u8]) {
        out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
        out.extend_from_slice(bytes);
    }
    let mut out = Vec::new();
    push(&mut out, b"cairn/device-authorization/v1");
    push(&mut out, user.as_uuid().as_bytes());
    push(&mut out, new_device.as_uuid().as_bytes());
    push(&mut out, new_public_key);
    out
}

/// What a signed request acts on.
///
/// A request that names no resource authorizes only the action, so a signature captured
/// from one call can be replayed against any other call with the same action inside the
/// replay window. Endpoints that act on a specific thing must therefore name it here —
/// which is why this is not just `RoomId`: claiming a key package targets a *user*, and
/// binding it as "no resource" would let a captured claim be redirected at anyone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceRef {
    Room(crate::RoomId),
    User(crate::UserId),
    Device(crate::DeviceId),
    Blob(crate::BlobId),
}

impl ResourceRef {
    /// A stable label, signed alongside the id so two kinds cannot be confused.
    pub const fn kind(self) -> &'static str {
        match self {
            ResourceRef::Room(_) => "room",
            ResourceRef::User(_) => "user",
            ResourceRef::Device(_) => "device",
            ResourceRef::Blob(_) => "blob",
        }
    }

    pub fn uuid(&self) -> &uuid::Uuid {
        match self {
            ResourceRef::Room(id) => id.as_uuid(),
            ResourceRef::User(id) => id.as_uuid(),
            ResourceRef::Device(id) => id.as_uuid(),
            ResourceRef::Blob(id) => id.as_uuid(),
        }
    }
}

impl From<crate::RoomId> for ResourceRef {
    fn from(id: crate::RoomId) -> Self {
        ResourceRef::Room(id)
    }
}

impl From<crate::UserId> for ResourceRef {
    fn from(id: crate::UserId) -> Self {
        ResourceRef::User(id)
    }
}

impl From<crate::DeviceId> for ResourceRef {
    fn from(id: crate::DeviceId) -> Self {
        ResourceRef::Device(id)
    }
}

impl From<crate::BlobId> for ResourceRef {
    fn from(id: crate::BlobId) -> Self {
        ResourceRef::Blob(id)
    }
}

/// Canonical bytes a device signs to authenticate a request that is not a message.
///
/// Messages authenticate themselves via [`Envelope::signing_bytes`]. Everything else —
/// reading a room's history, creating a room, joining one — had no authentication at all,
/// which meant membership could be enforced in the state layer and then trivially
/// bypassed by lying at the HTTP boundary.
///
/// `issued_at_ms` bounds replay: the server rejects requests outside a window. It is not a
/// nonce, so a captured request can be replayed inside that window; that is an accepted
/// limitation for read operations and is documented in `SECURITY.md`.
pub fn request_signing_bytes(
    action: &str,
    resource: Option<ResourceRef>,
    issued_at_ms: i64,
) -> Vec<u8> {
    fn push(out: &mut Vec<u8>, bytes: &[u8]) {
        out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
        out.extend_from_slice(bytes);
    }
    let mut out = Vec::new();
    push(&mut out, b"cairn/request/v1");
    push(&mut out, action.as_bytes());
    match resource {
        Some(r) => {
            out.push(1);
            // The kind is signed as well as the id. Without it a room and a user that
            // happened to share a UUID would produce identical bytes, and more usefully,
            // an authorization naming one kind of resource could be replayed against
            // another endpoint that names a different kind.
            push(&mut out, r.kind().as_bytes());
            push(&mut out, r.uuid().as_bytes());
        }
        None => out.push(0),
    }
    out.extend_from_slice(&issued_at_ms.to_be_bytes());
    out
}

#[cfg(test)]
mod request_auth_tests {
    use super::*;

    #[test]
    fn request_signing_covers_action_resource_and_time() {
        let room = RoomId::new();
        let base = request_signing_bytes("read", Some(room.into()), 1_000);
        assert_eq!(base, request_signing_bytes("read", Some(room.into()), 1_000));
        // An authorization to read must not also authorize a write.
        assert_ne!(base, request_signing_bytes("write", Some(room.into()), 1_000));
        // …nor the same action against a different room.
        assert_ne!(base, request_signing_bytes("read", Some(RoomId::new().into()), 1_000));
        assert_ne!(base, request_signing_bytes("read", None, 1_000));
        assert_ne!(base, request_signing_bytes("read", Some(room.into()), 2_000));
    }

    #[test]
    fn a_resource_kind_is_part_of_the_authorization() {
        // Same uuid, different kind of thing. Without the kind in the signed bytes, an
        // authorization to act on a room could be replayed against a user endpoint.
        let id = uuid::Uuid::new_v4();
        let as_room = request_signing_bytes("claim", Some(RoomId::from_uuid(id).into()), 1);
        let as_user = request_signing_bytes("claim", Some(crate::UserId::from_uuid(id).into()), 1);
        let as_device =
            request_signing_bytes("claim", Some(crate::DeviceId::from_uuid(id).into()), 1);
        assert_ne!(as_room, as_user);
        assert_ne!(as_user, as_device);
        assert_ne!(as_room, as_device);
    }

    #[test]
    fn a_signature_for_one_target_does_not_authorize_another() {
        // The property the key package endpoints depend on: a claim signed against one
        // account must not be redirectable at a different account inside the replay
        // window.
        let victim = crate::UserId::new();
        let bystander = crate::UserId::new();
        assert_ne!(
            request_signing_bytes("claim_key_packages", Some(victim.into()), 1),
            request_signing_bytes("claim_key_packages", Some(bystander.into()), 1)
        );
    }

    #[test]
    fn action_boundaries_cannot_be_confused() {
        // Without length prefixes "read" + room could collide with "readroom" + nothing.
        assert_ne!(request_signing_bytes("read", None, 0), request_signing_bytes("rea", None, 0));
    }
}

#[cfg(test)]
mod device_auth_tests {
    use super::*;

    #[test]
    fn authorization_covers_every_field() {
        let user = UserId::new();
        let device = DeviceId::new();
        let key = b"public-key-bytes";
        let base = device_authorization_bytes(user, device, key);

        assert_eq!(base, device_authorization_bytes(user, device, key), "deterministic");
        assert_ne!(base, device_authorization_bytes(UserId::new(), device, key), "user covered");
        assert_ne!(base, device_authorization_bytes(user, DeviceId::new(), key), "device covered");
        assert_ne!(base, device_authorization_bytes(user, device, b"other-key"), "key covered");
    }

    #[test]
    fn an_authorization_cannot_be_replayed_for_a_different_device() {
        // The signature is over the specific new device and key, so an attacker who
        // captures one cannot reuse it to attach a device of their own.
        let user = UserId::new();
        let honest = device_authorization_bytes(user, DeviceId::new(), b"k1");
        let attacker = device_authorization_bytes(user, DeviceId::new(), b"k2");
        assert_ne!(honest, attacker);
    }
}
