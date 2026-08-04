//! A conversation: MLS session, franking chain, and tier enforcement in one place.
//!
//! This is the type a platform UI drives. It deliberately owns the franking chain so that
//! a client cannot forget to maintain it — a message sent without a commitment is a
//! message that can never be reported.

use cairn_crypto::franking::{self, Commitment, Opening};
use cairn_crypto::mls::{GroupHandle, MlsError, Session};
use cairn_proto::{DeviceId, Envelope, EnvelopePayload, RoomId, RoomSeal, Tier, UserId};

#[derive(Debug, thiserror::Error)]
pub enum ConversationError {
    #[error(transparent)]
    Mls(#[from] MlsError),
    #[error(transparent)]
    Envelope(#[from] cairn_proto::envelope::EnvelopeError),
    #[error("this conversation is not end-to-end encrypted; use send_plaintext")]
    NotEncrypted,
    #[error("this conversation is end-to-end encrypted; use send")]
    Encrypted,
}

/// A message ready to hand to the transport, plus the opening the sender must retain.
#[derive(Debug)]
pub struct OutboundMessage {
    pub envelope: Envelope,
    /// The franking opening.
    ///
    /// Delivered to recipients **inside the encrypted payload**, never to the server.
    /// In this scaffold it is returned alongside so the send path is testable; wiring it
    /// into the encrypted body is tracked in `docs/03-protocol-evaluation.md`.
    pub opening: Opening,
    /// The commitment for this message, which becomes the next message's `prev`.
    pub commitment: Commitment,
}

/// One conversation from a single device's point of view.
pub struct Conversation {
    seal: RoomSeal,
    room: RoomId,
    user: UserId,
    device: DeviceId,
    group: Option<GroupHandle>,
    /// Tail of the franking hash chain. `None` before the first message.
    prev_commitment: Option<Commitment>,
}

impl std::fmt::Debug for Conversation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Conversation")
            .field("room", &self.room)
            .field("tier", &self.seal.tier().label())
            .field("encrypted", &self.seal.tier().is_e2ee())
            .finish()
    }
}

impl Conversation {
    /// Open an encrypted (T1/T2) conversation, creating the MLS group.
    pub fn create_encrypted(
        seal: RoomSeal,
        user: UserId,
        device: DeviceId,
        session: &Session,
    ) -> Result<Self, ConversationError> {
        if !seal.tier().is_e2ee() {
            return Err(ConversationError::NotEncrypted);
        }
        Ok(Self {
            seal,
            room: RoomId::new(),
            user,
            device,
            group: Some(session.create_group()?),
            prev_commitment: None,
        })
    }

    /// Open a public (T3) conversation. No MLS group; the server reads content.
    pub fn create_public(
        seal: RoomSeal,
        user: UserId,
        device: DeviceId,
    ) -> Result<Self, ConversationError> {
        if seal.tier().is_e2ee() {
            return Err(ConversationError::Encrypted);
        }
        Ok(Self { seal, room: RoomId::new(), user, device, group: None, prev_commitment: None })
    }

    pub const fn tier(&self) -> Tier {
        self.seal.tier()
    }

    pub const fn room(&self) -> RoomId {
        self.room
    }

    /// Attach an existing MLS group (e.g. after joining from a welcome).
    pub fn with_group(mut self, group: GroupHandle) -> Self {
        self.group = Some(group);
        self
    }

    pub fn group_mut(&mut self) -> Option<&mut GroupHandle> {
        self.group.as_mut()
    }

    /// Encrypt and frank a message.
    ///
    /// Franking and encryption happen together and cannot be separated by a caller —
    /// there is no code path that produces an unfrankable encrypted message.
    pub fn send(
        &mut self,
        plaintext: &[u8],
        now_ms: i64,
    ) -> Result<OutboundMessage, ConversationError> {
        let tier = self.seal.tier();
        if !tier.is_e2ee() {
            return Err(ConversationError::NotEncrypted);
        }
        let group = self.group.as_mut().ok_or(MlsError::NoGroup)?;

        let (commitment, opening) = franking::commit(plaintext, self.prev_commitment.as_ref());
        let mls_message = group.encrypt(plaintext)?;
        let ciphertext = mls_message.to_bytes().map_err(MlsError::from)?;

        let envelope = Envelope::new(
            tier,
            self.room,
            self.user,
            self.device,
            now_ms,
            EnvelopePayload::MlsApplication { ciphertext },
        )?
        .with_franking_commitment(commitment.to_hex());

        self.prev_commitment = Some(commitment);
        Ok(OutboundMessage { envelope, opening, commitment })
    }

    /// Send plaintext in a T3 conversation.
    pub fn send_plaintext(
        &mut self,
        body: &str,
        now_ms: i64,
    ) -> Result<Envelope, ConversationError> {
        let tier = self.seal.tier();
        if tier.is_e2ee() {
            return Err(ConversationError::Encrypted);
        }
        Ok(Envelope::new(
            tier,
            self.room,
            self.user,
            self.device,
            now_ms,
            EnvelopePayload::Plaintext { body: body.to_owned() },
        )?)
    }

    /// Decrypt an incoming envelope, advancing the local franking chain.
    pub fn receive(&mut self, envelope: &Envelope) -> Result<Option<Vec<u8>>, ConversationError> {
        match &envelope.payload {
            EnvelopePayload::Plaintext { body } => Ok(Some(body.clone().into_bytes())),
            EnvelopePayload::MlsApplication { ciphertext }
            | EnvelopePayload::MlsHandshake { message: ciphertext, .. } => {
                let group = self.group.as_mut().ok_or(MlsError::NoGroup)?;
                let msg = cairn_crypto::mls::parse_message(ciphertext)?;
                let out = group.process(msg)?;
                if let Some(hex) = &envelope.franking_commitment {
                    if let Some(c) = decode_commitment(hex) {
                        self.prev_commitment = Some(c);
                    }
                }
                Ok(out)
            }
        }
    }
}

fn decode_commitment(hex_str: &str) -> Option<Commitment> {
    let bytes = hex::decode(hex_str).ok()?;
    let arr: [u8; 32] = bytes.try_into().ok()?;
    Some(Commitment(arr))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cairn_proto::RoomShape;

    fn dm_seal() -> RoomSeal {
        RoomSeal::new(RoomShape {
            is_direct: true,
            is_publicly_discoverable: false,
            member_ceiling: 2,
        })
        .unwrap()
    }

    fn public_seal() -> RoomSeal {
        RoomSeal::new(RoomShape {
            is_direct: false,
            is_publicly_discoverable: true,
            member_ceiling: 50_000,
        })
        .unwrap()
    }

    #[test]
    fn encrypted_conversation_produces_franked_ciphertext() {
        let session = Session::new(b"alice").unwrap();
        let mut convo =
            Conversation::create_encrypted(dm_seal(), UserId::new(), DeviceId::new(), &session)
                .unwrap();

        let out = convo.send(b"hello", 1_000).unwrap();
        assert!(out.envelope.payload.is_opaque_to_server());
        assert!(out.envelope.franking_commitment.is_some());
        assert_eq!(
            out.envelope.franking_commitment.as_deref(),
            Some(out.commitment.to_hex()).as_deref()
        );
    }

    #[test]
    fn franking_chain_advances_across_messages() {
        // Each message must commit to its predecessor, or transcript reports cannot
        // prove ordering later.
        let session = Session::new(b"alice").unwrap();
        let mut convo =
            Conversation::create_encrypted(dm_seal(), UserId::new(), DeviceId::new(), &session)
                .unwrap();

        let first = convo.send(b"one", 1).unwrap();
        let second = convo.send(b"two", 2).unwrap();
        assert_ne!(first.commitment, second.commitment);

        // The second message's commitment must be reproducible only with the first as prev.
        let recomputed =
            franking::commit_with_opening(b"two", Some(&first.commitment), &second.opening);
        assert_eq!(recomputed, second.commitment);
        let wrong = franking::commit_with_opening(b"two", None, &second.opening);
        assert_ne!(wrong, second.commitment);
    }

    #[test]
    fn tier_mismatch_is_refused_in_both_directions() {
        let session = Session::new(b"alice").unwrap();
        let mut encrypted =
            Conversation::create_encrypted(dm_seal(), UserId::new(), DeviceId::new(), &session)
                .unwrap();
        assert!(matches!(encrypted.send_plaintext("oops", 0), Err(ConversationError::Encrypted)));

        let mut public =
            Conversation::create_public(public_seal(), UserId::new(), DeviceId::new()).unwrap();
        assert!(matches!(public.send(b"oops", 0), Err(ConversationError::NotEncrypted)));
    }

    #[test]
    fn cannot_create_encrypted_conversation_for_a_public_room() {
        let session = Session::new(b"alice").unwrap();
        assert!(matches!(
            Conversation::create_encrypted(public_seal(), UserId::new(), DeviceId::new(), &session),
            Err(ConversationError::NotEncrypted)
        ));
    }

    #[test]
    fn public_conversation_sends_plaintext() {
        let mut convo =
            Conversation::create_public(public_seal(), UserId::new(), DeviceId::new()).unwrap();
        let env = convo.send_plaintext("hello world", 5).unwrap();
        assert!(!env.payload.is_opaque_to_server());
        assert_eq!(env.franking_commitment, None);
    }
}
