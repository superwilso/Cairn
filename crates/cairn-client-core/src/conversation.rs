//! A conversation: MLS session, franking chain, and tier enforcement in one place.
//!
//! This is the type a platform UI drives. It deliberately owns the franking chain so that
//! a client cannot forget to maintain it — a message sent without a commitment is a
//! message that can never be reported.

use std::sync::Arc;

use serde::{Deserialize, Serialize};

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
    #[error("encrypted message carried no franking commitment")]
    MissingCommitment,
    #[error("franking commitment does not open to the decrypted message")]
    CommitmentMismatch,
    #[error("could not encode or decode the message body: {0}")]
    Encoding(#[from] serde_json::Error),
}

/// A message ready to hand to the transport, plus the opening the sender must retain.
#[derive(Debug)]
pub struct OutboundMessage {
    pub envelope: Envelope,
    /// The franking opening, as retained by the *sender*.
    ///
    /// Recipients get their own copy from inside the encrypted body — see [`InnerBody`].
    /// This copy never goes to the server.
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
    /// The device identity, retained so outbound envelopes can be signed.
    ///
    /// Held here rather than passed per call so a platform UI cannot send an unsigned
    /// message by forgetting an argument. The server rejects unsigned envelopes, and an
    /// unsigned message would be unattributable — franking would have nothing to bind to.
    session: Arc<Session>,
    group: Option<GroupHandle>,
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
        session: Arc<Session>,
    ) -> Result<Self, ConversationError> {
        if !seal.tier().is_e2ee() {
            return Err(ConversationError::NotEncrypted);
        }
        let group = session.create_group()?;
        Ok(Self { seal, room: RoomId::new(), user, device, session, group: Some(group) })
    }

    /// Join an existing encrypted conversation, having accepted an MLS welcome.
    ///
    /// A joiner has no access to prior messages — MLS deliberately does not grant it, and
    /// franking must not invent it. The server owns the franking chain, so a joiner simply
    /// starts reporting from the messages it can actually decrypt.
    pub fn join_encrypted(
        seal: RoomSeal,
        room: RoomId,
        user: UserId,
        device: DeviceId,
        session: Arc<Session>,
        group: GroupHandle,
    ) -> Result<Self, ConversationError> {
        if !seal.tier().is_e2ee() {
            return Err(ConversationError::NotEncrypted);
        }
        Ok(Self { seal, room, user, device, session, group: Some(group) })
    }

    /// Open a public (T3) conversation. No MLS group; the server reads content.
    pub fn create_public(
        seal: RoomSeal,
        user: UserId,
        device: DeviceId,
        session: Arc<Session>,
    ) -> Result<Self, ConversationError> {
        if seal.tier().is_e2ee() {
            return Err(ConversationError::Encrypted);
        }
        Ok(Self { seal, room: RoomId::new(), user, device, session, group: None })
    }

    /// Sign an outbound envelope with this device's key.
    ///
    /// Every send path goes through here; there is no way to emit an unsigned envelope.
    fn sign(&self, envelope: Envelope) -> Result<Envelope, ConversationError> {
        let signature = self.session.sign(&envelope.signing_bytes())?;
        Ok(envelope.with_signature(hex::encode(signature)))
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

        let (commitment, opening) = franking::commit(plaintext);

        // The opening travels *inside* the encrypted body, never beside it. A recipient
        // cannot file a report without it, and the server must never see it — a server
        // holding openings could verify reports nobody chose to make, which would defeat
        // the point of franking.
        let inner = InnerBody { body: plaintext.to_vec(), opening: opening.clone() };
        let encoded = serde_json::to_vec(&inner).map_err(ConversationError::Encoding)?;
        let mls_message = group.encrypt(&encoded)?;
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
        let envelope = self.sign(envelope)?;
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
        let envelope = Envelope::new(
            tier,
            self.room,
            self.user,
            self.device,
            now_ms,
            EnvelopePayload::Plaintext { body: body.to_owned() },
        )?;
        self.sign(envelope)
    }

    /// Decrypt an incoming envelope, verify its franking commitment, and advance the chain.
    ///
    /// The commitment check is a real defence, not bookkeeping. It proves the commitment
    /// the server tagged is the one that opens to the text actually displayed. Without it,
    /// a sender could have the server tag a commitment for one message while showing the
    /// recipient another — making the recipient's future report fail to verify, and
    /// leaving them unable to prove what they were sent.
    pub fn receive(
        &mut self,
        envelope: &Envelope,
    ) -> Result<Option<ReceivedMessage>, ConversationError> {
        match &envelope.payload {
            EnvelopePayload::Plaintext { body } => {
                Ok(Some(ReceivedMessage { body: body.clone().into_bytes(), franking: None }))
            }
            EnvelopePayload::MlsApplication { ciphertext }
            | EnvelopePayload::MlsHandshake { message: ciphertext, .. } => {
                let group = self.group.as_mut().ok_or(MlsError::NoGroup)?;
                let msg = cairn_crypto::mls::parse_message(ciphertext)?;
                let Some(decrypted) = group.process(msg)? else {
                    // A handshake message: group state advanced, no application content.
                    return Ok(None);
                };

                let inner: InnerBody =
                    serde_json::from_slice(&decrypted).map_err(ConversationError::Encoding)?;

                let claimed = envelope
                    .franking_commitment
                    .as_deref()
                    .and_then(decode_commitment)
                    .ok_or(ConversationError::MissingCommitment)?;

                if !franking::verify_commitment(&inner.body, &inner.opening, &claimed) {
                    return Err(ConversationError::CommitmentMismatch);
                }

                Ok(Some(ReceivedMessage {
                    body: inner.body,
                    franking: Some(ReceivedFranking {
                        opening: inner.opening,
                        commitment: claimed,
                    }),
                }))
            }
        }
    }
}

/// What actually gets encrypted: the message and its franking opening.
#[derive(Debug, Serialize, Deserialize)]
struct InnerBody {
    body: Vec<u8>,
    opening: Opening,
}

/// A decrypted message plus the material needed to report it later.
#[derive(Debug)]
pub struct ReceivedMessage {
    pub body: Vec<u8>,
    /// Present for E2EE messages. A recipient must retain this to file a report; without
    /// it the message is unreportable.
    pub franking: Option<ReceivedFranking>,
}

/// Franking material a recipient retains so a message can be reported later.
#[derive(Debug)]
pub struct ReceivedFranking {
    pub opening: Opening,
    pub commitment: Commitment,
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
        let session = Arc::new(Session::new(b"alice").unwrap());
        let mut convo = Conversation::create_encrypted(
            dm_seal(),
            UserId::new(),
            DeviceId::new(),
            session.clone(),
        )
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
    fn each_message_gets_a_distinct_opening_and_commitment() {
        // Ordering is attested by the server, not the sender, so a commitment binds only
        // its own message. Each send must still be independently openable.
        let session = Arc::new(Session::new(b"alice").unwrap());
        let mut convo = Conversation::create_encrypted(
            dm_seal(),
            UserId::new(),
            DeviceId::new(),
            session.clone(),
        )
        .unwrap();

        let first = convo.send(b"one", 1).unwrap();
        let second = convo.send(b"two", 2).unwrap();
        assert_ne!(first.commitment, second.commitment);

        assert_eq!(franking::commit_with_opening(b"one", &first.opening), first.commitment);
        assert_eq!(franking::commit_with_opening(b"two", &second.opening), second.commitment);
        // An opening must not open a different message.
        assert_ne!(franking::commit_with_opening(b"two", &first.opening), second.commitment);
    }

    #[test]
    fn tier_mismatch_is_refused_in_both_directions() {
        let session = Arc::new(Session::new(b"alice").unwrap());
        let mut encrypted = Conversation::create_encrypted(
            dm_seal(),
            UserId::new(),
            DeviceId::new(),
            session.clone(),
        )
        .unwrap();
        assert!(matches!(encrypted.send_plaintext("oops", 0), Err(ConversationError::Encrypted)));

        let mut public = Conversation::create_public(
            public_seal(),
            UserId::new(),
            DeviceId::new(),
            Arc::new(Session::new(b"pub").unwrap()),
        )
        .unwrap();
        assert!(matches!(public.send(b"oops", 0), Err(ConversationError::NotEncrypted)));
    }

    #[test]
    fn cannot_create_encrypted_conversation_for_a_public_room() {
        let session = Arc::new(Session::new(b"alice").unwrap());
        assert!(matches!(
            Conversation::create_encrypted(
                public_seal(),
                UserId::new(),
                DeviceId::new(),
                session.clone()
            ),
            Err(ConversationError::NotEncrypted)
        ));
    }

    /// Wire two conversations together over a shared MLS group.
    fn linked_pair() -> (Conversation, Conversation) {
        let alice_session = Arc::new(Session::new(b"alice").unwrap());
        let bob_session = Arc::new(Session::new(b"bob").unwrap());

        let mut alice = Conversation::create_encrypted(
            dm_seal(),
            UserId::new(),
            DeviceId::new(),
            alice_session.clone(),
        )
        .unwrap();

        let commit =
            alice.group_mut().unwrap().add_member(bob_session.key_package().unwrap()).unwrap();
        let bob_group = bob_session.join(&commit.welcome.unwrap()).unwrap();

        let bob = Conversation::join_encrypted(
            dm_seal(),
            alice.room(),
            UserId::new(),
            DeviceId::new(),
            bob_session.clone(),
            bob_group,
        )
        .unwrap();

        (alice, bob)
    }

    #[test]
    fn round_trip_delivers_body_and_franking_material() {
        let (mut alice, mut bob) = linked_pair();

        let sent = alice.send(b"hello bob", 1_000).unwrap();
        let received = bob.receive(&sent.envelope).unwrap().expect("an application message");

        assert_eq!(received.body, b"hello bob");
        let franking = received.franking.expect("E2EE messages must carry franking material");
        assert_eq!(franking.commitment, sent.commitment);
    }

    #[test]
    fn recipient_rejects_a_commitment_that_does_not_open_to_the_message() {
        // Without this check a sender could have the server tag one commitment while
        // showing the recipient different text, leaving the recipient unable to prove
        // what they actually received.
        let (mut alice, mut bob) = linked_pair();

        let mut sent = alice.send(b"innocuous", 1).unwrap();
        let (bogus, _) = franking::commit(b"something else entirely");
        sent.envelope.franking_commitment = Some(bogus.to_hex());

        assert!(matches!(bob.receive(&sent.envelope), Err(ConversationError::CommitmentMismatch)));
    }

    #[test]
    fn a_recipient_can_build_a_report_that_verifies() {
        // The end-to-end property the whole franking design exists for: a recipient who
        // only ever saw ciphertext plus an in-envelope opening can produce evidence the
        // server verifies.
        use cairn_crypto::franking::{Context, ReportedMessage, ServerFrankingKey};
        use cairn_crypto::TranscriptReport;

        let (mut alice, mut bob) = linked_pair();
        let server_key = ServerFrankingKey::generate();

        let mut reported = Vec::new();
        let mut prev = None;
        for (i, text) in [&b"first"[..], &b"second"[..], &b"third"[..]].iter().enumerate() {
            let sent = alice.send(text, i as i64).unwrap();

            // The server tags what it can see — the commitment, never the plaintext — and
            // supplies the chain, since only it knows the true order.
            let context = Context {
                commitment: sent.commitment,
                room: sent.envelope.room,
                sender: sent.envelope.sender,
                sender_device: sent.envelope.sender_device,
                server_seq: i as u64 + 1,
                prev_commitment: prev,
            };
            let tag = server_key.tag(&context);
            prev = Some(sent.commitment);

            let got = bob.receive(&sent.envelope).unwrap().unwrap();
            let franking = got.franking.unwrap();

            reported.push(ReportedMessage {
                plaintext: got.body,
                opening: franking.opening,
                context,
                tag,
            });
        }

        let report = TranscriptReport { messages: reported };
        assert_eq!(report.verify(&server_key), Ok(()));
    }

    #[test]
    fn public_conversation_sends_plaintext() {
        let mut convo = Conversation::create_public(
            public_seal(),
            UserId::new(),
            DeviceId::new(),
            Arc::new(Session::new(b"pub").unwrap()),
        )
        .unwrap();
        let env = convo.send_plaintext("hello world", 5).unwrap();
        assert!(!env.payload.is_opaque_to_server());
        assert_eq!(env.franking_commitment, None);
    }
}
