//! A conversation: MLS session, franking chain, and tier enforcement in one place.
//!
//! This is the type a platform UI drives. It deliberately owns the franking chain so that
//! a client cannot forget to maintain it — a message sent without a commitment is a
//! message that can never be reported.

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use cairn_crypto::franking::{self, Commitment, Opening};
use cairn_crypto::mls::{GroupEvent, GroupHandle, GroupMember, MlsError, Session};
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
    /// Recipients get their own copy from inside the encrypted body, so both ends can
    /// report the same message. This copy never goes to the server.
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
    ///
    /// `room` is the id the **server** assigned when the room was created. This used to
    /// mint its own, which worked only because the vertical slice faked the server
    /// in-process; against a real one every message was addressed to a room that did not
    /// exist and came back `404 no such room`. A conversation cannot invent its own room
    /// id, so it does not get the chance to.
    pub fn create_encrypted(
        seal: RoomSeal,
        room: RoomId,
        user: UserId,
        device: DeviceId,
        session: Arc<Session>,
    ) -> Result<Self, ConversationError> {
        if !seal.tier().is_e2ee() {
            return Err(ConversationError::NotEncrypted);
        }
        let group = session.create_group()?;
        Ok(Self { seal, room, user, device, session, group: Some(group) })
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

    /// Resume an encrypted conversation whose MLS group is already on disk.
    ///
    /// `room` must be the id the **server** knows, not a fresh one: a resumed conversation
    /// that minted its own id would post into a room nobody else is reading, and its
    /// franking chain would not line up with the server's. That is why this takes the room
    /// id rather than generating one the way [`Conversation::create_encrypted`] does.
    ///
    /// Requires a session opened with [`Session::open`]; an in-memory session has nothing
    /// to load.
    pub fn resume_encrypted(
        seal: RoomSeal,
        room: RoomId,
        user: UserId,
        device: DeviceId,
        session: Arc<Session>,
        group_id: &[u8],
    ) -> Result<Self, ConversationError> {
        if !seal.tier().is_e2ee() {
            return Err(ConversationError::NotEncrypted);
        }
        let group = session.load_group(group_id)?;
        Ok(Self { seal, room, user, device, session, group: Some(group) })
    }

    /// The MLS group id backing this conversation, if it is encrypted.
    ///
    /// A client persists this against the room id so it can find the group again after a
    /// restart — see [`crate::store::ConversationIndex`].
    pub fn group_id(&self) -> Option<&[u8]> {
        self.group.as_ref().map(|g| g.group_id())
    }

    /// Open a public (T3) conversation. No MLS group; the server reads content.
    ///
    /// Takes the server's room id, for the reason in [`Conversation::create_encrypted`].
    pub fn create_public(
        seal: RoomSeal,
        room: RoomId,
        user: UserId,
        device: DeviceId,
        session: Arc<Session>,
    ) -> Result<Self, ConversationError> {
        if seal.tier().is_e2ee() {
            return Err(ConversationError::Encrypted);
        }
        Ok(Self { seal, room, user, device, session, group: None })
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

    /// Everyone in this conversation, as the MLS group's own state records them.
    ///
    /// Empty for a T3 conversation, which has no group: its membership is the server's to
    /// state, and a client must not present a server's list with the same confidence as a
    /// roster it verified.
    pub fn members(&self) -> Vec<GroupMember> {
        self.group.as_ref().map(GroupHandle::members).unwrap_or_default()
    }

    /// This device's own leaf.
    pub fn own_member(&self) -> Result<GroupMember, ConversationError> {
        Ok(self.group.as_ref().ok_or(MlsError::NoGroup)?.own_member()?)
    }

    /// The safety number to compare with `peer`, out of band.
    pub fn safety_number_with(
        &self,
        peer: &GroupMember,
    ) -> Result<cairn_crypto::verification::SafetyNumber, ConversationError> {
        Ok(self.group.as_ref().ok_or(MlsError::NoGroup)?.safety_number_with(peer)?)
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

    /// Wrap an MLS handshake message — a commit or a welcome — for relay through the room.
    ///
    /// MLS produces these; something has to carry them. Cairn uses the room's own message
    /// stream rather than a separate channel, so the server sequences handshakes and
    /// application messages together. That ordering is what a single-instance deployment
    /// gives MLS for free (ADR-002), and splitting the two streams would reintroduce the
    /// problem of relating them.
    ///
    /// Deliberately unfranked: franking binds *content* a recipient may want to report,
    /// and a handshake has none. A commitment here would be a commitment to ciphertext
    /// nobody can open, which is worse than none — it would look like evidence.
    pub fn wrap_handshake(
        &self,
        message: &[u8],
        now_ms: i64,
    ) -> Result<Envelope, ConversationError> {
        let tier = self.seal.tier();
        if !tier.is_e2ee() {
            return Err(ConversationError::NotEncrypted);
        }
        let envelope = Envelope::new(
            tier,
            self.room,
            self.user,
            self.device,
            now_ms,
            EnvelopePayload::MlsHandshake { message: message.to_vec(), epoch_seq: None },
        )?;
        self.sign(envelope)
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
    /// Returns a [`TimelineEvent`], not an optional message, because a roster change is
    /// something the user must be shown rather than a state transition to absorb quietly
    /// (`docs/02-encryption-tiers.md` §4.6).
    pub fn receive(&mut self, envelope: &Envelope) -> Result<TimelineEvent, ConversationError> {
        match &envelope.payload {
            EnvelopePayload::Plaintext { body } => Ok(TimelineEvent::Message(ReceivedMessage {
                body: body.clone().into_bytes(),
                franking: None,
            })),
            EnvelopePayload::MlsApplication { ciphertext }
            | EnvelopePayload::MlsHandshake { message: ciphertext, .. } => {
                let group = self.group.as_mut().ok_or(MlsError::NoGroup)?;
                let msg = cairn_crypto::mls::parse_message(ciphertext)?;
                let decrypted = match group.process(msg)? {
                    GroupEvent::Application(data) => data,
                    GroupEvent::MembershipChanged { added, removed, committer } => {
                        return Ok(TimelineEvent::Membership { added, removed, committer })
                    }
                    GroupEvent::Removed { by } => return Ok(TimelineEvent::RemovedFromRoom { by }),
                    GroupEvent::Other => return Ok(TimelineEvent::Nothing),
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

                Ok(TimelineEvent::Message(ReceivedMessage {
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

/// Accept `envelope` as an invitation to join a group, if that is what it carries.
///
/// A client polling a room it was just added to sees the welcome as an ordinary message.
/// `Ok(None)` means the envelope was not a welcome — commits and application messages for
/// a group this device is not yet in look the same from outside and are simply not for it.
/// A malformed welcome is an error rather than `None`, so a joiner that can never join
/// finds out instead of polling forever.
pub fn accept_welcome(
    session: &Session,
    envelope: &Envelope,
) -> Result<Option<GroupHandle>, ConversationError> {
    let EnvelopePayload::MlsHandshake { message, .. } = &envelope.payload else {
        return Ok(None);
    };
    let parsed = cairn_crypto::mls::parse_message(message)?;
    if !cairn_crypto::mls::is_welcome(&parsed) {
        return Ok(None);
    }
    Ok(Some(session.join(&parsed)?))
}

/// What actually gets encrypted: the message and its franking opening.
#[derive(Debug, Serialize, Deserialize)]
struct InnerBody {
    body: Vec<u8>,
    opening: Opening,
}

/// What an incoming envelope turned out to be.
///
/// A membership change is a first-class outcome. Collapsing it into "not a message" is
/// what let an added member be invisible: MLS applies the commit either way, so the
/// difference between a wiretap and a normal handshake existed only in a value the old
/// signature had no room for.
#[derive(Debug)]
pub enum TimelineEvent {
    /// Content to display.
    Message(ReceivedMessage),
    /// The roster changed. **Show this.**
    Membership {
        added: Vec<GroupMember>,
        removed: Vec<GroupMember>,
        /// Leaf index of the member who committed the change, when the message named one.
        committer: Option<u32>,
    },
    /// **This device was removed from the conversation.** It can no longer read anything
    /// sent after this point, and a client that keeps the room looking live is lying about
    /// it.
    RemovedFromRoom {
        /// Leaf index of the member who removed it, when the commit named one.
        by: Option<u32>,
    },
    /// A handshake that changed no membership — a proposal, or a key update.
    Nothing,
}

impl TimelineEvent {
    /// The message, if this event was one. Convenient for tests and for callers that
    /// genuinely only want content; the enum still forced them to say so.
    pub fn message(self) -> Option<ReceivedMessage> {
        match self {
            TimelineEvent::Message(m) => Some(m),
            _ => None,
        }
    }
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
            RoomId::new(),
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
            RoomId::new(),
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
            RoomId::new(),
            UserId::new(),
            DeviceId::new(),
            session.clone(),
        )
        .unwrap();
        assert!(matches!(encrypted.send_plaintext("oops", 0), Err(ConversationError::Encrypted)));

        let mut public = Conversation::create_public(
            public_seal(),
            RoomId::new(),
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
                RoomId::new(),
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
            RoomId::new(),
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

    /// M1's exit condition at the layer a client actually drives.
    ///
    /// `linked_pair` above proves the round trip; this proves it still works when both
    /// sides are rebuilt from disk with nothing carried over in memory but the ids a
    /// server would have handed back.
    #[test]
    fn a_conversation_resumes_from_disk_and_keeps_talking() {
        use crate::store::ConversationIndex;

        let dir =
            std::env::temp_dir().join("cairn-convo-resume").join(format!("{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let alice_dir = dir.join("alice");
        let bob_dir = dir.join("bob");

        let (room, alice_user, alice_device, bob_user, bob_device) =
            (RoomId::new(), UserId::new(), DeviceId::new(), UserId::new(), DeviceId::new());

        {
            let alice_session = Arc::new(Session::open(&alice_dir, b"alice").unwrap());
            let bob_session = Arc::new(Session::open(&bob_dir, b"bob").unwrap());

            let mut alice = Conversation::create_encrypted(
                dm_seal(),
                room,
                alice_user,
                alice_device,
                alice_session.clone(),
            )
            .unwrap();
            let commit =
                alice.group_mut().unwrap().add_member(bob_session.key_package().unwrap()).unwrap();
            let bob_group = bob_session.join(&commit.welcome.unwrap()).unwrap();
            let bob = Conversation::join_encrypted(
                dm_seal(),
                room,
                bob_user,
                bob_device,
                bob_session.clone(),
                bob_group,
            )
            .unwrap();

            // Both ends write the room→group mapping, which is the part MLS does not
            // store for us.
            let group_id = alice.group_id().expect("an encrypted room has a group").to_vec();
            for (store_dir, seal) in [(&alice_dir, dm_seal()), (&bob_dir, dm_seal())] {
                ConversationIndex::open(store_dir)
                    .unwrap()
                    .record(room, &seal, Some(&group_id))
                    .unwrap();
            }
            assert_eq!(bob.group_id().unwrap(), group_id.as_slice());
        }

        // Restart. Only the directories survive.
        let alice_session = Arc::new(Session::open(&alice_dir, b"alice").unwrap());
        let bob_session = Arc::new(Session::open(&bob_dir, b"bob").unwrap());
        let alice_index = ConversationIndex::open(&alice_dir).unwrap();
        let bob_index = ConversationIndex::open(&bob_dir).unwrap();

        let mut alice = Conversation::resume_encrypted(
            dm_seal(),
            room,
            alice_user,
            alice_device,
            alice_session,
            &alice_index.group_id(&room).unwrap().expect("alice must remember the group"),
        )
        .unwrap();
        let mut bob = Conversation::resume_encrypted(
            dm_seal(),
            room,
            bob_user,
            bob_device,
            bob_session,
            &bob_index.group_id(&room).unwrap().expect("bob must remember the group"),
        )
        .unwrap();

        let sent = alice.send(b"still here", 1).unwrap();
        let received =
            bob.receive(&sent.envelope).unwrap().message().expect("an application message");
        assert_eq!(received.body, b"still here");

        // And the franking material still lines up, so a resumed conversation is still
        // reportable — a resumed room that cannot be reported would be a safety
        // regression hiding behind a working chat.
        let franking = received.franking.expect("E2EE messages must carry franking material");
        assert_eq!(franking.commitment, sent.commitment);
    }

    #[test]
    fn round_trip_delivers_body_and_franking_material() {
        let (mut alice, mut bob) = linked_pair();

        let sent = alice.send(b"hello bob", 1_000).unwrap();
        let received =
            bob.receive(&sent.envelope).unwrap().message().expect("an application message");

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

            let got = bob.receive(&sent.envelope).unwrap().message().unwrap();
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
            RoomId::new(),
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
