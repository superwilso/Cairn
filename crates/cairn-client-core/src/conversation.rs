//! A conversation: MLS session, franking chain, and tier enforcement in one place.
//!
//! This is the type a platform UI drives. It deliberately owns the franking chain so that
//! a client cannot forget to maintain it — a message sent without a commitment is a
//! message that can never be reported.

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use cairn_crypto::attachment::AttachmentKey;
use cairn_crypto::franking::{self, Commitment, Opening};
use cairn_crypto::mls::{GroupEvent, GroupHandle, GroupMember, MlsError, Session};
use cairn_proto::{BlobId, DeviceId, Envelope, EnvelopePayload, RoomId, RoomSeal, Tier, UserId};

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
        self.send_with_card(plaintext, None, now_ms)
    }

    /// Send with a link card the caller already rendered.
    ///
    /// The card is **not** franked separately, and that is deliberate: the franking
    /// commitment covers `plaintext`, which is what a report is about. A card is the
    /// sender's own decoration of their own message — binding it into the commitment would
    /// imply the server had attested something about it, which it cannot, since it never
    /// saw the URL (`docs/05-embeds.md` §3).
    pub fn send_with_card(
        &mut self,
        plaintext: &[u8],
        card: Option<crate::embed::Card>,
        now_ms: i64,
    ) -> Result<OutboundMessage, ConversationError> {
        self.send_with(plaintext, Extras { card, ..Extras::default() }, now_ms)
    }

    /// Send with an attachment the caller has already sealed and uploaded.
    ///
    /// Sealing and uploading are deliberately *not* done here. This type holds the group
    /// keys and has no transport, and giving it one so it could upload would put a network
    /// call inside the encryption path — where a failure would leave the caller unable to
    /// tell whether the message was sent.
    pub fn send_with_attachment(
        &mut self,
        plaintext: &[u8],
        attachment: Attachment,
        now_ms: i64,
    ) -> Result<OutboundMessage, ConversationError> {
        self.send_with(
            plaintext,
            Extras { attachment: Some(attachment), ..Extras::default() },
            now_ms,
        )
    }

    /// Send a call signal. The body is empty: this is not a message anyone reads.
    ///
    /// It still goes through the ordinary encrypted path, so an instance cannot tell a
    /// signalling message from a chat message by looking — only that traffic happened,
    /// which it already knew.
    pub fn send_signal(
        &mut self,
        signal: crate::call::CallSignal,
        now_ms: i64,
    ) -> Result<OutboundMessage, ConversationError> {
        self.send_with(b"", Extras { signal: Some(signal), ..Extras::default() }, now_ms)
    }

    /// Send a message that answers an earlier one.
    ///
    /// Carries a *reference* and nothing else — no copy of the text being answered. Each
    /// recipient looks the quote up in its own transcript, so a sender cannot misquote
    /// anyone, and a quote cannot keep a disappearing message alive after its timer.
    pub fn send_reply(
        &mut self,
        plaintext: &[u8],
        reply_to: MessageRef,
        now_ms: i64,
    ) -> Result<OutboundMessage, ConversationError> {
        self.send_with(plaintext, Extras { reply_to: Some(reply_to), ..Extras::default() }, now_ms)
    }

    /// React to a message, or withdraw a reaction (`emoji: None`).
    ///
    /// The body is empty, like a signal's, so the franking commitment covers nothing a
    /// report could use: **a reaction is not reportable**. That is a limitation, recorded
    /// here rather than discovered; the alternative — franking the emoji as if it were the
    /// message — would make a reaction indistinguishable from a one-character message to
    /// any client that predates reactions.
    pub fn send_reaction(
        &mut self,
        reaction: Reaction,
        now_ms: i64,
    ) -> Result<OutboundMessage, ConversationError> {
        self.send_with(b"", Extras { reaction: Some(reaction), ..Extras::default() }, now_ms)
    }

    fn send_with(
        &mut self,
        plaintext: &[u8],
        extras: Extras,
        now_ms: i64,
    ) -> Result<OutboundMessage, ConversationError> {
        let Extras { card, attachment, signal, reply_to, reaction } = extras;
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
        let inner = InnerBody {
            body: plaintext.to_vec(),
            opening: opening.clone(),
            card: card.map(crate::embed::Card::clamp),
            attachment,
            signal,
            reply_to,
            reaction,
        };
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
                // A T3 room carries no signalling: a call there would be transport-only and
                // its setup has nowhere private to travel.
                signal: None,
                body: body.clone().into_bytes(),
                franking: None,
                card: None,
                // A T3 plaintext message carries no attachment: there is no encrypted body
                // to put the key in, and a key beside the ciphertext protects nothing.
                attachment: None,
                reply_to: None,
                reaction: None,
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

                // A reaction that is not one is dropped whole rather than shown as an empty
                // message: these bytes came from the sender, and a "reaction" carrying a
                // paragraph is a hostile client using the reaction chip as a billboard.
                if inner.reaction.as_ref().is_some_and(|r| !r.is_valid()) {
                    return Ok(TimelineEvent::Nothing);
                }

                Ok(TimelineEvent::Message(ReceivedMessage {
                    body: inner.body,
                    franking: Some(ReceivedFranking {
                        opening: inner.opening,
                        commitment: claimed,
                    }),
                    // Clamped again on receipt. These bytes came from the sender, so the
                    // limits are a defence against a hostile one, not tidiness.
                    card: inner.card.map(crate::embed::Card::clamp),
                    attachment: inner.attachment.map(Box::new),
                    signal: inner.signal.map(Box::new),
                    // A malformed reference makes this an ordinary message, not an error:
                    // the text is still something its sender said.
                    reply_to: inner.reply_to.filter(MessageRef::is_valid).map(Box::new),
                    reaction: inner.reaction.map(Box::new),
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

/// An attachment the sender uploaded, and everything needed to open it.
///
/// Travels **inside** the encrypted body, exactly like [`Opening`] and the link card, and
/// for the same reason: the server stores the sealed bytes and must not hold the key that
/// opens them. It also never learns which blob belongs to which message — the blob id is in
/// here too, so an instance cannot even correlate an upload with the message that referred
/// to it beyond what the upload itself revealed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attachment {
    pub blob: BlobId,
    /// Single-use, generated per attachment by [`cairn_crypto::attachment::seal`].
    pub key: AttachmentKey,
    /// The sender's claimed filename. **Chosen by the sender**, like everything else in a
    /// message — a client must treat it as a label to display, never as a path to write to.
    pub name: String,
    /// Plaintext length, for a progress indicator before the bytes arrive.
    pub size: usize,
    /// The sender's claimed media type, e.g. `image/png` or `audio/webm`.
    ///
    /// **Also chosen by the sender**, and a claim about bytes nobody has checked. A client
    /// uses it to pick a presentation — inline image, audio player, download chip — and
    /// must decide which claims it is willing to act on; see
    /// `crate::session::AttachmentView`. `default` so a descriptor from a client that
    /// predates it (the CLI's `/send`) still decodes, as an untyped file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mime: Option<String>,
}

/// What actually gets encrypted: the message and its franking opening.
#[derive(Debug, Serialize, Deserialize)]
struct InnerBody {
    body: Vec<u8>,
    opening: Opening,
    /// A link card the sender rendered on their own device.
    ///
    /// Inside the encrypted body, so the server never learns the URL — that is the whole
    /// point of the design in `docs/05-embeds.md`. `default` so a message from a client
    /// that predates cards still decodes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    card: Option<crate::embed::Card>,
    /// `default` so a message from a client that predates attachments still decodes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    attachment: Option<Attachment>,
    /// Call signalling — an SDP offer, an answer, or an ICE candidate.
    ///
    /// **Inside the encrypted body deliberately.** An offer describes the sender's codecs,
    /// network candidates and IP addresses; carrying it beside the ciphertext would hand
    /// all of that to the instance, which relays the message and has no need for any of it.
    /// `default` so a message from a client that predates calls still decodes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    signal: Option<crate::call::CallSignal>,
    /// The message this one answers. A reference only — see [`Conversation::send_reply`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reply_to: Option<MessageRef>,
    /// A reaction to an earlier message. Inside the encrypted body like everything else: who
    /// reacted to what, with which emoji, is conversation content.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reaction: Option<Reaction>,
}

/// The optional parts of an outgoing message. Bundled so `send_with` does not grow a
/// positional argument for every feature, which is how two `Option`s get swapped silently.
#[derive(Default)]
struct Extras {
    card: Option<crate::embed::Card>,
    attachment: Option<Attachment>,
    signal: Option<crate::call::CallSignal>,
    reply_to: Option<MessageRef>,
    reaction: Option<Reaction>,
}

/// Names one earlier message in a room: who sent it, and its franking commitment.
///
/// The commitment is the message's identity because every party already has it — the
/// sender computed it, each recipient verified it, and the instance stored it beside the
/// ciphertext — so naming it inside an encrypted body tells the instance nothing new. It is
/// unique per message (the opening is random), but **only per sender**: anyone holding a
/// message's opening can send the same body and reproduce its commitment. A reference
/// therefore always carries the sender, and resolving one must match both.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct MessageRef {
    pub sender: UserId,
    /// Hex of the target's franking commitment.
    pub id: String,
}

impl MessageRef {
    /// Whether `id` is a well-formed commitment. Checked on receipt: an arbitrary string
    /// here would be stored, indexed and echoed back by every recipient.
    /// Lowercase only, so one message has one spelling and a lookup cannot miss it on case.
    pub fn is_valid(&self) -> bool {
        decode_commitment(&self.id).is_some_and(|c| c.to_hex() == self.id)
    }
}

/// One member's reaction to one message. Each member holds at most one per message; a
/// later reaction replaces an earlier one, and `emoji: None` withdraws it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reaction {
    pub target: MessageRef,
    pub emoji: Option<String>,
}

impl Reaction {
    /// Longest emoji accepted, in scalar values. A family with skin tones is eleven.
    pub const MAX_CHARS: usize = 16;

    /// Whether this is a reaction rather than a message wearing one's clothes.
    ///
    /// Short, no ASCII (which rules out words, not emoji), and no control characters or
    /// whitespace. Not a full emoji grammar — the point is that a chip under someone's
    /// message cannot carry text, not that every sequence is a well-formed glyph.
    pub fn is_valid(&self) -> bool {
        self.target.is_valid() && self.emoji.as_deref().is_none_or(is_emoji_like)
    }
}

fn is_emoji_like(s: &str) -> bool {
    let n = s.chars().count();
    (1..=Reaction::MAX_CHARS).contains(&n)
        && s.chars().all(|c| !c.is_ascii() && !c.is_control() && !c.is_whitespace())
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
    /// The sender's link card, if they sent one.
    ///
    /// **Everything in it was chosen by the sender.** A client renders it as a claim, keeps
    /// the URL visible, and derives no trust signal from its contents. It must not fetch
    /// anything to display it — see [`crate::embed`].
    pub card: Option<crate::embed::Card>,
    /// The sender's attachment, if they sent one. Fetch the blob and open it with the key
    /// inside; both came from the encrypted body, so the server supplied neither.
    ///
    /// Boxed to keep [`TimelineEvent`]'s variants a similar size — a message carrying an
    /// attachment descriptor would otherwise make every membership event pay for it.
    pub attachment: Option<Box<Attachment>>,
    /// Present for E2EE messages. A recipient must retain this to file a report; without
    /// it the message is unreportable.
    pub franking: Option<ReceivedFranking>,
    /// Call signalling, if this message carried some rather than text.
    ///
    /// A client routes this to its WebRTC layer instead of the timeline — nobody wants an
    /// SDP blob rendered as a chat message.
    ///
    /// Boxed for the same reason the attachment above is: an SDP offer is not small, and
    /// without the box every membership event would carry room for one.
    #[allow(clippy::doc_markdown)]
    pub signal: Option<Box<crate::call::CallSignal>>,
    /// The message this one answers, when it is a reply. Unresolved: the quote is looked up
    /// in the recipient's own history, never taken from the sender.
    ///
    /// Boxed, like the attachment, so membership events do not pay for it.
    pub reply_to: Option<Box<MessageRef>>,
    /// A reaction rather than text. Already checked with [`Reaction::is_valid`].
    pub reaction: Option<Box<Reaction>>,
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
    fn a_reaction_carrying_text_is_dropped_on_receipt() {
        // A hostile client is not bound by the sender-side check, and a reaction chip that
        // displayed whatever it was sent would be a place to put words under someone else's
        // message where they look like part of it.
        let (mut alice, mut bob) = linked_pair();
        let target = MessageRef { sender: UserId::new(), id: "ab".repeat(32) };
        for emoji in ["you are a fraud", "👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍", "👍\n👍", ""]
        {
            let reaction = Reaction { target: target.clone(), emoji: Some(emoji.to_owned()) };
            let sent = alice.send_reaction(reaction, 1_000).unwrap();
            let got = bob.receive(&sent.envelope).unwrap();
            assert!(matches!(got, TimelineEvent::Nothing), "{emoji:?} must not arrive as anything");
        }

        let good = Reaction { target: target.clone(), emoji: Some("❤️".to_owned()) };
        let sent = alice.send_reaction(good.clone(), 1_000).unwrap();
        let got = bob.receive(&sent.envelope).unwrap().message().unwrap();
        assert_eq!(got.reaction.as_deref(), Some(&good));
    }

    #[test]
    fn a_malformed_reply_reference_leaves_an_ordinary_message() {
        let (mut alice, mut bob) = linked_pair();
        let bad = MessageRef { sender: UserId::new(), id: "AB".repeat(32) };
        let sent = alice.send_reply(b"still said this", bad, 1_000).unwrap();
        let got = bob.receive(&sent.envelope).unwrap().message().unwrap();
        assert_eq!(got.body, b"still said this", "the words survive");
        assert!(got.reply_to.is_none(), "an uppercase id is not one spelling of a message");
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

#[cfg(test)]
mod attachment_tests {
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

    fn convo() -> Conversation {
        Conversation::create_encrypted(
            dm_seal(),
            RoomId::new(),
            UserId::new(),
            DeviceId::new(),
            Arc::new(Session::new(b"alice").unwrap()),
        )
        .unwrap()
    }

    fn descriptor() -> (Attachment, Vec<u8>, Vec<u8>) {
        let plaintext = b"the contents of a private file".to_vec();
        let (key, sealed) = cairn_crypto::attachment::seal(&plaintext);
        let attachment = Attachment {
            blob: BlobId::new(),
            key,
            name: "notes.txt".into(),
            size: plaintext.len(),
            mime: Some("text/plain".into()),
        };
        (attachment, plaintext, sealed)
    }

    #[test]
    fn the_attachment_key_never_appears_outside_the_ciphertext() {
        // The property that makes the blob store worth anything. If the key is anywhere in
        // the envelope the server receives, the server can open every attachment it holds
        // and the encryption is theatre.
        let mut alice = convo();
        let (attachment, _plaintext, _sealed) = descriptor();

        // Exactly the bytes the key would serialize to, so this compares like for like.
        let key_json = serde_json::to_string(&attachment.key).unwrap();
        let key_hex = key_json.trim_matches('"').to_string();
        assert_eq!(key_hex.len(), 64, "a 32-byte key should serialize as 64 hex chars");

        let out = alice.send_with_attachment(b"attached", attachment, 0).unwrap();
        let wire = serde_json::to_string(&out.envelope).unwrap();

        assert!(
            !wire.contains(&key_hex),
            "the attachment key must never appear in the envelope the server sees"
        );
    }

    #[test]
    fn the_descriptor_survives_the_encrypted_body_encoding() {
        // The body is JSON inside the MLS ciphertext, so a field that fails to encode would
        // silently drop the attachment rather than fail the send.
        let (attachment, plaintext, sealed) = descriptor();
        let blob = attachment.blob;
        let inner = InnerBody {
            body: b"here is that file".to_vec(),
            opening: cairn_crypto::franking::Opening::generate(),
            card: None,
            attachment: Some(attachment),
            signal: None,
            reply_to: None,
            reaction: None,
        };

        let encoded = serde_json::to_vec(&inner).unwrap();
        let decoded: InnerBody = serde_json::from_slice(&encoded).unwrap();

        let got = decoded.attachment.expect("the attachment must survive encoding");
        assert_eq!(got.blob, blob);
        assert_eq!(got.name, "notes.txt");
        // The key that came back out opens the bytes the server was holding.
        assert_eq!(cairn_crypto::attachment::open(&got.key, &sealed).unwrap(), plaintext);
    }

    #[test]
    fn a_body_from_a_client_that_predates_attachments_still_decodes() {
        // `serde(default)` is load-bearing: without it every older client's messages become
        // undecodable the moment this field ships, which looks like data loss to the user.
        let older = serde_json::json!({
            "body": b"no attachment here".to_vec(),
            "opening": cairn_crypto::franking::Opening::generate(),
        });
        let decoded: InnerBody = serde_json::from_value(older).unwrap();
        assert!(decoded.attachment.is_none());
        assert_eq!(decoded.body, b"no attachment here");
    }
}
