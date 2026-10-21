//! Replies, reactions, edits and deletes, folded over a room's transcript.
//!
//! All four arrive as ordinary encrypted messages that *name* an earlier one (a
//! [`MessageRef`]). Nothing here trusts a sender to describe the message they named:
//!
//! - **A quote is resolved locally.** A reply carries a reference and no text, and the
//!   snippet shown above it is whatever *this device* recorded that sender saying. A sender
//!   who names a message that does not exist, or attributes one person's message to
//!   another, gets a quote that reads "unavailable" — never words of their choosing under
//!   someone else's name.
//! - **A quote dies with its original.** The transcript is the only source, and the timer
//!   deletes from the transcript, so a reply cannot carry a disappearing message past its
//!   timer.
//! - **A reaction is attributed to whoever sent it**, which is the envelope's sender. The
//!   payload has no "reactor" field to forge.
//! - **Only a message's sender may edit or delete it**, and only a message this device
//!   holds. "Sender" is the envelope's, checked against the group's roster; a reference
//!   naming somebody else's message, or one this device never saw, is dropped rather than
//!   remembered ([`Thread::admits`]). In particular a delete that arrives before its message
//!   arms nothing: it is discarded, and the message, when it comes, is shown.
//! - **An edit changes the text and nothing else.** The sender, the time the message was
//!   sent and its place in the conversation are the original's. The earlier versions stay
//!   in the transcript, so recipients can see what was changed.

use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};

use cairn_proto::UserId;

use crate::conversation::{MessageRef, Reaction};
use crate::history::Entry;

/// Longest quote handed to a frontend, in characters. The original is one click away; a
/// quote is a reminder of which message, not a second copy of it.
pub const SNIPPET_CHARS: usize = 140;

/// The message a reply answers, as this device knows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuoteView {
    pub sender: String,
    pub id: String,
    /// `None` when this device has no such message from that sender — it expired, it was
    /// sent before this device joined, or the reference was never true.
    pub snippet: Option<String>,
    /// When the original was sent, so a frontend can blank the quote when the original
    /// expires without asking again.
    pub sent_at_ms: Option<i64>,
    /// The original was deleted by its sender. `snippet` is `None`.
    #[serde(default)]
    pub deleted: bool,
    /// The snippet is of an edited version, not of what was first sent.
    #[serde(default)]
    pub edited: bool,
}

/// One earlier version of an edited message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Revision {
    pub body: String,
    /// When this version was sent, by the sender's clock. For the first version, the
    /// message's own time; for an edit, never earlier than that.
    pub at_ms: i64,
}

/// One emoji under a message, and who chose it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReactionView {
    pub emoji: String,
    /// Users, in a stable order.
    pub by: Vec<String>,
}

struct Original {
    snippet: String,
    sent_at_ms: i64,
    deleted: bool,
    /// Text only: an attachment's body is its filename and a sticker's is its name, and
    /// editing either would change what the message *is*, not what it says.
    editable: bool,
}

/// What a room's transcript says about replies, reactions and edits.
#[derive(Default)]
pub struct Thread {
    originals: HashMap<MessageRef, Original>,
    /// Target → reactor → emoji. One reaction per member per message, latest wins.
    reactions: HashMap<MessageRef, BTreeMap<UserId, String>>,
    /// Target → each edit's text and time, oldest first. The original's own text is in its
    /// transcript entry, which is where [`Thread::versions`] takes it from.
    edits: HashMap<MessageRef, Vec<Revision>>,
}

/// What an edited message looks like now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Versions {
    /// The text to show: the latest edit's.
    pub current: String,
    /// When that edit was sent.
    pub edited_at_ms: i64,
    /// Every earlier version, oldest first, starting with what was first sent.
    pub earlier: Vec<Revision>,
}

impl Thread {
    /// Fold a transcript, oldest first.
    pub fn build(entries: &[Entry]) -> Self {
        let mut thread = Self::default();
        for entry in entries {
            thread.record(entry);
        }
        thread
    }

    /// Whether `entry` may enter the transcript at all.
    ///
    /// Everything is admitted except an edit this transcript cannot honour: one naming a
    /// message this device does not hold, somebody else's message, a deleted one, or one that
    /// is not text. Refused edits are never written down, so they cannot take effect later —
    /// when the message they name arrives, or after a restart.
    pub fn admits(&self, entry: &Entry) -> bool {
        match &entry.edit {
            None => true,
            Some(target) => {
                !entry.body.is_empty()
                    && target.sender == entry.sender
                    && self.originals.get(target).is_some_and(|o| o.editable && !o.deleted)
            }
        }
    }

    /// Whether `sender` may delete `target` here: it is theirs, this device holds it, and it
    /// has not been deleted already.
    pub fn admits_delete(&self, sender: UserId, target: &MessageRef) -> bool {
        target.sender == sender && self.originals.get(target).is_some_and(|o| !o.deleted)
    }

    /// Whether `target` is a message `me` could edit: theirs, held, text, not deleted.
    pub fn editable_by(&self, me: UserId, target: &MessageRef) -> bool {
        target.sender == me && self.originals.get(target).is_some_and(|o| o.editable && !o.deleted)
    }

    /// Take one transcript entry into account: a message becomes quotable, a reaction is
    /// applied, an edit replaces its target's text.
    pub fn record(&mut self, entry: &Entry) {
        if let Some(reaction) = &entry.reaction {
            self.react(entry.sender, reaction);
            return;
        }
        if let Some(target) = &entry.edit {
            // Checked again on the way in from disk: the rule is the transcript's, and a file
            // is not a reason to skip it.
            if !self.admits(entry) {
                return;
            }
            let original = self.originals.get_mut(target).expect("admits checked it is held");
            original.snippet = snippet(&entry.body);
            // An edit cannot claim to predate the message it edits.
            let at_ms = entry.sent_at_ms.max(original.sent_at_ms);
            let body = String::from_utf8_lossy(&entry.body).into_owned();
            self.edits.entry(target.clone()).or_default().push(Revision { body, at_ms });
            return;
        }
        let Some(target) = entry.message_ref() else { return };
        // First wins. Only the original sender can produce a given (sender, id) pair
        // legitimately, and a later duplicate from them is a replay of the same words.
        self.originals.entry(target).or_insert_with(|| Original {
            snippet: snippet(&entry.body),
            sent_at_ms: entry.sent_at_ms,
            deleted: entry.deleted,
            editable: !entry.deleted && entry.attachment.is_none() && entry.sticker.is_none(),
        });
    }

    /// The current text and earlier versions of `original`, if it has been edited.
    pub fn versions(&self, original: &Entry) -> Option<Versions> {
        let target = original.message_ref()?;
        if original.deleted {
            return None;
        }
        let edits = self.edits.get(&target).filter(|e| !e.is_empty())?;
        let (last, before) = edits.split_last().expect("not empty");
        let mut earlier = vec![Revision {
            body: String::from_utf8_lossy(&original.body).into_owned(),
            at_ms: original.sent_at_ms,
        }];
        earlier.extend(before.iter().cloned());
        Some(Versions { current: last.body.clone(), edited_at_ms: last.at_ms, earlier })
    }

    fn react(&mut self, reactor: UserId, reaction: &Reaction) {
        let per_target = self.reactions.entry(reaction.target.clone()).or_default();
        match &reaction.emoji {
            Some(emoji) => {
                per_target.insert(reactor, emoji.clone());
            }
            None => {
                per_target.remove(&reactor);
            }
        }
    }

    /// Whether this device holds the message `target` names.
    pub fn knows(&self, target: &MessageRef) -> bool {
        self.originals.contains_key(target)
    }

    /// The quote to show above a reply to `target`: its current text, from this device's
    /// transcript, or nothing.
    pub fn quote(&self, target: &MessageRef) -> QuoteView {
        let original = self.originals.get(target);
        let deleted = original.is_some_and(|o| o.deleted);
        QuoteView {
            sender: target.sender.to_string(),
            id: target.id.clone(),
            snippet: original.filter(|o| !o.deleted).map(|o| o.snippet.clone()),
            sent_at_ms: original.map(|o| o.sent_at_ms),
            deleted,
            edited: !deleted && self.edits.get(target).is_some_and(|e| !e.is_empty()),
        }
    }

    /// The reactions currently under `target`, grouped by emoji.
    pub fn reactions(&self, target: &MessageRef) -> Vec<ReactionView> {
        let Some(per_target) = self.reactions.get(target) else { return Vec::new() };
        let mut grouped: BTreeMap<&str, Vec<String>> = BTreeMap::new();
        for (user, emoji) in per_target {
            grouped.entry(emoji).or_default().push(user.to_string());
        }
        grouped
            .into_iter()
            .map(|(emoji, by)| ReactionView { emoji: emoji.to_owned(), by })
            .collect()
    }
}

fn snippet(body: &[u8]) -> String {
    let text = String::from_utf8_lossy(body);
    let mut out: String = text.chars().take(SNIPPET_CHARS).collect();
    if text.chars().nth(SNIPPET_CHARS).is_some() {
        out.push('…');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID_A: &str = "aa00000000000000000000000000000000000000000000000000000000000000";

    fn message(sender: UserId, id: &str, body: &str) -> Entry {
        Entry {
            sender,
            sent_at_ms: 1,
            body: body.as_bytes().to_vec(),
            attachment_name: None,
            attachment: None,
            id: Some(id.to_owned()),
            reply_to: None,
            reaction: None,
            card: None,
            sticker: None,
            edit: None,
            deleted: false,
        }
    }

    fn edit(by: UserId, target: &MessageRef, at: i64, body: &str) -> Entry {
        Entry {
            sent_at_ms: at,
            id: Some(format!("{at:064x}")),
            edit: Some(target.clone()),
            ..message(by, "unused", body)
        }
    }

    fn reaction(by: UserId, target: &MessageRef, emoji: Option<&str>) -> Entry {
        Entry {
            sender: by,
            sent_at_ms: 2,
            body: Vec::new(),
            attachment_name: None,
            attachment: None,
            id: None,
            reply_to: None,
            reaction: Some(Reaction { target: target.clone(), emoji: emoji.map(str::to_owned) }),
            card: None,
            sticker: None,
            edit: None,
            deleted: false,
        }
    }

    #[test]
    fn nobody_can_edit_someone_elses_message() {
        // Probe: mallory names alice's real message, as herself and as alice. Neither may
        // enter the transcript, and alice's words stay alice's.
        let (alice, mallory) = (UserId::new(), UserId::new());
        let original = message(alice, ID_A, "the meeting is at 3");
        let target = original.message_ref().unwrap();
        let mut thread = Thread::build(std::slice::from_ref(&original));

        let as_herself = edit(mallory, &target, 5, "the meeting is cancelled");
        assert!(!thread.admits(&as_herself));
        // The reference names a message mallory supposedly sent with alice's id: no such
        // message exists here, and the pairing must not resolve to alice's.
        let relabelled =
            edit(mallory, &MessageRef { sender: mallory, id: ID_A.into() }, 5, "cancelled");
        assert!(!thread.admits(&relabelled));
        assert!(!thread.admits_delete(mallory, &target));

        // Even if a transcript somehow held them, folding it must not apply them.
        thread.record(&as_herself);
        thread.record(&relabelled);
        assert_eq!(thread.versions(&original), None);
        assert_eq!(thread.quote(&target).snippet.as_deref(), Some("the meeting is at 3"));
    }

    #[test]
    fn an_edit_changes_the_text_and_never_the_time_or_the_author() {
        // Probe: an edit claiming to have been sent before the message it edits.
        let alice = UserId::new();
        let original = Entry { sent_at_ms: 10_000, ..message(alice, ID_A, "draft") };
        let target = original.message_ref().unwrap();
        let mut thread = Thread::build(std::slice::from_ref(&original));
        let backdated = edit(alice, &target, 1, "final");
        assert!(thread.admits(&backdated));
        thread.record(&backdated);

        let versions = thread.versions(&original).unwrap();
        assert_eq!(versions.current, "final");
        assert_eq!(versions.edited_at_ms, 10_000, "an edit cannot predate what it edits");
        assert_eq!(versions.earlier, vec![Revision { body: "draft".into(), at_ms: 10_000 }]);
        let quote = thread.quote(&target);
        assert_eq!(quote.sent_at_ms, Some(10_000), "the quote keeps the original's time");
        assert_eq!(quote.sender, alice.to_string());
        assert_eq!(quote.snippet.as_deref(), Some("final"));
        assert!(quote.edited);
    }

    #[test]
    fn every_earlier_version_stays_visible_in_order() {
        let alice = UserId::new();
        let original = message(alice, ID_A, "v1");
        let target = original.message_ref().unwrap();
        let thread = Thread::build(&[
            original.clone(),
            edit(alice, &target, 2, "v2"),
            edit(alice, &target, 3, "v3"),
        ]);
        let versions = thread.versions(&original).unwrap();
        assert_eq!(versions.current, "v3");
        let bodies: Vec<&str> = versions.earlier.iter().map(|r| r.body.as_str()).collect();
        assert_eq!(bodies, ["v1", "v2"]);
    }

    #[test]
    fn an_edit_or_delete_that_arrives_before_its_message_arms_nothing() {
        // Probe: the sender computes a commitment in advance and sends the delete (or edit)
        // first. It must not be remembered and applied when the message turns up — that
        // would let a message be shown to nobody honest while still sitting on the instance.
        let alice = UserId::new();
        let original = message(alice, ID_A, "arrives second");
        let target = original.message_ref().unwrap();
        let mut thread = Thread::default();
        let early = edit(alice, &target, 0, "arrived first");
        assert!(!thread.admits(&early));
        assert!(!thread.admits_delete(alice, &target));
        thread.record(&early);
        thread.record(&original);
        assert_eq!(thread.versions(&original), None);
        assert_eq!(thread.quote(&target).snippet.as_deref(), Some("arrives second"));
        assert!(thread.admits_delete(alice, &target), "and it can still be deleted properly");
    }

    #[test]
    fn a_deleted_message_cannot_be_edited_and_its_quote_says_deleted() {
        let alice = UserId::new();
        let tombstone = Entry { deleted: true, body: Vec::new(), ..message(alice, ID_A, "") };
        let target = tombstone.message_ref().unwrap();
        let thread = Thread::build(&[tombstone]);
        assert!(!thread.admits(&edit(alice, &target, 5, "back from the dead")));
        assert!(!thread.admits_delete(alice, &target));
        let quote = thread.quote(&target);
        assert!(quote.deleted);
        assert_eq!(quote.snippet, None);
    }

    #[test]
    fn a_sticker_or_attachment_is_not_editable_text() {
        let alice = UserId::new();
        let sticker = Entry { sticker: Some("wave".into()), ..message(alice, ID_A, ":wave:") };
        let target = sticker.message_ref().unwrap();
        let thread = Thread::build(&[sticker]);
        assert!(!thread.admits(&edit(alice, &target, 5, "some words")));
        assert!(!thread.editable_by(alice, &target));
        assert!(thread.admits_delete(alice, &target), "deleting one is still allowed");
    }

    #[test]
    fn a_quote_cannot_attribute_one_members_words_to_another() {
        // Mallory names alice's message but says bob sent it. The id is real; the pairing is
        // not, and a lookup by id alone would show alice's words under bob's name.
        let (alice, bob) = (UserId::new(), UserId::new());
        let thread = Thread::build(&[message(alice, ID_A, "alice said this")]);
        let forged = MessageRef { sender: bob, id: ID_A.to_owned() };
        assert_eq!(thread.quote(&forged).snippet, None);
        let honest = MessageRef { sender: alice, id: ID_A.to_owned() };
        assert_eq!(thread.quote(&honest).snippet.as_deref(), Some("alice said this"));
    }

    #[test]
    fn each_member_holds_one_reaction_per_message_and_can_withdraw_it() {
        let (alice, bob) = (UserId::new(), UserId::new());
        let target = MessageRef { sender: alice, id: ID_A.to_owned() };
        let thread = Thread::build(&[
            message(alice, ID_A, "hi"),
            reaction(bob, &target, Some("👍")),
            reaction(bob, &target, Some("❤️")),
            reaction(alice, &target, Some("❤️")),
        ]);
        let shown = thread.reactions(&target);
        assert_eq!(shown.len(), 1, "bob's second reaction replaces his first: {shown:?}");
        assert_eq!(shown[0].by.len(), 2);

        let mut thread = thread;
        thread.record(&reaction(bob, &target, None));
        assert_eq!(thread.reactions(&target)[0].by, vec![alice.to_string()]);
    }

    #[test]
    fn a_long_message_is_quoted_short() {
        let alice = UserId::new();
        let long = "x".repeat(SNIPPET_CHARS * 3);
        let thread = Thread::build(&[message(alice, ID_A, &long)]);
        let quoted = thread.quote(&MessageRef { sender: alice, id: ID_A.to_owned() });
        assert_eq!(quoted.snippet.unwrap().chars().count(), SNIPPET_CHARS + 1);
    }
}
