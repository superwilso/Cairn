//! Replies and reactions, folded over a room's transcript.
//!
//! Both arrive as ordinary encrypted messages that *name* an earlier one (a
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
}

/// What a room's transcript says about replies and reactions.
#[derive(Default)]
pub struct Thread {
    originals: HashMap<MessageRef, Original>,
    /// Target → reactor → emoji. One reaction per member per message, latest wins.
    reactions: HashMap<MessageRef, BTreeMap<UserId, String>>,
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

    /// Take one transcript entry into account: a message becomes quotable, a reaction is
    /// applied.
    pub fn record(&mut self, entry: &Entry) {
        if let Some(reaction) = &entry.reaction {
            self.react(entry.sender, reaction);
            return;
        }
        let Some(id) = &entry.id else { return };
        let target = MessageRef { sender: entry.sender, id: id.clone() };
        // First wins. Only the original sender can produce a given (sender, id) pair
        // legitimately, and a later duplicate from them is a replay of the same words.
        self.originals.entry(target).or_insert_with(|| Original {
            snippet: snippet(&entry.body),
            sent_at_ms: entry.sent_at_ms,
        });
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

    /// The quote to show above a reply to `target`.
    pub fn quote(&self, target: &MessageRef) -> QuoteView {
        let original = self.originals.get(target);
        QuoteView {
            sender: target.sender.to_string(),
            id: target.id.clone(),
            snippet: original.map(|o| o.snippet.clone()),
            sent_at_ms: original.map(|o| o.sent_at_ms),
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
        }
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
