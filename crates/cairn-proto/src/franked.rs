//! The exact bytes a franking commitment covers, and how a moderator reads them back.
//!
//! For an ordinary message the commitment covers its text and nothing else. An **edit** is
//! different: its text alone would let a reporter present it as a standalone message, or —
//! worse — claim it replaced some *other* message. So an edit's commitment covers the text
//! **and which message it replaces**, in the frame built by [`edit_bytes`]. A moderator who
//! verifies a report of an edit therefore learns, from the cryptography rather than from the
//! reporter, whose message it claims to replace and which one; a report that also carries the
//! original lets them check that the two were sent by the same account.
//!
//! Why this lives in `cairn-proto`: the frame is protocol, not client behaviour. A moderator's
//! tooling on the instance must decode it without linking a client, and a third-party client
//! must produce the same bytes or its edits will not verify.
//!
//! ## Unambiguity
//!
//! The frame starts with a length-prefixed domain label whose first byte is a length, not
//! text, so no message a person types begins with it by accident. One a hostile client
//! *builds* could; that is why an honest client refuses to send an ordinary message whose
//! text parses as a frame, and drops one on receipt (`cairn-client-core`), so every message
//! an honest client displayed reads back to a moderator as what it was.

use crate::ids::UserId;

/// Domain label for an edit's franked bytes. Versioned, so a later frame cannot be confused
/// with this one.
const EDIT_DOMAIN: &[u8] = b"cairn/franked/edit/v1";

/// What a franking commitment opened to, as a moderator should read it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Franked<'a> {
    /// An ordinary message: the commitment covers exactly this text.
    Message(&'a [u8]),
    /// A replacement for an earlier message.
    Edit {
        /// Whose message this claims to replace. A verified report of the edit proves who
        /// *sent* the edit; if this names anyone else, the edit was not honoured by any
        /// honest client, and a moderator must not read it as the target's words.
        target_sender: UserId,
        /// The franking commitment of the message being replaced — its identity in the
        /// room's chain, so the original can be matched to its own tag.
        target_commitment: [u8; 32],
        /// The replacement text.
        body: &'a [u8],
    },
}

fn push(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// The bytes an edit's franking commitment covers.
///
/// Length-prefixed throughout, so no two different (target, body) pairs share an encoding.
pub fn edit_bytes(target_sender: UserId, target_commitment: &[u8; 32], body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(EDIT_DOMAIN.len() + 16 + 32 + body.len() + 32);
    push(&mut out, EDIT_DOMAIN);
    push(&mut out, target_sender.as_uuid().as_bytes());
    push(&mut out, target_commitment);
    push(&mut out, body);
    out
}

/// Read franked bytes back. Anything that is not exactly an edit frame is a message.
pub fn parse(bytes: &[u8]) -> Franked<'_> {
    parse_edit(bytes).unwrap_or(Franked::Message(bytes))
}

/// Whether these bytes would be read as an edit frame. An ordinary message for which this is
/// true must not be sent, and is dropped on receipt.
pub fn is_edit_frame(bytes: &[u8]) -> bool {
    parse_edit(bytes).is_some()
}

fn parse_edit(bytes: &[u8]) -> Option<Franked<'_>> {
    fn take<'a>(rest: &mut &'a [u8]) -> Option<&'a [u8]> {
        let (len, tail) = rest.split_first_chunk::<8>()?;
        let len = usize::try_from(u64::from_be_bytes(*len)).ok()?;
        if tail.len() < len {
            return None;
        }
        let (field, tail) = tail.split_at(len);
        *rest = tail;
        Some(field)
    }
    let mut rest = bytes;
    if take(&mut rest)? != EDIT_DOMAIN {
        return None;
    }
    let sender: [u8; 16] = take(&mut rest)?.try_into().ok()?;
    let target_commitment: [u8; 32] = take(&mut rest)?.try_into().ok()?;
    let body = take(&mut rest)?;
    // Exactly consumed, or it is not a frame: trailing bytes would be a second reading.
    if !rest.is_empty() {
        return None;
    }
    Some(Franked::Edit {
        target_sender: UserId::from_uuid(uuid::Uuid::from_bytes(sender)),
        target_commitment,
        body,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_edit_frame_reads_back_as_the_edit_it_encodes() {
        let alice = UserId::new();
        let bytes = edit_bytes(alice, &[7; 32], b"fixed the typo");
        assert_eq!(
            parse(&bytes),
            Franked::Edit {
                target_sender: alice,
                target_commitment: [7; 32],
                body: b"fixed the typo"
            }
        );
    }

    #[test]
    fn ordinary_text_is_a_message() {
        for text in [&b""[..], b"hello", b"cairn/franked/edit/v1", &[0u8; 8][..]] {
            assert_eq!(parse(text), Franked::Message(text));
            assert!(!is_edit_frame(text));
        }
    }

    #[test]
    fn every_field_of_an_edit_is_covered() {
        let (a, b) = (UserId::new(), UserId::new());
        let base = edit_bytes(a, &[1; 32], b"x");
        assert_ne!(base, edit_bytes(b, &[1; 32], b"x"), "target sender must be covered");
        assert_ne!(base, edit_bytes(a, &[2; 32], b"x"), "target message must be covered");
        assert_ne!(base, edit_bytes(a, &[1; 32], b"y"), "body must be covered");
    }

    #[test]
    fn a_frame_with_trailing_bytes_is_not_an_edit() {
        let mut bytes = edit_bytes(UserId::new(), &[1; 32], b"x");
        bytes.push(0);
        assert!(!is_edit_frame(&bytes));
        let truncated = &edit_bytes(UserId::new(), &[1; 32], b"xyz")[..60];
        assert!(!is_edit_frame(truncated));
    }
}
