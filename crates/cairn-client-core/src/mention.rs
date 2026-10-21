//! Whether a message mentions this account: `@` followed by one of its names.
//!
//! Decided here rather than in a frontend because it decides what a person is *alerted* to,
//! and two clients disagreeing about whether "@al" pings Alice is a bug nobody could find.
//!
//! What it is not: a protocol feature. A mention is plain text inside the encrypted body, so
//! the instance never learns that anyone was mentioned, or whom; nothing is addressed, and
//! nothing is sent to the person named. Each recipient's device reads the words and decides
//! for itself, which also means **a mention is only as precise as names are**: two members
//! who both call themselves "Sam" are both pinged by "@Sam". The lookalike checks in
//! [`crate::profile`] label *senders*; they do not stop someone writing another member's name.

/// True when `body` contains `@name` for any of `names`, ignoring case, with the name ending
/// at a word boundary — so `@al` does not ping someone called Alice, and `@alice` does not
/// ping someone called Al. The `@` must start a word too, which keeps `me@alice.example`
/// from being a mention.
pub fn mentions(body: &str, names: &[String]) -> bool {
    let body = body.to_lowercase();
    names.iter().map(|n| n.trim().to_lowercase()).filter(|n| !n.is_empty()).any(|name| {
        let needle = format!("@{name}");
        body.match_indices(&needle).any(|(at, _)| {
            let before = body[..at].chars().next_back();
            let after = body[at + needle.len()..].chars().next();
            !before.is_some_and(is_word) && !after.is_some_and(is_word)
        })
    })
}

fn is_word(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(n: &[&str]) -> Vec<String> {
        n.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn an_at_name_mentions_its_owner_whatever_the_case() {
        let me = names(&["Alice"]);
        assert!(mentions("hey @alice, look", &me));
        assert!(mentions("@ALICE", &me));
        assert!(mentions("(@Alice)", &me));
    }

    #[test]
    fn a_name_is_matched_whole_not_as_a_prefix_or_inside_an_address() {
        assert!(!mentions("@alice2 is someone else", &names(&["Alice"])));
        assert!(!mentions("@alice", &names(&["Al"])));
        assert!(!mentions("write to me@alice.example", &names(&["Alice"])));
        assert!(!mentions("alice, no at sign", &names(&["Alice"])));
    }

    #[test]
    fn any_of_several_names_counts_and_blank_ones_never_do() {
        let me = names(&["", "  ", "Ann Lee", "a11ce000"]);
        assert!(mentions("thanks @ann lee!", &me));
        assert!(mentions("cc @a11ce000", &me));
        assert!(!mentions("@ everyone", &me), "an empty name must not match a bare @");
    }
}
