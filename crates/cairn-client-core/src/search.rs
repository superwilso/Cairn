//! Searching this device's own transcripts.
//!
//! In an end-to-end encrypted room the instance holds ciphertext, so it cannot search and
//! must not be asked to: a query sent to the instance is itself a disclosure of what the
//! user is looking for. Search therefore runs here, over [`crate::history`], and sends
//! nothing anywhere.
//!
//! It can only find what this device kept — nothing from before it joined a room, and
//! nothing past a room's disappearing timer. The second is enforced, not incidental: the
//! caller sweeps each transcript against its timer before matching, so a search is never
//! the way an expired message comes back.

use serde::{Deserialize, Serialize};

use crate::history::Entry;

/// Characters of context kept either side of a match.
const BEFORE_CHARS: usize = 32;
const AFTER_CHARS: usize = 80;

/// One message that matched, split so a frontend can mark the match without searching the
/// text again — which would be a second, possibly different, idea of what matched.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SearchHit {
    pub room: String,
    pub sender: String,
    pub sent_at_ms: i64,
    /// The message's id, for jumping to it. `None` for one recorded before ids existed.
    pub id: Option<String>,
    pub before: String,
    pub matched: String,
    pub after: String,
}

/// The messages in `entries` that contain `query`, ignoring case. Reactions are not
/// messages and are never hits.
pub fn search_entries(room: &str, entries: &[Entry], query: &str) -> Vec<SearchHit> {
    let needle: Vec<char> = query.trim().chars().flat_map(char::to_lowercase).collect();
    if needle.is_empty() {
        return Vec::new();
    }
    entries
        .iter()
        .filter(|e| e.reaction.is_none())
        .filter_map(|e| {
            let body = String::from_utf8_lossy(&e.body);
            let (start, end) = find_ci(&body, &needle)?;
            Some(SearchHit {
                room: room.to_owned(),
                sender: e.sender.to_string(),
                sent_at_ms: e.sent_at_ms,
                id: e.id.clone(),
                before: tail(&body[..start], BEFORE_CHARS),
                matched: body[start..end].to_owned(),
                after: head(&body[end..], AFTER_CHARS),
            })
        })
        .collect()
}

/// Byte range of the first case-insensitive occurrence of `needle` (already lowercased) in
/// `hay`, on `hay`'s own character boundaries.
fn find_ci(hay: &str, needle: &[char]) -> Option<(usize, usize)> {
    'start: for (start, _) in hay.char_indices() {
        let mut k = 0;
        for (offset, c) in hay[start..].char_indices() {
            for lower in c.to_lowercase() {
                if needle.get(k) != Some(&lower) {
                    continue 'start;
                }
                k += 1;
            }
            if k == needle.len() {
                return Some((start, start + offset + c.len_utf8()));
            }
        }
    }
    None
}

fn head(s: &str, n: usize) -> String {
    let mut out: String = s.chars().take(n).collect();
    if s.chars().nth(n).is_some() {
        out.push('…');
    }
    out
}

fn tail(s: &str, n: usize) -> String {
    let count = s.chars().count();
    if count <= n {
        return s.to_owned();
    }
    let mut out = String::from("…");
    out.extend(s.chars().skip(count - n));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use cairn_proto::UserId;

    fn entry(body: &str) -> Entry {
        Entry {
            sender: UserId::new(),
            sent_at_ms: 1,
            body: body.as_bytes().to_vec(),
            attachment_name: None,
            id: None,
            reply_to: None,
            reaction: None,
        }
    }

    #[test]
    fn matching_ignores_case_and_keeps_the_original_spelling() {
        let hits = search_entries("r", &[entry("Meet at the Café ÉTOILE")], "café étoile");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].matched, "Café ÉTOILE");
        assert_eq!(hits[0].before, "Meet at the ");
    }

    #[test]
    fn a_blank_query_finds_nothing_rather_than_everything() {
        assert!(search_entries("r", &[entry("anything")], "   ").is_empty());
    }

    #[test]
    fn a_reaction_is_not_a_search_result() {
        let mut reaction = entry("");
        reaction.reaction = Some(crate::conversation::Reaction {
            target: crate::conversation::MessageRef { sender: UserId::new(), id: "ab".repeat(32) },
            emoji: Some("👍".to_owned()),
        });
        assert!(search_entries("r", &[reaction], "👍").is_empty());
    }

    #[test]
    fn context_is_trimmed_on_character_boundaries() {
        let long = format!("{}needle{}", "é".repeat(100), "ü".repeat(200));
        let hit = &search_entries("r", &[entry(&long)], "NEEDLE")[0];
        assert_eq!(hit.before.chars().count(), BEFORE_CHARS + 1);
        assert_eq!(hit.after.chars().count(), AFTER_CHARS + 1);
        assert_eq!(hit.matched, "needle");
    }
}
