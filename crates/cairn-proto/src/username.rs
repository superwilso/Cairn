//! Usernames, and the rules that stop two of them looking like one.
//!
//! A username is a **handle you can say out loud**, replacing the raw uuids the client
//! currently makes people paste. It resolves by exact match only — there is no search or
//! listing, so knowing a handle confirms an account exists but nobody can walk the instance
//! for a roster (`docs/10-roadmap.md`).
//!
//! ## Why this is a security type and not a string
//!
//! A username is how one person decides they are talking to another. If two distinct
//! usernames can render identically, an attacker registers the lookalike and receives
//! messages meant for someone else — and the safety-number check that would catch a key
//! substitution never fires, because the victim is genuinely talking to the account they
//! asked for. **Cairn's whole verification story assumes you addressed the right person to
//! begin with.**
//!
//! So the charset is deliberately tiny: lowercase ASCII letters, digits, and underscore.
//! Not "Unicode with confusable detection" — that is a moving target maintained against an
//! adversary, and the first version of it is always incomplete. This gives up legitimate
//! non-Latin handles, which is a real cost and is the reason display names exist separately:
//! a display name can be anything, because nobody addresses a message to one.

use std::fmt;

/// Shortest allowed handle. Below this the space is small enough to enumerate outright.
pub const MIN_USERNAME_LEN: usize = 3;
/// Longest allowed handle, so a name fits a UI and a log line.
pub const MAX_USERNAME_LEN: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UsernameError {
    #[error("a username must be at least {MIN_USERNAME_LEN} characters")]
    TooShort,
    #[error("a username must be at most {MAX_USERNAME_LEN} characters")]
    TooLong,
    #[error(
        "a username may contain only letters a-z, digits, and underscore — \
         characters that look alike are not allowed to differ"
    )]
    IllegalCharacter,
    #[error("a username must start with a letter")]
    MustStartWithLetter,
}

/// A validated, normalised username.
///
/// The only constructor normalises and validates, so a `Username` in hand is already safe to
/// compare with `==`. That is the point of the type: an instance that compared raw strings
/// would treat `Alice` and `alice` as different accounts, and a user typing either would
/// reach whichever one registered first.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
pub struct Username(String);

impl Username {
    /// Normalise and validate. Case is folded, so `@Alice` and `@alice` are one account.
    pub fn parse(input: &str) -> Result<Self, UsernameError> {
        let trimmed = input.trim().trim_start_matches('@');

        // Length is checked on the normalised form, so case folding cannot change the
        // verdict after the fact.
        let normalised = trimmed.to_ascii_lowercase();

        if normalised.chars().count() < MIN_USERNAME_LEN {
            return Err(UsernameError::TooShort);
        }
        if normalised.chars().count() > MAX_USERNAME_LEN {
            return Err(UsernameError::TooLong);
        }
        if !normalised.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_') {
            return Err(UsernameError::IllegalCharacter);
        }
        // A leading digit or underscore invites handles that read as something else —
        // `_alice`, `1alice` — sitting next to the real one in a list.
        if !normalised.starts_with(|c: char| c.is_ascii_lowercase()) {
            return Err(UsernameError::MustStartWithLetter);
        }

        Ok(Self(normalised))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Username {
    /// Rendered with the `@`, which is how a user says it and how it appears in a UI.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "@{}", self.0)
    }
}

impl std::str::FromStr for Username {
    type Err = UsernameError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

/// Deserialization goes through [`Username::parse`], so a username read off the wire or out
/// of storage is validated by the same code that validated it on the way in. A `derive`
/// here would let an unnormalised name enter through JSON and compare unequal to itself.
impl<'de> serde::Deserialize<'de> for Username {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        Username::parse(&raw).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn case_does_not_create_a_second_account() {
        // The impersonation this type exists to prevent: if `Alice` and `alice` were
        // different handles, whoever registered second gets messages meant for the first.
        assert_eq!(Username::parse("Alice").unwrap(), Username::parse("alice").unwrap());
        assert_eq!(Username::parse("@ALICE").unwrap(), Username::parse("alice").unwrap());
    }

    #[test]
    fn a_lookalike_in_another_script_is_refused() {
        // `а` here is Cyrillic U+0430, which renders identically to Latin `a` in most fonts.
        // Accepting it would let someone register a handle indistinguishable from another
        // person's — and the safety number would not help, because the victim really is
        // talking to the account they asked for.
        assert_eq!(Username::parse("аlice"), Err(UsernameError::IllegalCharacter));
        // Nor the mathematical alphanumerics, which are a common bypass for naive filters.
        assert_eq!(Username::parse("𝗮lice"), Err(UsernameError::IllegalCharacter));
    }

    #[test]
    fn invisible_characters_cannot_pad_a_name() {
        // A zero-width joiner would make two identical-looking names compare unequal.
        assert_eq!(Username::parse("ali\u{200d}ce"), Err(UsernameError::IllegalCharacter));
        assert_eq!(Username::parse("alice\u{200b}"), Err(UsernameError::IllegalCharacter));
    }

    #[test]
    fn the_at_sign_and_surrounding_space_are_accepted_and_stripped() {
        // People paste `@alice` and type trailing spaces. Rejecting those is hostile, and
        // accepting them *without* stripping would store two different handles.
        assert_eq!(Username::parse("  @alice  ").unwrap().as_str(), "alice");
    }

    #[test]
    fn a_username_must_start_with_a_letter() {
        assert_eq!(Username::parse("_alice"), Err(UsernameError::MustStartWithLetter));
        assert_eq!(Username::parse("1alice"), Err(UsernameError::MustStartWithLetter));
        assert!(Username::parse("alice_1").is_ok());
    }

    #[test]
    fn lengths_are_bounded_at_both_ends() {
        assert_eq!(Username::parse("ab"), Err(UsernameError::TooShort));
        assert!(Username::parse("abc").is_ok());
        assert!(Username::parse(&"a".repeat(MAX_USERNAME_LEN)).is_ok());
        assert_eq!(Username::parse(&"a".repeat(MAX_USERNAME_LEN + 1)), Err(UsernameError::TooLong));
    }

    #[test]
    fn deserialization_validates_rather_than_trusting_the_wire() {
        // A stored or transmitted name must go through the same gate as a typed one, or an
        // unnormalised handle enters through the side door and compares unequal to itself.
        let unnormalised: Result<Username, _> = serde_json::from_str("\"Alice\"");
        assert_eq!(unnormalised.unwrap().as_str(), "alice");

        let illegal: Result<Username, _> = serde_json::from_str("\"аlice\"");
        assert!(illegal.is_err(), "a lookalike must not enter through deserialization");
    }

    #[test]
    fn display_round_trips_through_parse() {
        let name = Username::parse("alice_1").unwrap();
        assert_eq!(name.to_string(), "@alice_1");
        assert_eq!(Username::parse(&name.to_string()).unwrap(), name);
    }
}
