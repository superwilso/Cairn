//! Out-of-band key verification — safety numbers.
//!
//! ## What this closes
//!
//! `docs/01-threat-model.md` §4 lists key substitution as the main thing a *malicious*
//! server can do that an honest-but-curious one cannot. The server distributes key
//! material, so it can hand Alice a key it controls and claim it is Bob's — the classic
//! active MITM. No amount of MLS fixes this, because MLS protects a group whose members
//! were correctly identified in the first place.
//!
//! The defence is for the two humans to compare a short value derived from both identity
//! keys over a channel the server does not control: in person, over a phone call, on a
//! video call. If the numbers match, no substitution happened. If they differ, something
//! is wrong.
//!
//! Until key transparency exists (still outstanding), this is the *only* protection
//! against a malicious server, which is why it belongs in the same release as encryption
//! rather than a later one.
//!
//! ## Construction
//!
//! Follows the design Signal uses for its safety numbers:
//!
//! 1. Iterate a hash over the identity key and a stable identifier many times. The
//!    iteration count is a deliberate cost: it makes searching for a key whose fingerprint
//!    collides in the displayed digits expensive, since only the truncated, displayed
//!    portion has to collide to fool a human.
//! 2. Truncate to 30 bytes and render as 6 groups of 5 decimal digits per party.
//! 3. Concatenate both parties' halves in a **sorted** order, so both sides display the
//!    same number without needing to agree who is "first".

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use subtle::ConstantTimeEq;

/// Hash iterations, matching Signal's choice.
///
/// High enough to make grinding a colliding fingerprint costly, low enough that computing
/// one is imperceptible.
const ITERATIONS: u32 = 5200;

/// Fingerprint version. Bump if the construction changes — a silent change would make
/// previously verified contacts appear unverified, or worse, appear verified when they
/// are not.
const VERSION: u8 = 1;

/// Digits shown per party. Two parties therefore display 60 digits.
const DIGIT_GROUPS: usize = 6;

/// A stable fingerprint of one participant's identity key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fingerprint([u8; 30]);

impl Fingerprint {
    /// Compute the fingerprint of an identity key bound to a stable identifier.
    ///
    /// `stable_identifier` must be something that does not change between sessions — the
    /// user's account ID, not a device or session ID. Binding the key to an identifier is
    /// what stops a server presenting Bob's real key while claiming it belongs to Carol.
    pub fn compute(public_key: &[u8], stable_identifier: &[u8]) -> Self {
        let mut hash = Sha512::new()
            .chain_update([VERSION])
            .chain_update(public_key)
            .chain_update(stable_identifier)
            .finalize()
            .to_vec();

        // Re-mixing the key on every iteration means an attacker cannot precompute a
        // chain independent of the key they are trying to match.
        for _ in 0..ITERATIONS {
            hash = Sha512::new().chain_update(&hash).chain_update(public_key).finalize().to_vec();
        }

        let mut out = [0u8; 30];
        out.copy_from_slice(&hash[..30]);
        Self(out)
    }

    /// The six 5-digit groups this fingerprint contributes to a safety number.
    fn digit_groups(&self) -> Vec<String> {
        self.0
            .chunks(5)
            .take(DIGIT_GROUPS)
            .map(|chunk| {
                // Each 5-byte chunk becomes one 5-digit group.
                let mut acc: u64 = 0;
                for &b in chunk {
                    acc = (acc << 8) | u64::from(b);
                }
                format!("{:05}", acc % 100_000)
            })
            .collect()
    }

    pub fn as_bytes(&self) -> &[u8; 30] {
        &self.0
    }
}

/// A safety number two people compare out of band.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SafetyNumber(String);

impl SafetyNumber {
    /// Derive the safety number for a pair of participants.
    ///
    /// Order-independent: both sides compute the same value without negotiating who is
    /// first. That matters because a UI that showed different numbers to each party would
    /// be unusable, and users would learn to ignore a mismatch.
    pub fn between(a: &Fingerprint, b: &Fingerprint) -> Self {
        let (first, second) = if a.0 <= b.0 { (a, b) } else { (b, a) };
        let mut groups = first.digit_groups();
        groups.extend(second.digit_groups());
        Self(groups.join(" "))
    }

    /// The displayable form: 12 groups of 5 digits.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The digits with no separators, for QR codes and scanning.
    pub fn digits(&self) -> String {
        self.0.chars().filter(char::is_ascii_digit).collect()
    }

    /// Constant-time comparison against a scanned or typed value.
    ///
    /// Constant time is arguably unnecessary here, since both values are shown to the
    /// user anyway. It costs nothing and removes the need to reason about whether a
    /// timing signal on verification could ever matter.
    pub fn matches(&self, other: &SafetyNumber) -> bool {
        self.0.as_bytes().ct_eq(other.0.as_bytes()).into()
    }
}

impl std::fmt::Display for SafetyNumber {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Whether a contact's key has been verified out of band, and whether it has since changed.
///
/// A changed key after verification is the signal that matters most. It is benign when a
/// contact reinstalls, and it is exactly what an active MITM looks like — so the UI must
/// surface it rather than silently re-trusting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationState {
    /// Never verified out of band.
    Unverified,
    /// Verified, and the key has not changed since.
    Verified,
    /// Verified previously, but the identity key has since changed. **Warn loudly.**
    ChangedSinceVerified,
}

/// A contact's verification record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContactVerification {
    pub fingerprint: Fingerprint,
    pub state: VerificationState,
}

impl ContactVerification {
    pub fn new(fingerprint: Fingerprint) -> Self {
        Self { fingerprint, state: VerificationState::Unverified }
    }

    /// Record that the user compared safety numbers out of band and they matched.
    pub fn mark_verified(&mut self) {
        self.state = VerificationState::Verified;
    }

    /// Observe the contact's current identity key.
    ///
    /// If it differs from what was verified, the state moves to
    /// [`VerificationState::ChangedSinceVerified`] and **stays there** until the user
    /// re-verifies. It must never silently return to `Verified`: that would erase exactly
    /// the evidence the user needs.
    pub fn observe(&mut self, current: Fingerprint) {
        if current != self.fingerprint {
            self.fingerprint = current;
            self.state = match self.state {
                VerificationState::Unverified => VerificationState::Unverified,
                VerificationState::Verified | VerificationState::ChangedSinceVerified => {
                    VerificationState::ChangedSinceVerified
                }
            };
        }
    }

    /// Whether the UI should warn the user before they send.
    pub fn needs_attention(&self) -> bool {
        self.state == VerificationState::ChangedSinceVerified
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fp(key: &[u8], id: &[u8]) -> Fingerprint {
        Fingerprint::compute(key, id)
    }

    #[test]
    fn fingerprint_is_deterministic() {
        assert_eq!(fp(b"key-a", b"alice"), fp(b"key-a", b"alice"));
    }

    #[test]
    fn different_keys_give_different_fingerprints() {
        assert_ne!(fp(b"key-a", b"alice"), fp(b"key-b", b"alice"));
    }

    #[test]
    fn same_key_under_different_identities_differs() {
        // Binding to the identifier is what stops a server presenting a real key while
        // claiming it belongs to someone else.
        assert_ne!(fp(b"key-a", b"alice"), fp(b"key-a", b"carol"));
    }

    #[test]
    fn safety_number_is_order_independent() {
        // Both parties must see the same number without agreeing who is first.
        let a = fp(b"key-a", b"alice");
        let b = fp(b"key-b", b"bob");
        assert_eq!(SafetyNumber::between(&a, &b), SafetyNumber::between(&b, &a));
    }

    #[test]
    fn safety_number_has_sixty_digits_in_twelve_groups() {
        let n = SafetyNumber::between(&fp(b"key-a", b"alice"), &fp(b"key-b", b"bob"));
        assert_eq!(n.digits().len(), 60);
        assert_eq!(n.as_str().split(' ').count(), 12);
        assert!(n
            .as_str()
            .split(' ')
            .all(|g| g.len() == 5 && g.chars().all(|c| c.is_ascii_digit())));
    }

    #[test]
    fn substituting_a_key_changes_the_safety_number() {
        // The whole point: an active MITM cannot preserve the displayed number.
        let alice = fp(b"alice-key", b"alice");
        let real_bob = fp(b"bob-key", b"bob");
        let server_key = fp(b"attacker-key", b"bob");

        let honest = SafetyNumber::between(&alice, &real_bob);
        let attacked = SafetyNumber::between(&alice, &server_key);
        assert_ne!(honest, attacked, "key substitution must be visible to the user");
    }

    #[test]
    fn matching_is_reflexive_and_rejects_others() {
        let a = SafetyNumber::between(&fp(b"k1", b"a"), &fp(b"k2", b"b"));
        let b = SafetyNumber::between(&fp(b"k3", b"a"), &fp(b"k4", b"b"));
        assert!(a.matches(&a.clone()));
        assert!(!a.matches(&b));
    }

    #[test]
    fn a_changed_key_after_verification_is_flagged() {
        let mut contact = ContactVerification::new(fp(b"bob-key", b"bob"));
        assert!(!contact.needs_attention());

        contact.mark_verified();
        assert_eq!(contact.state, VerificationState::Verified);
        assert!(!contact.needs_attention());

        // Bob's key changes — a reinstall, or an active attack. Indistinguishable here,
        // which is precisely why the user must be told.
        contact.observe(fp(b"new-bob-key", b"bob"));
        assert_eq!(contact.state, VerificationState::ChangedSinceVerified);
        assert!(contact.needs_attention());
    }

    #[test]
    fn a_flagged_contact_does_not_silently_become_verified_again() {
        // Re-observing must never clear the warning; only an explicit re-verification by
        // the user may do that. Otherwise the evidence disappears on the next sync.
        let mut contact = ContactVerification::new(fp(b"bob-key", b"bob"));
        contact.mark_verified();
        contact.observe(fp(b"attacker-key", b"bob"));
        assert!(contact.needs_attention());

        contact.observe(fp(b"attacker-key", b"bob"));
        assert!(contact.needs_attention(), "re-observing the same key must not clear the warning");

        contact.observe(fp(b"another-key", b"bob"));
        assert!(contact.needs_attention());
    }

    #[test]
    fn observing_an_unchanged_key_preserves_verification() {
        let mut contact = ContactVerification::new(fp(b"bob-key", b"bob"));
        contact.mark_verified();
        contact.observe(fp(b"bob-key", b"bob"));
        assert_eq!(contact.state, VerificationState::Verified);
    }

    #[test]
    fn unverified_contact_rotating_keys_stays_unverified() {
        let mut contact = ContactVerification::new(fp(b"bob-key", b"bob"));
        contact.observe(fp(b"bob-key-2", b"bob"));
        assert_eq!(contact.state, VerificationState::Unverified);
        assert!(!contact.needs_attention());
    }
}
