//! Attachment encryption.
//!
//! The server stores attachment bytes it cannot read (`cairn-server`'s blob store), which
//! only means anything if the client encrypts them first. This is that step.
//!
//! ## Shape
//!
//! Each attachment gets a **fresh random key**, used once and never again. The key travels
//! inside the encrypted message body — that is the whole design, and the reason a tier's
//! guarantee extends to attachments rather than stopping at message text. A key that
//! travelled beside the ciphertext, or in any field the server can read, would make the
//! blob store's ignorance decorative.
//!
//! ## Why substitution is already handled
//!
//! An earlier draft of this module carried a content hash so a recipient could detect the
//! server swapping one attachment's bytes for another's. It is redundant: the swapped bytes
//! were sealed under a *different* key, so opening them under this attachment's key fails
//! the authentication tag. Truncation and bit-flips fail the same way. A hash field would
//! have looked like a protection and added none, which is worse than not having one.
//!
//! ## Ciphersuite
//!
//! XChaCha20-Poly1305. The 192-bit nonce means a randomly generated nonce has no realistic
//! collision risk, so this does not need a counter it would have to persist — and an
//! attachment path that silently reused a nonce after a restart is exactly the kind of
//! failure that does not announce itself.
//!
//! `chacha20poly1305` is not a new dependency: `mls-rs-crypto-rustcrypto` already pulls it
//! into the build, so this adds nothing to a supply chain kept deliberately small.

use chacha20poly1305::aead::{Aead, KeyInit, OsRng};
use chacha20poly1305::{AeadCore, XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// How many bytes the nonce prefix takes at the front of a sealed attachment.
const NONCE_LEN: usize = 24;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AttachmentError {
    #[error("attachment could not be opened: wrong key, or the bytes were altered")]
    NotAuthentic,
    #[error("attachment is too short to contain a nonce")]
    Truncated,
}

/// A single-use key for one attachment.
///
/// Serialized into the *encrypted* message body and nowhere else. `Zeroize` on drop and a
/// redacted `Debug`, per the project's rule that secrets never appear in `Debug` output —
/// a key printed into a log is a key on disk.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct AttachmentKey(#[serde(with = "crate::franking::hex_array")] [u8; 32]);

impl std::fmt::Debug for AttachmentKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AttachmentKey(<redacted>)")
    }
}

impl AttachmentKey {
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }
}

/// Encrypt an attachment under a fresh key.
///
/// Returns the key — which belongs in the encrypted message body — and the bytes to upload,
/// which are `nonce || ciphertext || tag` and are what the server stores.
pub fn seal(plaintext: &[u8]) -> (AttachmentKey, Vec<u8>) {
    let key = AttachmentKey::generate();
    let cipher = XChaCha20Poly1305::new((&key.0).into());
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);

    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .expect("XChaCha20-Poly1305 encryption cannot fail for an in-memory plaintext");

    let mut sealed = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    sealed.extend_from_slice(nonce.as_slice());
    sealed.extend_from_slice(&ciphertext);
    (key, sealed)
}

/// Decrypt an attachment fetched from a blob store.
///
/// Fails rather than returning anything if the bytes were altered, truncated, or are a
/// different attachment's — which is what makes it safe to accept these from a server the
/// threat model treats as semi-trusted.
pub fn open(key: &AttachmentKey, sealed: &[u8]) -> Result<Vec<u8>, AttachmentError> {
    if sealed.len() < NONCE_LEN {
        return Err(AttachmentError::Truncated);
    }
    let (nonce, ciphertext) = sealed.split_at(NONCE_LEN);
    let cipher = XChaCha20Poly1305::new((&key.0).into());
    cipher.decrypt(XNonce::from_slice(nonce), ciphertext).map_err(|_| AttachmentError::NotAuthentic)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_attachment_round_trips() {
        let plaintext: Vec<u8> = (0..10_000).map(|i| (i % 251) as u8).collect();
        let (key, sealed) = seal(&plaintext);
        assert_eq!(open(&key, &sealed).unwrap(), plaintext);
    }

    #[test]
    fn the_sealed_bytes_do_not_contain_the_plaintext() {
        // The property the whole blob store depends on. If this fails, the server holds
        // readable attachments and every claim about attachment privacy is false.
        let plaintext = b"the quick brown fox jumps over the lazy dog".to_vec();
        let (_key, sealed) = seal(&plaintext);
        assert!(
            !sealed.windows(plaintext.len()).any(|w| w == plaintext.as_slice()),
            "sealed bytes must not contain the plaintext"
        );
    }

    #[test]
    fn a_wrong_key_cannot_open_an_attachment() {
        let (_key, sealed) = seal(b"secret");
        let other = AttachmentKey::generate();
        assert_eq!(open(&other, &sealed), Err(AttachmentError::NotAuthentic));
    }

    #[test]
    fn altered_bytes_are_rejected_rather_than_returned() {
        // The server is semi-trusted (`docs/01-threat-model.md` §2) and holds these bytes,
        // so a modified attachment must fail loudly rather than decrypt to something.
        let (key, sealed) = seal(b"an important document");
        for index in [0, NONCE_LEN, sealed.len() - 1] {
            let mut tampered = sealed.clone();
            tampered[index] ^= 0x01;
            assert_eq!(
                open(&key, &tampered),
                Err(AttachmentError::NotAuthentic),
                "a flipped bit at {index} must be caught"
            );
        }
    }

    #[test]
    fn another_attachments_bytes_cannot_be_substituted() {
        // A malicious instance holds every blob and could serve the wrong one. This is why
        // there is no content-hash field: the authentication tag already refuses.
        let (key_a, _sealed_a) = seal(b"attachment A");
        let (_key_b, sealed_b) = seal(b"attachment B");
        assert_eq!(open(&key_a, &sealed_b), Err(AttachmentError::NotAuthentic));
    }

    #[test]
    fn a_truncated_attachment_is_rejected() {
        let (key, sealed) = seal(b"something");
        assert_eq!(open(&key, &sealed[..NONCE_LEN - 1]), Err(AttachmentError::Truncated));
        assert_eq!(open(&key, &sealed[..NONCE_LEN + 2]), Err(AttachmentError::NotAuthentic));
    }

    #[test]
    fn two_seals_of_the_same_bytes_differ() {
        // Otherwise the server could tell that two people sent the same file, which is a
        // content signal it is not supposed to have.
        let (_k1, one) = seal(b"identical");
        let (_k2, two) = seal(b"identical");
        assert_ne!(one, two);
    }

    #[test]
    fn a_key_never_appears_in_debug_output() {
        let key = AttachmentKey::generate();
        let printed = format!("{key:?}");
        assert!(printed.contains("redacted"));
        assert!(!printed.contains(&hex::encode(key.0)));
    }
}
