//! End-to-end encryption for call media that crosses a server.
//!
//! ## Why this exists
//!
//! A mesh call needs none of this: DTLS-SRTP runs between the two devices and nothing sits
//! in the middle. A selective forwarding unit *is* the middle. It terminates DTLS-SRTP from
//! every participant, so without a second layer it holds every participant's audio in the
//! clear. This module is that second layer — the "end-to-end" half of
//! `docs/adr/012-sfu-voice-channels.md`. The SFU forwards what it is given and never holds a
//! key from here.
//!
//! ## Keys
//!
//! One key per **sending device**, per **MLS epoch** of the room's group, exported with the
//! MLS exporter (RFC 9420 §8.5) under [`MEDIA_KEY_LABEL`]. The context is the room id and the
//! sender's credential, each length-prefixed, so no two (room, sender) pairs can produce the
//! same context bytes however their lengths split.
//!
//! What that buys, and what it does not, stated rather than implied:
//!
//! - **The instance cannot derive any key.** It is not in the group. It can drop, delay,
//!   replay or reorder frames — it carries them — but it cannot read or forge one.
//! - **A key is per sender, so the SFU cannot relabel who is speaking.** A frame arriving on
//!   a slot the SFU says is Alice's opens only under Alice's key. Swapping two people's
//!   streams makes both fail to open; it cannot make Bob's words play as Alice's.
//! - **Every member of the room can derive every sender's key.** The exporter is
//!   group-wide. Against another member (A6) a per-sender key authenticates nothing — a
//!   member could seal a frame under Alice's key. That is the same position as a member in
//!   any group call, and per `docs/01-threat-model.md` §5 there is no defence against it.
//! - **Removal rotates the keys, but only once the removal commit is processed.** A removed
//!   member keeps the old epoch's keys and can open anything sealed under them. A sender
//!   who has not yet processed the commit keeps sealing under the old epoch. The SFU stops
//!   forwarding to a removed member at once (that is the instance's rule, in `cairn-server`);
//!   the cryptography only catches up when the commit lands.
//!
//! ## Frame format, version 1
//!
//! ```text
//! ciphertext ‖ GCM tag (16) ‖ iv (12) ‖ epoch (u32 BE) ‖ leaf (u32 BE) ‖ version (1)
//! └──────── AES-128-GCM ──────┘ └──────────── trailer, authenticated as AAD ───────────┘
//! ```
//!
//! The plaintext is `flags (1) ‖ codec frame`. `flags` carries the sender's mute and deafen
//! state, so it reaches the other participants end to end rather than as a message the
//! instance could timestamp.
//!
//! - **A trailer, not a header.** Packetisers for video codecs read the first bytes of a
//!   frame; keeping our bytes at the end leaves the start for them. Only audio crosses the
//!   SFU today, so this is a choice made for later rather than one anything relies on yet.
//! - **A random IV per frame.** A counter would need persisting across rejoins under the
//!   same epoch key, and an IV reused under GCM is catastrophic. 96 random bits per frame
//!   at 50 frames a second stays far inside GCM's random-IV bound for the life of any key,
//!   and the key rotates every epoch besides. It costs 12 bytes a frame.
//! - **`epoch` is the low 32 bits of the MLS epoch** and `leaf` the sender's leaf index in
//!   that epoch. They tell a receiver which key to try. They are in the clear, so the SFU
//!   learns when the room's group changed epoch — which the instance already knows, since it
//!   relayed the commit.
//! - **Not RFC 9605 SFrame.** The shape is the same — a per-sender key from MLS, an AEAD,
//!   key id beside the ciphertext — but the encoding is not SFrame's, and it should not be
//!   described as SFrame. Moving to SFrame proper is a format change, not a redesign.
//! - **AES-GCM is not key-committing.** A frame could in principle be constructed to open
//!   under two different keys. Building one needs both keys, so it is a member's attack, not
//!   the instance's; it is recorded because `docs/12-realtime-media.md` §4 asked that it be.
//!
//! AES-128-GCM rather than the XChaCha20-Poly1305 the attachment code uses, because the
//! frames are sealed in the webview by WebCrypto, which offers AES-GCM and not ChaCha20.
//! The Rust implementation here is the reference the JavaScript must agree with —
//! `clients/desktop/tests/mediaframe.test.js` checks the vector in this module's tests.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Nonce};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// The MLS exporter label for voice media keys. Changing it changes every key.
pub const MEDIA_KEY_LABEL: &[u8] = b"Cairn voice media v1";

/// The last byte of every sealed frame.
pub const FRAME_VERSION: u8 = 0xC1;

/// Bytes after the ciphertext: iv, epoch, leaf, version.
pub const TRAILER_LEN: usize = 12 + 4 + 4 + 1;

const TAG_LEN: usize = 16;

/// Bit 0 of the flags byte: the sender's microphone is closed.
pub const FLAG_MUTED: u8 = 0b01;
/// Bit 1: the sender is deafened (and therefore muted as well).
pub const FLAG_DEAFENED: u8 = 0b10;
/// Bit 2: this frame is from the sender's soundboard track, not their microphone.
///
/// Sealed with the frame, so in an end-to-end call a listener tells a soundboard clip from a
/// voice by the sender's own word, not the SFU's slot mapping — which is what lets "mute this
/// person's soundboard" mute only the clips, whatever the SFU does with the slots.
pub const FLAG_SOUNDBOARD: u8 = 0b100;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MediaError {
    /// Not a version-1 frame at all — too short, or the last byte is wrong. A receiver in an
    /// end-to-end call drops it; it is how plaintext the SFU injected looks.
    #[error("not a sealed media frame")]
    NotSealed,
    /// Shaped like a frame but did not open: wrong key, wrong epoch, or altered bytes.
    #[error("media frame did not open: wrong key, or the bytes were altered")]
    NotAuthentic,
}

/// One sender's media key for one epoch.
///
/// Handed across the FFI line exactly once per epoch, to be imported as a non-extractable
/// WebCrypto key; see `docs/adr/012-sfu-voice-channels.md` for why that is the line and not
/// "the UI never sees it". Redacted in `Debug`, zeroized on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MediaKey([u8; 16]);

impl std::fmt::Debug for MediaKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MediaKey(<redacted>)")
    }
}

impl MediaKey {
    pub(crate) fn from_exported(bytes: &[u8]) -> Result<Self, crate::MlsError> {
        let key: [u8; 16] = bytes
            .try_into()
            .map_err(|_| crate::MlsError::Crypto("exporter returned the wrong length".into()))?;
        Ok(Self(key))
    }

    /// For tests and vectors only: a key from known bytes.
    #[doc(hidden)]
    pub fn from_bytes_for_test(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// The raw key, for import into WebCrypto. The only reason this is public.
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// The exporter context for `sender` in `room`: both length-prefixed.
pub fn key_context(room: &[u8], sender_credential: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + room.len() + sender_credential.len());
    for part in [room, sender_credential] {
        out.extend_from_slice(&(part.len() as u32).to_be_bytes());
        out.extend_from_slice(part);
    }
    out
}

/// Which key a sealed frame names. Read from the clear trailer, before anything is opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameKeyId {
    pub epoch: u32,
    pub leaf: u32,
}

/// Read the key id from a sealed frame without opening it.
pub fn peek(sealed: &[u8]) -> Result<FrameKeyId, MediaError> {
    if sealed.len() < TAG_LEN + TRAILER_LEN + 1 || sealed[sealed.len() - 1] != FRAME_VERSION {
        return Err(MediaError::NotSealed);
    }
    let t = &sealed[sealed.len() - TRAILER_LEN..];
    Ok(FrameKeyId {
        epoch: u32::from_be_bytes(t[12..16].try_into().expect("four bytes")),
        leaf: u32::from_be_bytes(t[16..20].try_into().expect("four bytes")),
    })
}

/// Seal one codec frame. `flags` is [`FLAG_MUTED`] / [`FLAG_DEAFENED`] / [`FLAG_SOUNDBOARD`].
pub fn seal(key: &MediaKey, id: FrameKeyId, flags: u8, frame: &[u8]) -> Vec<u8> {
    let mut iv = [0u8; 12];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut iv);
    seal_with_iv(key, id, flags, frame, iv)
}

/// [`seal`] with a chosen IV. Public only so the cross-language vector can be produced;
/// a caller choosing IVs is a caller who will one day reuse one.
#[doc(hidden)]
pub fn seal_with_iv(
    key: &MediaKey,
    id: FrameKeyId,
    flags: u8,
    frame: &[u8],
    iv: [u8; 12],
) -> Vec<u8> {
    let mut trailer = [0u8; TRAILER_LEN];
    trailer[..12].copy_from_slice(&iv);
    trailer[12..16].copy_from_slice(&id.epoch.to_be_bytes());
    trailer[16..20].copy_from_slice(&id.leaf.to_be_bytes());
    trailer[20] = FRAME_VERSION;

    let mut plaintext = Vec::with_capacity(1 + frame.len());
    plaintext.push(flags);
    plaintext.extend_from_slice(frame);

    let cipher = Aes128Gcm::new(key.0.as_ref().into());
    let mut out = cipher
        .encrypt(Nonce::from_slice(&iv), Payload { msg: &plaintext, aad: &trailer })
        .expect("AES-GCM encryption of an in-memory buffer cannot fail");
    plaintext.zeroize();
    out.extend_from_slice(&trailer);
    out
}

/// Open a sealed frame, returning `(flags, codec frame)`.
pub fn open(key: &MediaKey, sealed: &[u8]) -> Result<(u8, Vec<u8>), MediaError> {
    peek(sealed)?;
    let (body, trailer) = sealed.split_at(sealed.len() - TRAILER_LEN);
    let cipher = Aes128Gcm::new(key.0.as_ref().into());
    let mut plaintext = cipher
        .decrypt(Nonce::from_slice(&trailer[..12]), Payload { msg: body, aad: trailer })
        .map_err(|_| MediaError::NotAuthentic)?;
    if plaintext.is_empty() {
        return Err(MediaError::NotAuthentic);
    }
    let flags = plaintext[0];
    let frame = plaintext.split_off(1);
    Ok((flags, frame))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(b: u8) -> MediaKey {
        MediaKey::from_bytes_for_test([b; 16])
    }

    const ID: FrameKeyId = FrameKeyId { epoch: 7, leaf: 2 };

    #[test]
    fn a_frame_opens_under_its_own_key_and_carries_its_flags() {
        let sealed = seal(&key(1), ID, FLAG_MUTED, b"opus bytes");
        assert_eq!(peek(&sealed).unwrap(), ID);
        assert_eq!(open(&key(1), &sealed).unwrap(), (FLAG_MUTED, b"opus bytes".to_vec()));
    }

    #[test]
    fn a_sealed_frame_does_not_contain_the_audio() {
        // The property the SFU's position depends on, at the smallest scale: what it
        // forwards is not what was said. The browser test checks the same thing on frames
        // the SFU actually saw.
        let audio = b"a recognisable run of codec bytes";
        let sealed = seal(&key(1), ID, 0, audio);
        assert!(!sealed.windows(audio.len()).any(|w| w == audio));
    }

    #[test]
    fn another_senders_key_does_not_open_a_frame() {
        // Per-sender keys are what stop the SFU relabelling who is speaking: Bob's frame
        // delivered on Alice's slot must fail, not play.
        let sealed = seal(&key(1), ID, 0, b"bob speaking");
        assert_eq!(open(&key(2), &sealed), Err(MediaError::NotAuthentic));
    }

    #[test]
    fn an_altered_trailer_or_body_does_not_open() {
        let sealed = seal(&key(1), ID, 0, b"payload");
        for i in 0..sealed.len() - 1 {
            let mut bent = sealed.clone();
            bent[i] ^= 0x01;
            assert!(open(&key(1), &bent).is_err(), "flipping byte {i} went unnoticed");
        }
    }

    #[test]
    fn plaintext_is_not_mistaken_for_a_frame() {
        // What an injected or passthrough frame looks like to a receiver expecting E2EE.
        assert_eq!(peek(b"short"), Err(MediaError::NotSealed));
        let mut plain = vec![0u8; 80];
        plain[79] = 0x00;
        assert_eq!(open(&key(1), &plain), Err(MediaError::NotSealed));
        // Ending in the version byte by chance is caught by the tag instead.
        plain[79] = FRAME_VERSION;
        assert_eq!(open(&key(1), &plain), Err(MediaError::NotAuthentic));
    }

    #[test]
    fn the_context_cannot_be_reproduced_by_moving_a_boundary() {
        assert_ne!(key_context(b"ab", b"c"), key_context(b"a", b"bc"));
    }

    #[test]
    fn a_media_key_is_not_printed() {
        assert!(!format!("{:?}", key(0xAB)).contains("ab"));
        assert!(!format!("{:?}", key(0xAB)).contains("171"));
    }

    /// The vector `clients/desktop/tests/mediaframe.test.js` checks the JavaScript against.
    /// If this changes, that file changes in the same commit — and every client in the field
    /// stops understanding every other one.
    #[test]
    fn the_cross_language_vector() {
        let k = MediaKey::from_bytes_for_test(*b"0123456789abcdef");
        let sealed = seal_with_iv(
            &k,
            FrameKeyId { epoch: 0x0102_0304, leaf: 5 },
            FLAG_MUTED,
            b"hello opus",
            *b"iv-iv-iv-iv-",
        );
        // Computed by Node's WebCrypto, not by this code read back:
        //   subtle.encrypt({name: "AES-GCM", iv, additionalData: trailer}, key, 0x01‖"hello opus")
        assert_eq!(
            hex::encode(&sealed),
            "e126fc7fb205e7918fdcf4dda551589a464b8df80e332b72e3f9b3\
             69762d69762d69762d69762d0102030400000005c1",
            "vector changed"
        );
    }
}
