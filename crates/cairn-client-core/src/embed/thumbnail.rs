//! Thumbnails, made on the sender's device and carried inside the encrypted card.
//!
//! ## Why the sender fetches the image
//!
//! A card that names an image URL and leaves the recipient to load it has moved the leak onto
//! the recipient — the platform's CDN learns their IP address and that they looked, which is
//! precisely what `docs/05-embeds.md` exists to prevent. So the **sender** fetches the image
//! (the same device that already fetched the page, contacting the same platform's CDN),
//! shrinks it, and puts the bytes in the card. The recipient renders those bytes and fetches
//! nothing.
//!
//! ## Why it is re-encoded rather than passed through
//!
//! - **Size.** A card travels in every copy of the message. A 2 MB `og:image` in each one is
//!   a file transfer wearing a card's clothes. Re-encoding to a small JPEG bounds it.
//! - **Metadata.** Re-encoding from decoded pixels drops EXIF — including location — by
//!   construction (`docs/05-embeds.md`: "Strip EXIF from re-hosted images").
//! - **Parser exposure.** The recipient's webview decodes whatever the sender put in the
//!   card. Re-encoding means an honest sender only ever ships baseline JPEG; [`Thumbnail::clamp`]
//!   refuses anything else on receipt. A hostile sender can still hand-craft a JPEG, and the
//!   webview's decoder is what meets it — the same exposure every messenger that shows an
//!   image has, stated rather than implied away.
//!
//! The image is a claim, like everything else on a card: the sender chose these pixels.

use serde::{Deserialize, Serialize};

/// Widest a thumbnail is made. A card is a few hundred pixels across on any screen.
pub const MAX_WIDTH: u32 = 480;
/// Tallest. Reels are 9:16, so a portrait thumbnail needs more height than width.
pub const MAX_HEIGHT: u32 = 640;
/// The largest encoded thumbnail a card may carry, before base64.
///
/// Bounded on receipt as well as on creation: these bytes come from the sender, and a
/// hostile one could otherwise use a "thumbnail" to push megabytes into every recipient's
/// transcript.
pub const MAX_BYTES: usize = 48 * 1024;

/// A small image inside a card.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Thumbnail {
    /// Always `image/jpeg` from this code. Anything else is dropped on receipt.
    pub mime: String,
    pub width: u32,
    pub height: u32,
    /// Standard base64 of the encoded image.
    pub data: String,
}

impl Thumbnail {
    /// Keep a received thumbnail only if it is the shape this code produces.
    ///
    /// Checked on receipt because the bytes are the sender's: a mime type other than JPEG,
    /// data that is not base64, a payload over [`MAX_BYTES`], or dimensions outside the
    /// bounds all mean somebody built this by hand, and none of them is worth rendering.
    pub fn clamp(self) -> Option<Self> {
        use base64::Engine as _;
        if self.mime != "image/jpeg"
            || self.width == 0
            || self.height == 0
            || self.width > MAX_WIDTH
            || self.height > MAX_HEIGHT
            || self.data.len() > MAX_BYTES.div_ceil(3) * 4
        {
            return None;
        }
        let bytes = base64::engine::general_purpose::STANDARD.decode(&self.data).ok()?;
        // JPEG's start-of-image marker. Cheap, and it means a data: URI built from this is
        // at least claiming to be what its mime type says.
        if bytes.len() > MAX_BYTES || !bytes.starts_with(&[0xFF, 0xD8, 0xFF]) {
            return None;
        }
        Some(self)
    }

    /// The `data:` URI a UI puts in an `<img>`. Only ever built from a clamped thumbnail.
    pub fn data_uri(&self) -> String {
        format!("data:{};base64,{}", self.mime, self.data)
    }

    /// Whether this is taller than it is wide — the shape of a reel or a short.
    pub fn is_portrait(&self) -> bool {
        self.height > self.width
    }
}

#[cfg(feature = "http")]
pub use make::from_image_bytes;

#[cfg(feature = "http")]
mod make {
    use super::{Thumbnail, MAX_BYTES, MAX_HEIGHT, MAX_WIDTH};

    /// Largest source image decoded, per side. A small file can declare enormous
    /// dimensions — a decompression bomb — and the decoder refuses before allocating.
    const MAX_SOURCE_SIDE: u32 = 4096;
    /// Ceiling on what the decoder may allocate for one image.
    const MAX_SOURCE_ALLOC: u64 = 64 * 1024 * 1024;

    /// Decode an image, shrink it, and re-encode it as a small JPEG.
    ///
    /// `None` for anything that is not a JPEG, PNG or WebP within the limits, or that
    /// cannot be brought under [`MAX_BYTES`]. A card without a thumbnail is a perfectly good
    /// card; a failure here never blocks one.
    pub fn from_image_bytes(bytes: &[u8]) -> Option<Thumbnail> {
        use base64::Engine as _;
        use image::{ImageFormat, ImageReader, Limits};

        let format = image::guess_format(bytes).ok()?;
        if !matches!(format, ImageFormat::Jpeg | ImageFormat::Png | ImageFormat::WebP) {
            return None;
        }
        let mut reader = ImageReader::with_format(std::io::Cursor::new(bytes), format);
        let mut limits = Limits::default();
        limits.max_image_width = Some(MAX_SOURCE_SIDE);
        limits.max_image_height = Some(MAX_SOURCE_SIDE);
        limits.max_alloc = Some(MAX_SOURCE_ALLOC);
        reader.limits(limits);
        let decoded = reader.decode().ok()?;

        // Alpha has nowhere to go in a JPEG; flatten rather than let the encoder refuse.
        let mut rgb = image::DynamicImage::ImageRgb8(decoded.to_rgb8());
        let mut bounds = (MAX_WIDTH, MAX_HEIGHT);
        // Quality first, then size: a smaller image at decent quality reads better than a
        // full-width one full of block artefacts.
        for _ in 0..3 {
            if rgb.width() > bounds.0 || rgb.height() > bounds.1 {
                rgb = rgb.resize(bounds.0, bounds.1, image::imageops::FilterType::Triangle);
            }
            for quality in [72u8, 55, 40] {
                let mut out = Vec::new();
                let encoder = image::codecs::jpeg::JpegEncoder::new_with_quality(&mut out, quality);
                rgb.write_with_encoder(encoder).ok()?;
                if out.len() <= MAX_BYTES {
                    return Some(Thumbnail {
                        mime: "image/jpeg".to_string(),
                        width: rgb.width(),
                        height: rgb.height(),
                        data: base64::engine::general_purpose::STANDARD.encode(&out),
                    });
                }
            }
            bounds = (bounds.0 * 2 / 3, bounds.1 * 2 / 3);
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "http")]
    fn encode(img: image::DynamicImage, format: image::ImageFormat) -> Vec<u8> {
        let mut out = std::io::Cursor::new(Vec::new());
        img.write_to(&mut out, format).unwrap();
        out.into_inner()
    }

    #[cfg(feature = "http")]
    fn noisy(w: u32, h: u32) -> image::DynamicImage {
        // Noise, so the JPEG cannot compress it to nothing and the size cap is exercised.
        let mut seed = 0x2545_f491_u32;
        image::DynamicImage::ImageRgb8(image::RgbImage::from_fn(w, h, |_, _| {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            let [a, b, c, _] = seed.to_le_bytes();
            image::Rgb([a, b, c])
        }))
    }

    #[test]
    #[cfg(feature = "http")]
    fn a_large_image_becomes_a_small_jpeg_within_every_bound() {
        let png = encode(noisy(1600, 1200), image::ImageFormat::Png);
        assert!(png.len() > 2 * MAX_BYTES, "the source must be big enough to need shrinking");
        let thumb = from_image_bytes(&png).expect("a thumbnail");
        assert_eq!(thumb.mime, "image/jpeg");
        assert!(thumb.width <= MAX_WIDTH && thumb.height <= MAX_HEIGHT);
        assert!(thumb.clone().clamp().is_some(), "what we make must survive our own receipt check");
    }

    #[test]
    #[cfg(feature = "http")]
    fn a_portrait_reel_frame_stays_portrait() {
        let jpeg = encode(noisy(720, 1280), image::ImageFormat::Jpeg);
        let thumb = from_image_bytes(&jpeg).unwrap();
        assert!(thumb.is_portrait());
        assert!(thumb.height <= MAX_HEIGHT);
    }

    #[test]
    #[cfg(feature = "http")]
    fn exif_does_not_survive_re_encoding() {
        // A JPEG carrying an APP1/Exif segment with a recognisable payload. Re-encoding from
        // pixels must drop it — location data in a re-hosted photo is a leak the sender did
        // not intend.
        let clean = encode(noisy(64, 64), image::ImageFormat::Jpeg);
        let payload = b"Exif\0\0GPS-LATITUDE-51.5007";
        let mut with_exif = vec![0xFF, 0xD8, 0xFF, 0xE1];
        with_exif.extend_from_slice(&((payload.len() + 2) as u16).to_be_bytes());
        with_exif.extend_from_slice(payload);
        with_exif.extend_from_slice(&clean[2..]);

        let thumb = from_image_bytes(&with_exif).expect("still a valid JPEG");
        use base64::Engine as _;
        let out = base64::engine::general_purpose::STANDARD.decode(thumb.data).unwrap();
        assert!(
            !out.windows(12).any(|w| w == b"GPS-LATITUDE"),
            "the source's metadata must not reach the card"
        );
    }

    #[test]
    #[cfg(feature = "http")]
    fn a_decompression_bomb_is_refused_before_it_is_decoded() {
        // A tiny PNG declaring 20000x20000 pixels: 1.2 GB once decoded.
        let mut png = encode(noisy(8, 8), image::ImageFormat::Png);
        png[16..20].copy_from_slice(&20_000u32.to_be_bytes());
        png[20..24].copy_from_slice(&20_000u32.to_be_bytes());
        assert!(from_image_bytes(&png).is_none());
    }

    #[test]
    #[cfg(feature = "http")]
    fn things_that_are_not_images_make_no_thumbnail() {
        for junk in [&b"<html><script>alert(1)</script>"[..], b"GIF89a....", b"", b"\xFF\xD8\xFF"] {
            assert!(from_image_bytes(junk).is_none());
        }
    }

    #[test]
    fn a_hand_built_thumbnail_is_dropped_on_receipt() {
        // The sender controls these bytes. Anything this code would not have produced is
        // not rendered.
        use base64::Engine as _;
        let jpeg_ish = base64::engine::general_purpose::STANDARD.encode([0xFF, 0xD8, 0xFF, 0xE0]);
        let ok = Thumbnail { mime: "image/jpeg".into(), width: 10, height: 10, data: jpeg_ish };
        assert!(ok.clone().clamp().is_some(), "counterfactual: a well-formed one survives");

        let cases = [
            Thumbnail { mime: "image/svg+xml".into(), ..ok.clone() },
            Thumbnail { mime: "text/html".into(), ..ok.clone() },
            Thumbnail { data: "not base64!\"><script>".into(), ..ok.clone() },
            Thumbnail { data: "A".repeat(MAX_BYTES * 2), ..ok.clone() },
            Thumbnail {
                data: base64::engine::general_purpose::STANDARD.encode(b"<svg onload=x>"),
                ..ok.clone()
            },
            Thumbnail { width: 10_000, ..ok.clone() },
            Thumbnail { height: 0, ..ok.clone() },
        ];
        for bad in cases {
            assert!(bad.clone().clamp().is_none(), "must drop {:?}", bad.mime);
        }
    }
}
