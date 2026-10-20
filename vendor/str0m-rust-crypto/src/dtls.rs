//! DTLS implementation using dimpl with RustCrypto backend.

use std::sync::Arc;
use std::time::Instant;

use str0m_proto::crypto::CryptoError;
use str0m_proto::crypto::DtlsVersion;
use str0m_proto::crypto::dtls::ProtocolVersion;
use str0m_proto::crypto::dtls::{DtlsCert, DtlsImplError, DtlsInstance, DtlsOutput, DtlsProvider};

// ============================================================================
// DTLS Provider Implementation
// ============================================================================

#[derive(Debug)]
pub(super) struct RustCryptoDtlsProvider;

impl DtlsProvider for RustCryptoDtlsProvider {
    fn generate_certificate(&self) -> Option<DtlsCert> {
        // Cairn: upstream calls dimpl's rcgen-based generator here. See VENDORED.md.
        self_signed().ok()
    }

    fn new_dtls(
        &self,
        cert: &DtlsCert,
        now: Instant,
        dtls_version: DtlsVersion,
        mtu: Option<usize>,
    ) -> Result<Box<dyn DtlsInstance>, CryptoError> {
        let dimpl_cert = dimpl::DtlsCertificate {
            certificate: cert.certificate.clone(),
            private_key: cert.private_key.clone(),
        };

        // Create a default dimpl Config with RustCrypto crypto provider
        // ICE verifies return routability before DTLS, making server cookies redundant.
        let mut builder = dimpl::Config::builder().use_server_cookie(false);
        if let Some(mtu) = mtu {
            builder = builder.mtu(mtu);
        }
        if self.is_test() {
            // We need the DTLS impl to be deterministic for the BWE tests.
            builder = builder.dangerously_set_rng_seed(42);
        }

        let config = builder
            .build()
            .map_err(|e| CryptoError::Other(format!("dimpl config creation failed: {}", e)))?;

        let config = Arc::new(config);
        let dtls = match dtls_version {
            DtlsVersion::Dtls12 => dimpl::Dtls::new_12(config, dimpl_cert, now),
            DtlsVersion::Dtls13 => dimpl::Dtls::new_13(config, dimpl_cert, now),
            DtlsVersion::Auto => dimpl::Dtls::new_auto(config, dimpl_cert, now),
            _ => {
                return Err(CryptoError::Other(format!(
                    "Unsupported DTLS version: {dtls_version}"
                )));
            }
        };

        Ok(Box::new(RustCryptoDtlsInstance { dtls }))
    }
}

/// A self-signed ECDSA P-256 / SHA-256 certificate and its PKCS#8 key, in DER — the same
/// shape dimpl's rcgen path produces. WebRTC peers pin the certificate by the fingerprint
/// carried in the SDP, so nothing here is checked against a trust store; the random serial
/// matters only because Firefox refuses two certificates with the same issuer and serial.
fn self_signed() -> Result<DtlsCert, String> {
    use p256::ecdsa::{DerSignature, SigningKey};
    use p256::pkcs8::EncodePrivateKey;
    use rand_core::{OsRng, RngCore};
    use x509_cert::builder::{Builder, CertificateBuilder, Profile};
    use x509_cert::der::Encode;
    use x509_cert::name::Name;
    use x509_cert::serial_number::SerialNumber;
    use x509_cert::spki::SubjectPublicKeyInfoOwned;
    use x509_cert::time::Validity;

    let e = |e: &dyn std::fmt::Display| e.to_string();
    let key = SigningKey::random(&mut OsRng);
    let mut serial = [0u8; 16];
    OsRng.fill_bytes(&mut serial);
    // A positive INTEGER: DER would otherwise read a set top bit as negative.
    serial[0] &= 0x7f;
    serial[0] |= 0x01;
    let serial = SerialNumber::new(&serial).map_err(|x| e(&x))?;
    let validity =
        Validity::from_now(std::time::Duration::from_secs(365 * 24 * 3600)).map_err(|x| e(&x))?;
    let subject: Name = "CN=DTLS Peer,O=DTLS".parse().map_err(|x: x509_cert::der::Error| e(&x))?;
    let spki = SubjectPublicKeyInfoOwned::from_key(*key.verifying_key()).map_err(|x| e(&x))?;
    // Self-signed: the issuer is the subject. A leaf, so it states it is not a CA.
    let profile = Profile::Leaf {
        issuer: subject.clone(),
        enable_key_agreement: false,
        enable_key_encipherment: false,
    };
    let cert = CertificateBuilder::new(profile, serial, validity, subject, spki, &key)
        .map_err(|x| e(&x))?
        .build::<DerSignature>()
        .map_err(|x| e(&x))?;
    Ok(DtlsCert {
        certificate: cert.to_der().map_err(|x| e(&x))?,
        private_key: key.to_pkcs8_der().map_err(|x| e(&x))?.as_bytes().to_vec(),
    })
}

#[cfg(test)]
mod cairn_tests {
    use super::*;

    #[test]
    fn the_generated_certificate_parses_and_serials_differ() {
        use p256::pkcs8::DecodePrivateKey;
        use x509_cert::der::Decode;
        let a = self_signed().expect("certificate");
        let b = self_signed().expect("certificate");
        let ca = x509_cert::Certificate::from_der(&a.certificate).expect("DER certificate");
        let cb = x509_cert::Certificate::from_der(&b.certificate).expect("DER certificate");
        assert_ne!(ca.tbs_certificate.serial_number, cb.tbs_certificate.serial_number);
        // The key form dimpl loads first (`SigningKey::from_pkcs8_der`), and it must be the
        // key the certificate names, or every handshake fails its CertificateVerify.
        let key = p256::ecdsa::SigningKey::from_pkcs8_der(&a.private_key).expect("PKCS#8 key");
        let named = ca.tbs_certificate.subject_public_key_info.subject_public_key.raw_bytes();
        assert_eq!(key.verifying_key().to_encoded_point(false).as_bytes(), named);
        // The handshake itself is exercised against a real browser in
        // crates/cairn-server/tests/voice_sfu.rs and clients/desktop/tests/voicechannel.browser.test.js.
        let _ = (Arc::new(()), Instant::now());
    }
}

// ============================================================================
// DTLS Instance Wrapper
// ============================================================================

struct RustCryptoDtlsInstance {
    dtls: dimpl::Dtls,
}

impl std::fmt::Debug for RustCryptoDtlsInstance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RustCryptoDtlsInstance").finish()
    }
}

impl DtlsInstance for RustCryptoDtlsInstance {
    fn set_active(&mut self, active: bool) {
        self.dtls.set_active(active);
    }

    fn handle_packet(&mut self, packet: &[u8]) -> Result<(), DtlsImplError> {
        self.dtls.handle_packet(packet)
    }

    fn poll_output<'a>(&mut self, buf: &'a mut [u8]) -> DtlsOutput<'a> {
        self.dtls.poll_output(buf)
    }

    fn handle_timeout(&mut self, now: Instant) -> Result<(), DtlsImplError> {
        self.dtls.handle_timeout(now)
    }

    fn send_application_data(&mut self, data: &[u8]) -> Result<(), DtlsImplError> {
        self.dtls.send_application_data(data)
    }

    fn is_active(&self) -> bool {
        self.dtls.is_active()
    }

    fn protocol_version(&self) -> Option<ProtocolVersion> {
        self.dtls.protocol_version()
    }

    fn is_closing(&self) -> bool {
        self.dtls.is_closing()
    }

    fn is_closed(&self) -> bool {
        self.dtls.is_closed()
    }

    fn close(&mut self) -> Result<(), DtlsImplError> {
        self.dtls.close()
    }
}
