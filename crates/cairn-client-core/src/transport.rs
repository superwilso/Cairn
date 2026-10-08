//! The seam between Cairn's client logic and however bytes actually reach a server.
//!
//! [`Client`](crate::client::Client) builds and signs every request; a [`Transport`] only
//! moves the resulting bytes. Keeping those apart matters for two reasons beyond
//! tidiness:
//!
//! - **Tests can drive the real client logic without a socket**, so the signing paths are
//!   exercised by the same code that runs in production rather than by a parallel test
//!   implementation that can drift from it. Both room vulnerabilities in this project's
//!   history survived tests written against a mistaken model of the real thing.
//! - **Platform clients bind to the client, not the transport** (ADR-006). A platform
//!   that wants its own networking stack — URLSession on Apple platforms, say — supplies
//!   a `Transport` and still cannot construct an unsigned or wrongly-scoped request.

use std::fmt;

#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("transport failure: {0}")]
    Io(String),
    #[error("server returned {status}: {body}")]
    Status { status: u16, body: String },
}

/// An HTTP-shaped response. Deliberately minimal — the client parses, the transport does
/// not.
#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    /// Raw bytes. A downloaded attachment is ciphertext, and reading it into a `String`
    /// would replace every invalid UTF-8 sequence with U+FFFD — corrupting the payload
    /// while looking like a successful fetch.
    pub body: Vec<u8>,
}

impl Response {
    /// The body as text, for the JSON endpoints. Lossy by construction, which is fine for
    /// JSON and is why binary callers use [`Response::body`] directly.
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

impl Response {
    /// Fail on any non-2xx, carrying the server's message.
    ///
    /// The server's error bodies are written to be actionable ("device is registered to a
    /// different account"), so discarding them in favour of a bare status code would make
    /// every client-side failure undiagnosable.
    pub fn ok(self) -> Result<Self, TransportError> {
        if (200..300).contains(&self.status) {
            Ok(self)
        } else {
            Err(TransportError::Status { status: self.status, body: self.text() })
        }
    }
}

/// A request body, and what it is.
///
/// Bytes rather than `&str`, because attachments are binary and there is no lossless way to
/// carry arbitrary ciphertext through a string. The content type travels with the bytes
/// rather than being assumed by the transport: it was previously hard-coded to
/// `application/json`, which silently mislabels every attachment upload.
#[derive(Debug, Clone, Copy)]
pub struct RequestBody<'a> {
    pub bytes: &'a [u8],
    pub content_type: &'static str,
}

impl<'a> RequestBody<'a> {
    pub fn json(body: &'a str) -> Self {
        Self { bytes: body.as_bytes(), content_type: "application/json" }
    }

    /// Opaque bytes — an encrypted attachment. The server is not meant to parse these.
    pub fn octets(bytes: &'a [u8]) -> Self {
        Self { bytes, content_type: "application/octet-stream" }
    }
}

/// The most a client will read from one response.
///
/// **Found by probing, not reading.** `ureq` caps a response body at 10 MiB unless told
/// otherwise, and the instance stores attachments up to 25 MiB. Every attachment between the
/// two uploaded cleanly and then failed to download for every recipient — reported as a
/// transport error on their side, long after the sender had watched it go. A bound is still
/// kept, because the instance is semi-trusted and an unbounded read is a way for it to
/// exhaust this device's memory; it sits above the largest blob with room for headers.
pub const MAX_RESPONSE_BYTES: u64 = 32 * 1024 * 1024;

/// Moves bytes to an instance and back. Synchronous, matching the rest of the client.
///
/// Sync on purpose: `mls-rs` is sync in this build, so no async runtime has to be pumped
/// across the FFI boundary (`docs/09-platform-strategy.md`).
pub trait Transport: Send + Sync + fmt::Debug {
    fn send(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, String)],
        body: Option<RequestBody<'_>>,
    ) -> Result<Response, TransportError>;
}

#[cfg(feature = "http")]
mod http {
    use super::{RequestBody, Response, Transport, TransportError};

    /// An instance reachable over HTTP(S).
    ///
    /// ## On TLS
    ///
    /// `ureq` verifies certificates with rustls by default and this does not disable that.
    /// The **server** still terminates no TLS of its own and must sit behind a reverse
    /// proxy (`docs/03-protocol-evaluation.md`), so pointing this at a bare `http://`
    /// origin is a plaintext connection — every guarantee in `docs/01-threat-model.md` §2
    /// against A1 and A2 comes from the transport, not from MLS. MLS still hides content,
    /// but an active attacker sees and can tamper with everything around it.
    #[derive(Debug, Clone)]
    pub struct HttpTransport {
        base: String,
        agent: ureq::Agent,
    }

    impl HttpTransport {
        /// `base` is an origin such as `https://cairn.example`. A trailing slash is fine.
        pub fn new(base: impl Into<String>) -> Self {
            let base = base.into().trim_end_matches('/').to_string();
            // Non-2xx must come back as a response, not an error: the server's body
            // says which check failed, and `Client` maps specific statuses (a 409 on a
            // key package claim, say) onto errors a caller can act on. Letting `ureq`
            // turn them into `StatusCode` errors would throw that away.
            let agent = ureq::Agent::new_with_config(
                ureq::Agent::config_builder().http_status_as_error(false).build(),
            );
            Self { base, agent }
        }

        /// Whether this transport is protected in flight.
        ///
        /// Exposed so a client can *say so* rather than let a user assume it. A UI that
        /// shows an encryption badge over a plaintext transport is the kind of claim
        /// `docs/01-threat-model.md` forbids.
        pub fn is_tls(&self) -> bool {
            self.base.starts_with("https://")
        }
    }

    impl Transport for HttpTransport {
        fn send(
            &self,
            method: &str,
            path: &str,
            headers: &[(&str, String)],
            body: Option<RequestBody<'_>>,
        ) -> Result<Response, TransportError> {
            let url = format!("{}{path}", self.base);

            // `ureq` types its builders by whether the method carries a body, so the two
            // families cannot be unified before the request is sent.
            let sent = match method {
                "POST" | "PUT" => {
                    let mut request =
                        if method == "POST" { self.agent.post(&url) } else { self.agent.put(&url) };
                    for (name, value) in headers {
                        request = request.header(*name, value);
                    }
                    match body {
                        Some(body) => {
                            request.header("content-type", body.content_type).send(body.bytes)
                        }
                        None => request.send_empty(),
                    }
                }
                "GET" | "DELETE" => {
                    let mut request = if method == "GET" {
                        self.agent.get(&url)
                    } else {
                        self.agent.delete(&url)
                    };
                    for (name, value) in headers {
                        request = request.header(*name, value);
                    }
                    request.call()
                }
                other => return Err(TransportError::Io(format!("unsupported method {other}"))),
            };

            // A non-2xx is a response to be read, not an error to be thrown away: the
            // server's body says which check failed.
            let mut response = match sent {
                Ok(response) => response,
                Err(ureq::Error::StatusCode(status)) => {
                    return Err(TransportError::Status { status, body: String::new() })
                }
                Err(e) => return Err(TransportError::Io(e.to_string())),
            };

            let status = response.status().as_u16();
            let body = response
                .body_mut()
                .with_config()
                .limit(super::MAX_RESPONSE_BYTES)
                .read_to_vec()
                .map_err(|e| TransportError::Io(e.to_string()))?;
            Ok(Response { status, body })
        }
    }
}

#[cfg(feature = "http")]
pub use http::HttpTransport;
