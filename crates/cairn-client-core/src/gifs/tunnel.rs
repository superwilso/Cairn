//! A TLS session to a GIF provider, carried through the instance's relay.
//!
//! The instance upgrades one HTTP request into a raw byte pipe to an allowlisted provider
//! host (`cairn_server::gif_relay`). Everything after the upgrade is this client's own TLS,
//! verified against the provider's certificate — so the instance relays the search without
//! being able to read it, and the provider answers it without learning who asked.
//!
//! Hand-rolled HTTP/1.1 rather than `ureq`, because `ureq` owns its sockets and cannot be
//! pointed at an already-upgraded one. The subset here is small on purpose: `GET`, keep-alive,
//! `Content-Length` or chunked bodies, no compression, a hard size cap on everything read.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

use super::GifError;

/// How long to wait for the instance, or the provider, to say anything at all.
const IO_TIMEOUT: Duration = Duration::from_secs(20);
/// A response head bigger than this is not a GIF API's.
const MAX_HEAD_BYTES: usize = 32 * 1024;

/// Anything bytes can go both ways through: a plain socket, or TLS to the instance.
pub(super) trait Pipe: Read + Write + Send {}
impl<T: Read + Write + Send> Pipe for T {}

/// Where the instance is, parsed from the base URL the session was opened with.
#[derive(Debug, Clone)]
pub(super) struct Origin {
    tls: bool,
    host: String,
    port: u16,
    /// What goes in the `Host` header: the authority as written.
    authority: String,
    /// A path prefix, for an instance served under one.
    prefix: String,
}

impl Origin {
    pub(super) fn parse(base: &str) -> Result<Self, GifError> {
        let bad = || GifError::Relay("the instance address is not an http(s) URL".into());
        let (tls, rest) = if let Some(r) = base.strip_prefix("https://") {
            (true, r)
        } else if let Some(r) = base.strip_prefix("http://") {
            (false, r)
        } else {
            return Err(bad());
        };
        let (authority, prefix) = match rest.find('/') {
            Some(i) => (&rest[..i], rest[i..].trim_end_matches('/')),
            None => (rest, ""),
        };
        if authority.is_empty() || authority.contains('@') {
            return Err(bad());
        }
        let default_port = if tls { 443 } else { 80 };
        let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
            let (h, after) = v6.split_once(']').ok_or_else(bad)?;
            let port = match after.strip_prefix(':') {
                Some(p) => p.parse().map_err(|_| bad())?,
                None if after.is_empty() => default_port,
                None => return Err(bad()),
            };
            (h.to_string(), port)
        } else {
            match authority.rsplit_once(':') {
                Some((h, p)) => (h.to_string(), p.parse().map_err(|_| bad())?),
                None => (authority.to_string(), default_port),
            }
        };
        Ok(Self { tls, host, port, authority: authority.to_string(), prefix: prefix.to_string() })
    }
}

/// TLS settings, with the roots each side is verified against.
pub(super) fn tls_config(roots: RootCertStore) -> Result<Arc<ClientConfig>, GifError> {
    let config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|e| GifError::Tls(e.to_string()))?
            .with_root_certificates(roots)
            .with_no_client_auth();
    Ok(Arc::new(config))
}

/// The web PKI's roots, as `ureq` uses for the instance itself.
pub(super) fn web_roots() -> RootCertStore {
    RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() }
}

/// Open a tunnel through the instance to `target_host:443`. Returns the raw pipe, on which
/// the caller must speak TLS to the provider.
pub(super) fn open(
    origin: &Origin,
    instance_tls: &Arc<ClientConfig>,
    path: &str,
    headers: &[(&'static str, String)],
) -> Result<Box<dyn Pipe>, GifError> {
    let io = |e: std::io::Error| GifError::Io(e.to_string());
    let addrs: Vec<_> =
        (origin.host.as_str(), origin.port).to_socket_addrs().map_err(io)?.collect();
    let mut last = None;
    let mut tcp = None;
    for addr in addrs {
        match TcpStream::connect_timeout(&addr, IO_TIMEOUT) {
            Ok(s) => {
                tcp = Some(s);
                break;
            }
            Err(e) => last = Some(e),
        }
    }
    let tcp = match (tcp, last) {
        (Some(s), _) => s,
        (None, Some(e)) => return Err(io(e)),
        (None, None) => return Err(GifError::Io("the instance address did not resolve".into())),
    };
    tcp.set_read_timeout(Some(IO_TIMEOUT)).map_err(io)?;
    tcp.set_write_timeout(Some(IO_TIMEOUT)).map_err(io)?;
    let _ = tcp.set_nodelay(true);

    let mut pipe: Box<dyn Pipe> = if origin.tls {
        let name = ServerName::try_from(origin.host.clone())
            .map_err(|_| GifError::Relay("the instance's host name is not valid".into()))?;
        let conn = ClientConnection::new(Arc::clone(instance_tls), name)
            .map_err(|e| GifError::Tls(e.to_string()))?;
        Box::new(StreamOwned::new(conn, tcp))
    } else {
        Box::new(tcp)
    };

    let mut request = format!(
        "GET {}{path} HTTP/1.1\r\nHost: {}\r\nConnection: Upgrade\r\nUpgrade: {}\r\n",
        origin.prefix, origin.authority, PROTOCOL
    );
    for (name, value) in headers {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str("\r\n");
    pipe.write_all(request.as_bytes()).map_err(io)?;
    pipe.flush().map_err(io)?;

    // Byte at a time, so nothing after the head is consumed into a buffer this function
    // would then have to hand on. The head is a few hundred bytes; this is not a hot path.
    let mut head = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() >= MAX_HEAD_BYTES {
            return Err(GifError::Relay("the instance sent an oversized response head".into()));
        }
        match pipe.read(&mut byte).map_err(io)? {
            0 => return Err(GifError::Relay("the instance closed the connection".into())),
            _ => head.push(byte[0]),
        }
    }
    let (status, _) = parse_head(&head)?;
    if status == 101 {
        return Ok(pipe);
    }
    Err(match status {
        401 => GifError::Relay("the instance did not accept this device's signature".into()),
        403 => GifError::Relay("the instance refused to relay to that host".into()),
        404 => GifError::NotConfigured,
        429 => GifError::RateLimited,
        502 => GifError::Relay("the instance could not reach the GIF provider".into()),
        other => GifError::Relay(format!("the instance answered {other} to a relay request")),
    })
}

/// The protocol a tunnel upgrades to. Matches `cairn_server::gif_relay::GIF_TUNNEL_PROTOCOL`.
pub(super) const PROTOCOL: &str = "cairn-gif-tunnel";

/// A response from a provider.
#[derive(Debug)]
pub(super) struct Reply {
    pub status: u16,
    pub body: Vec<u8>,
}

/// An HTTP/1.1 connection to one provider host, inside a relay tunnel.
pub(super) struct ProviderConn {
    io: BufReader<StreamOwned<ClientConnection, Box<dyn Pipe>>>,
    host: String,
    opened: Instant,
    last_used: Instant,
    reusable: bool,
}

impl ProviderConn {
    /// Start TLS to `host` over a tunnel. The certificate is checked against `host`, which
    /// is what makes the relay unable to answer in the provider's place.
    pub(super) fn handshake(
        pipe: Box<dyn Pipe>,
        host: &str,
        provider_tls: &Arc<ClientConfig>,
    ) -> Result<Self, GifError> {
        let name = ServerName::try_from(host.to_string())
            .map_err(|_| GifError::Malformed("provider host name"))?;
        let conn = ClientConnection::new(Arc::clone(provider_tls), name)
            .map_err(|e| GifError::Tls(e.to_string()))?;
        let now = Instant::now();
        Ok(Self {
            io: BufReader::new(StreamOwned::new(conn, pipe)),
            host: host.to_string(),
            opened: now,
            last_used: now,
            reusable: true,
        })
    }

    pub(super) fn host(&self) -> &str {
        &self.host
    }

    /// Whether this connection is still worth reusing. The instance closes an idle tunnel
    /// after 30s and any tunnel after five minutes; giving up a little earlier than either
    /// avoids sending a request into a pipe that is about to be cut.
    pub(super) fn fresh(&self) -> bool {
        self.reusable
            && self.last_used.elapsed() < Duration::from_secs(20)
            && self.opened.elapsed() < Duration::from_secs(4 * 60)
    }

    /// `GET path_and_query`, reading at most `limit` bytes of body.
    pub(super) fn get(&mut self, path_and_query: &str, limit: usize) -> Result<Reply, GifError> {
        let io = |e: std::io::Error| match e.kind() {
            std::io::ErrorKind::InvalidData => GifError::Tls(e.to_string()),
            _ => GifError::Io(e.to_string()),
        };
        // A small, fixed header set: nothing here describes the device, the account or the
        // instance beyond what the provider already sees — that the request came through it.
        let request = format!(
            "GET {path_and_query} HTTP/1.1\r\nHost: {}\r\nUser-Agent: Cairn\r\nAccept: */*\r\n\
             Accept-Encoding: identity\r\nConnection: keep-alive\r\n\r\n",
            self.host
        );
        self.last_used = Instant::now();
        let stream = self.io.get_mut();
        stream.write_all(request.as_bytes()).map_err(io)?;
        stream.flush().map_err(io)?;

        let mut head = Vec::with_capacity(1024);
        loop {
            let before = head.len();
            let n = (&mut self.io)
                .take((MAX_HEAD_BYTES - head.len().min(MAX_HEAD_BYTES)) as u64 + 1)
                .read_until(b'\n', &mut head)
                .map_err(io)?;
            if n == 0 {
                self.reusable = false;
                return Err(GifError::Io("the provider closed the connection".into()));
            }
            if head.len() > MAX_HEAD_BYTES {
                return Err(GifError::Malformed("provider response head"));
            }
            let line = &head[before..];
            if line == b"\r\n" || line == b"\n" {
                if head.len() == line.len() {
                    // Tolerate a stray blank line before the status line.
                    head.clear();
                    continue;
                }
                break;
            }
        }
        let (status, framing) = parse_head(&head)?;
        if framing.close {
            self.reusable = false;
        }
        if framing.encoded {
            self.reusable = false;
            return Err(GifError::Malformed("compressed provider response"));
        }
        let body = if framing.chunked {
            let body = read_chunked(&mut self.io, limit);
            if body.is_err() {
                self.reusable = false;
            }
            body?
        } else if let Some(len) = framing.length {
            if len > limit as u64 {
                self.reusable = false;
                return Err(GifError::TooLarge);
            }
            let mut body = vec![0u8; len as usize];
            self.io.read_exact(&mut body).map_err(io)?;
            body
        } else {
            // Neither length nor chunks: the body runs to the end of the connection.
            self.reusable = false;
            let mut body = Vec::new();
            (&mut self.io).take(limit as u64 + 1).read_to_end(&mut body).map_err(io)?;
            if body.len() > limit {
                return Err(GifError::TooLarge);
            }
            body
        };
        self.last_used = Instant::now();
        Ok(Reply { status, body })
    }
}

/// How a response body is framed.
#[derive(Debug, Default)]
struct Framing {
    length: Option<u64>,
    chunked: bool,
    close: bool,
    /// A content encoding other than identity, which this client asked not to get.
    encoded: bool,
}

fn parse_head(head: &[u8]) -> Result<(u16, Framing), GifError> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut response = httparse::Response::new(&mut headers);
    match response.parse(head) {
        Ok(httparse::Status::Complete(_)) => {}
        _ => return Err(GifError::Malformed("HTTP response head")),
    }
    let status = response.code.ok_or(GifError::Malformed("HTTP status"))?;
    let mut framing = Framing::default();
    for h in response.headers.iter() {
        let value = std::str::from_utf8(h.value).unwrap_or("").trim().to_ascii_lowercase();
        if h.name.eq_ignore_ascii_case("content-length") {
            let len = value.parse().map_err(|_| GifError::Malformed("Content-Length"))?;
            // Two different lengths is the request-smuggling shape; refuse rather than pick.
            if framing.length.is_some_and(|l| l != len) {
                return Err(GifError::Malformed("Content-Length"));
            }
            framing.length = Some(len);
        } else if h.name.eq_ignore_ascii_case("transfer-encoding") {
            framing.chunked = value.split(',').any(|v| v.trim() == "chunked");
        } else if h.name.eq_ignore_ascii_case("connection") {
            framing.close = value.split(',').any(|v| v.trim() == "close");
        } else if h.name.eq_ignore_ascii_case("content-encoding") {
            framing.encoded = !value.is_empty() && value != "identity";
        }
    }
    Ok((status, framing))
}

fn read_chunked(io: &mut impl BufRead, limit: usize) -> Result<Vec<u8>, GifError> {
    let err = |e: std::io::Error| GifError::Io(e.to_string());
    let mut body = Vec::new();
    loop {
        let mut line = Vec::new();
        io.take(256).read_until(b'\n', &mut line).map_err(err)?;
        let text = std::str::from_utf8(&line).map_err(|_| GifError::Malformed("chunk size"))?;
        let size_text = text.split(';').next().unwrap_or("").trim();
        let size =
            usize::from_str_radix(size_text, 16).map_err(|_| GifError::Malformed("chunk size"))?;
        if size == 0 {
            // Trailers, then the blank line that ends them.
            loop {
                let mut trailer = Vec::new();
                let n = io.take(8 * 1024).read_until(b'\n', &mut trailer).map_err(err)?;
                if n == 0 || trailer == b"\r\n" || trailer == b"\n" {
                    return Ok(body);
                }
            }
        }
        if body.len().saturating_add(size) > limit {
            return Err(GifError::TooLarge);
        }
        let start = body.len();
        body.resize(start + size, 0);
        io.read_exact(&mut body[start..]).map_err(err)?;
        let mut crlf = [0u8; 2];
        io.read_exact(&mut crlf).map_err(err)?;
        if &crlf != b"\r\n" {
            return Err(GifError::Malformed("chunk terminator"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_instance_address_is_parsed_into_where_to_dial_and_what_to_call_it() {
        let o = Origin::parse("https://cairn.example").unwrap();
        assert!(o.tls);
        assert_eq!((o.host.as_str(), o.port, o.prefix.as_str()), ("cairn.example", 443, ""));
        let o = Origin::parse("http://127.0.0.1:8080/").unwrap();
        assert_eq!(
            (o.host.as_str(), o.port, o.authority.as_str()),
            ("127.0.0.1", 8080, "127.0.0.1:8080")
        );
        let o = Origin::parse("http://[::1]:9000/cairn").unwrap();
        assert_eq!((o.host.as_str(), o.port, o.prefix.as_str()), ("::1", 9000, "/cairn"));
        for bad in ["ftp://x", "cairn.example", "http://user@host", "http://", "http://h:port"] {
            assert!(Origin::parse(bad).is_err(), "{bad} must not parse");
        }
    }

    #[test]
    fn a_chunked_body_is_reassembled_and_bounded() {
        let wire = b"5\r\nhello\r\n6;ext=1\r\n world\r\n0\r\nX-Trailer: y\r\n\r\n";
        let body = read_chunked(&mut &wire[..], 100).unwrap();
        assert_eq!(body, b"hello world");
        assert!(matches!(read_chunked(&mut &wire[..], 8), Err(GifError::TooLarge)));
        assert!(read_chunked(&mut &b"zz\r\n"[..], 100).is_err());
        assert!(read_chunked(&mut &b"5\r\nhelloXX"[..], 100).is_err());
    }

    #[test]
    fn conflicting_lengths_and_compressed_bodies_are_refused() {
        let twice = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n";
        assert!(parse_head(twice).is_err(), "two lengths is the smuggling shape");
        let gz = b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 5\r\n\r\n";
        assert!(parse_head(gz).unwrap().1.encoded);
        let ok = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n";
        let (status, f) = parse_head(ok).unwrap();
        assert_eq!(status, 200);
        assert!(f.chunked && f.close);
    }
}
