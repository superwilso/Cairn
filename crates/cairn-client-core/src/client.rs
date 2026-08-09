//! Talking to an instance.
//!
//! Every request a Cairn client makes is built and signed here, never by a platform UI.
//! That is ADR-006 applied to the network: five native clients each assembling signed
//! requests would be five chances to get the signed bytes wrong, and a request signed over
//! the wrong bytes does not fail loudly — it fails as an authorization that covers more
//! than it should.
//!
//! Concretely, this is why [`Client::claim_key_packages`] signs the *target account* into
//! its request. Signing only the action would let one captured signature drain any
//! account on the instance inside the replay window — see `cairn_proto::ResourceRef`.

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use cairn_crypto::mls::Session;
use cairn_crypto::TranscriptReport;
use cairn_proto::{DeviceId, Envelope, ResourceRef, RoomId, RoomShape, UserId};

use crate::transport::{Response, Transport, TransportError};

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error(transparent)]
    Transport(#[from] TransportError),
    #[error("could not encode or decode a server message: {0}")]
    Encoding(#[from] serde_json::Error),
    #[error(transparent)]
    Mls(#[from] cairn_crypto::mls::MlsError),
    #[error("the instance has no key packages for {0}; it cannot be added yet")]
    NoKeyPackages(UserId),
}

/// Wall clock, in milliseconds since the Unix epoch.
///
/// The server checks this against its own within a 60s window, so a device with a badly
/// wrong clock cannot authenticate at all. That is deliberate: the window is what bounds
/// replay of a captured request without the server having to store nonces.
fn now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

/// One device's connection to one instance.
#[derive(Debug)]
pub struct Client<T: Transport> {
    transport: T,
    session: Arc<Session>,
    user: UserId,
    device: DeviceId,
}

#[derive(Serialize)]
struct ClaimAccountRequest<'a> {
    user: uuid::Uuid,
    device: uuid::Uuid,
    public_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    invite: Option<&'a str>,
}

#[derive(Serialize)]
struct CreateRoomRequest {
    is_direct: bool,
    is_publicly_discoverable: bool,
    member_ceiling: u32,
}

#[derive(Deserialize)]
pub struct CreatedRoom {
    pub room: RoomId,
    /// The tier label the server derived. A client must show this
    /// (`docs/02-encryption-tiers.md` §4) rather than assume the tier it asked for.
    pub tier: String,
    pub e2ee: bool,
}

#[derive(Serialize)]
struct PublishKeyPackagesRequest {
    packages: Vec<String>,
}

#[derive(Deserialize)]
struct PublishKeyPackagesResponse {
    remaining: usize,
}

/// One device's key package, as handed out by a claim.
#[derive(Debug, Deserialize)]
pub struct ClaimedKeyPackage {
    pub device: DeviceId,
    pub key_package: String,
}

#[derive(Serialize)]
struct RoomMemberRequest {
    user: uuid::Uuid,
}

#[derive(Debug, Deserialize)]
pub struct SendReceipt {
    pub server_seq: u64,
    /// The server's franking tag. A recipient needs it to file a report, so a client that
    /// drops it has silently made the conversation unreportable.
    pub franking_tag: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct FetchedMessage {
    pub envelope: Envelope,
    pub server_seq: u64,
    pub franking_tag: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ReportVerdict {
    pub verified: bool,
    pub reason: Option<String>,
    pub message_count: usize,
}

impl<T: Transport> Client<T> {
    pub fn new(transport: T, session: Arc<Session>, user: UserId, device: DeviceId) -> Self {
        Self { transport, session, user, device }
    }

    pub const fn user(&self) -> UserId {
        self.user
    }

    pub const fn device(&self) -> DeviceId {
        self.device
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    /// Headers proving this device authorized `action` against `resource`.
    ///
    /// Private. There is no way for a caller to obtain these for an action or resource
    /// other than the one the request actually performs, which is the property that stops
    /// a signature being reused against a different target.
    fn auth(
        &self,
        action: &str,
        resource: Option<ResourceRef>,
    ) -> Result<Vec<(&'static str, String)>, ClientError> {
        let issued_at = now_ms();
        let bytes = cairn_proto::request_signing_bytes(action, resource, issued_at);
        let signature = self.session.sign(&bytes)?;
        Ok(vec![
            ("x-cairn-device", self.device.as_uuid().to_string()),
            ("x-cairn-timestamp", issued_at.to_string()),
            ("x-cairn-signature", hex::encode(signature)),
        ])
    }

    fn call(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, String)],
        body: Option<&str>,
    ) -> Result<Response, ClientError> {
        Ok(self.transport.send(method, path, headers, body)?.ok()?)
    }

    /// Claim this client's user id, registering its device as the account's first.
    ///
    /// Unauthenticated by construction — there is no account yet to authenticate as. What
    /// makes it safe is that the server refuses an id that is already claimed, so an
    /// attacker who sees a user id (they are on every message) cannot attach a device to
    /// it. See `cairn_server::state::AccountRecord`.
    pub fn claim_account(&self, invite: Option<&str>) -> Result<(), ClientError> {
        let body = serde_json::to_string(&ClaimAccountRequest {
            user: *self.user.as_uuid(),
            device: *self.device.as_uuid(),
            public_key: hex::encode(self.session.public_key()),
            invite,
        })?;
        self.call("POST", "/v1/accounts", &[], Some(&body))?;
        Ok(())
    }

    /// Publish key packages so others can add this device to groups.
    ///
    /// Returns how many the server now holds unclaimed. A client should top up before
    /// hitting zero: an account with none cannot be added to a room at all, and the
    /// failure surfaces to whoever tried to add them, not to the account that ran out.
    pub fn publish_key_packages(&self, count: usize) -> Result<usize, ClientError> {
        let packages = (0..count)
            .map(|_| {
                Ok(hex::encode(
                    self.session
                        .key_package()?
                        .to_bytes()
                        .map_err(cairn_crypto::mls::MlsError::from)?,
                ))
            })
            .collect::<Result<Vec<String>, ClientError>>()?;

        let body = serde_json::to_string(&PublishKeyPackagesRequest { packages })?;
        let response = self.call(
            "POST",
            &format!("/v1/devices/{}/key-packages", self.device.as_uuid()),
            &self.auth("publish_key_packages", Some(ResourceRef::Device(self.device)))?,
            Some(&body),
        )?;
        let parsed: PublishKeyPackagesResponse = serde_json::from_str(&response.body)?;
        Ok(parsed.remaining)
    }

    /// Claim one key package for each of `user`'s devices, consuming them.
    ///
    /// Every device, because each holds its own MLS leaf. The server refuses to return a
    /// partial set, so this either yields enough to add the whole account or fails —
    /// there is no path that adds some of someone's devices and leaves the rest unable to
    /// read the room.
    pub fn claim_key_packages(&self, user: UserId) -> Result<Vec<ClaimedKeyPackage>, ClientError> {
        let response = self.call(
            "POST",
            &format!("/v1/users/{}/key-packages", user.as_uuid()),
            &self.auth("claim_key_packages", Some(ResourceRef::User(user)))?,
            None,
        );

        match response {
            Ok(response) => Ok(serde_json::from_str(&response.body)?),
            Err(ClientError::Transport(TransportError::Status { status: 409, .. })) => {
                Err(ClientError::NoKeyPackages(user))
            }
            Err(e) => Err(e),
        }
    }

    pub fn create_room(&self, shape: RoomShape) -> Result<CreatedRoom, ClientError> {
        let body = serde_json::to_string(&CreateRoomRequest {
            is_direct: shape.is_direct,
            is_publicly_discoverable: shape.is_publicly_discoverable,
            member_ceiling: shape.member_ceiling,
        })?;
        let response =
            self.call("POST", "/v1/rooms", &self.auth("create_room", None)?, Some(&body))?;
        Ok(serde_json::from_str(&response.body)?)
    }

    pub fn add_room_member(&self, room: RoomId, user: UserId) -> Result<(), ClientError> {
        let body = serde_json::to_string(&RoomMemberRequest { user: *user.as_uuid() })?;
        self.call(
            "POST",
            &format!("/v1/rooms/{}/members", room.as_uuid()),
            &self.auth("add_member", Some(ResourceRef::Room(room)))?,
            Some(&body),
        )?;
        Ok(())
    }

    pub fn remove_room_member(&self, room: RoomId, target: UserId) -> Result<(), ClientError> {
        self.call(
            "DELETE",
            &format!("/v1/rooms/{}/members/{}", room.as_uuid(), target.as_uuid()),
            &self.auth("remove_member", Some(ResourceRef::Room(room)))?,
            None,
        )?;
        Ok(())
    }

    /// Post an already-signed envelope.
    ///
    /// Takes an [`Envelope`] rather than plaintext because the encryption, the franking
    /// commitment, and the envelope signature all belong to
    /// [`Conversation`](crate::Conversation) — which cannot produce an unfranked or
    /// unsigned message. Splitting that here would open a path to sending one.
    pub fn send(&self, room: RoomId, envelope: &Envelope) -> Result<SendReceipt, ClientError> {
        let body = serde_json::to_string(envelope)?;
        let response =
            self.call("POST", &format!("/v1/rooms/{}/messages", room.as_uuid()), &[], Some(&body))?;
        Ok(serde_json::from_str(&response.body)?)
    }

    /// Fetch messages after `after`. Polling is M1's delivery mechanism.
    pub fn fetch_since(
        &self,
        room: RoomId,
        after: u64,
    ) -> Result<Vec<FetchedMessage>, ClientError> {
        let response = self.call(
            "GET",
            &format!("/v1/rooms/{}/messages?after={after}", room.as_uuid()),
            &self.auth("read", Some(ResourceRef::Room(room)))?,
            None,
        )?;
        Ok(serde_json::from_str(&response.body)?)
    }

    /// File a franking report and get the server's verdict.
    ///
    /// A `verified: false` verdict is a successful call — the mechanism worked and the
    /// evidence did not hold up. Treating it as an error would conflate "your report was
    /// rejected" with "your request was malformed".
    pub fn report(&self, report: &TranscriptReport) -> Result<ReportVerdict, ClientError> {
        let body = serde_json::to_string(report)?;
        let response = self.call("POST", "/v1/reports", &[], Some(&body))?;
        Ok(serde_json::from_str(&response.body)?)
    }
}
