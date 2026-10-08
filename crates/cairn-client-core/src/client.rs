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
use cairn_proto::{
    DeviceId, DeviceIdentity, Envelope, ResourceRef, RoomId, RoomSeal, RoomShape, UserId,
};

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
    /// The instance returned a key package for a different account than the one asked for.
    ///
    /// Refused rather than reported, because adding it would put that account into the group
    /// under a leaf the adder believes belongs to someone else — which is the impersonation
    /// the credential format exists to prevent.
    #[error(
        "asked the instance for {asked_for}'s key package and got one claiming {claims}; \
         refusing to add it. Either the instance is substituting accounts or something is \
         badly out of sync — adding it anyway would put the wrong person in the room"
    )]
    WrongAccountInKeyPackage { asked_for: UserId, claims: UserId },
    /// A key package whose credential cannot be read at all.
    ///
    /// Includes the legacy `name@server` format, which is why upgrading a client is not
    /// optional for anyone who wants to be added to a room by a current one.
    #[error(
        "the key package the instance returned for {0} does not carry a readable Cairn \
         identity; it may have been published by a client too old to name its account"
    )]
    UnverifiableKeyPackage(UserId),
    #[error("this room cannot be created as specified: {0}")]
    Shape(#[from] cairn_proto::ShapeError),
    #[error(
        "the instance classified this room as {server} but the published rule makes it \
         {local}; refusing rather than showing a badge that may not describe what happens \
         to the messages"
    )]
    TierDisagreement { local: &'static str, server: String },
    #[error("the instance returned a malformed {0}")]
    Malformed(&'static str),
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
///
/// `Clone` (when the transport is) so a long transfer can run on a copy without holding
/// whatever lock guards the original. A copy shares the device's signing key through the
/// same `Arc`, and can only make the same signed requests the original could.
#[derive(Debug, Clone)]
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
struct RoomMemberEntryResponse {
    user: String,
    role: String,
}

#[derive(Deserialize)]
struct MintedInviteResponse {
    token: String,
}

#[derive(Deserialize)]
struct RedeemedInviteResponse {
    room: String,
}

#[derive(Deserialize)]
struct ResolvedUserResponse {
    user: String,
}

#[derive(Deserialize)]
struct UploadedBlobResponse {
    blob: String,
}

#[derive(Deserialize)]
struct CreatedRoomResponse {
    room: RoomId,
    tier: String,
    e2ee: bool,
    #[serde(default)]
    ttl_ms: Option<i64>,
}

/// A room this client just created.
#[derive(Debug)]
pub struct CreatedRoom {
    pub room: RoomId,
    /// The tier this client derived, locally, from the shape it asked for.
    ///
    /// **This is the badge to display**, not the label the server sent back. The seal is
    /// what decides whether [`crate::Conversation`] encrypts, so showing anything else
    /// would let the badge and the behaviour disagree — and a badge that does not describe
    /// what the client actually does is the false assurance `docs/01-threat-model.md`
    /// forbids. `derive_tier` is a pure function of the shape, so the client never has to
    /// ask.
    pub seal: RoomSeal,
}

impl CreatedRoom {
    /// The label to render. Always the locally-derived tier.
    pub fn tier_label(&self) -> &'static str {
        self.seal.tier().label()
    }
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
        self.call_raw(method, path, headers, body.map(crate::transport::RequestBody::json))
    }

    /// The bytes-level escape hatch, for the one endpoint whose body is not JSON.
    ///
    /// Kept separate rather than widening `call`, so every existing caller stays visibly
    /// JSON and an attachment upload has to say that it is not.
    fn call_raw(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, String)],
        body: Option<crate::transport::RequestBody<'_>>,
    ) -> Result<Response, ClientError> {
        Ok(self.transport.send(method, path, headers, body)?.ok()?)
    }

    /// The room's disappearing-message timer, as the instance holds it.
    ///
    /// A client applies the same value to its own stored transcript, so a message the
    /// server has dropped does not live on in local history — the timer would otherwise be
    /// true of the instance and false of the one device its user actually controls.
    pub fn room_ttl(&self, room: RoomId) -> Result<Option<i64>, ClientError> {
        let response = self.call(
            "GET",
            &format!("/v1/rooms/{}", room.as_uuid()),
            &self.auth("describe", Some(room.into()))?,
            None,
        )?;
        let parsed: CreatedRoomResponse = serde_json::from_slice(&response.body)?;
        Ok(parsed.ttl_ms)
    }

    /// Set or clear the room's disappearing-message timer. Any member may.
    pub fn set_room_ttl(&self, room: RoomId, ttl_ms: Option<i64>) -> Result<(), ClientError> {
        let body = serde_json::json!({ "ttl_ms": ttl_ms }).to_string();
        self.call(
            "POST",
            &format!("/v1/rooms/{}/ttl", room.as_uuid()),
            &self.auth("set_room_ttl", Some(room.into()))?,
            Some(&body),
        )?;
        Ok(())
    }

    /// The room's server-side membership.
    ///
    /// **Not the MLS roster.** The two diverge whenever someone joins by invite: the server
    /// admits them at once, and the encrypted group gains them only when a member commits an
    /// Add. A caller that conflated the two would show a user as present in a conversation
    /// they cannot actually read.
    pub fn room_members(&self, room: RoomId) -> Result<Vec<(UserId, String)>, ClientError> {
        let response = self.call(
            "GET",
            &format!("/v1/rooms/{}/members", room.as_uuid()),
            &self.auth("list_room_members", Some(room.into()))?,
            None,
        )?;
        let parsed: Vec<RoomMemberEntryResponse> = serde_json::from_slice(&response.body)?;
        parsed
            .into_iter()
            .map(|m| {
                m.user.parse().map(|u| (u, m.role)).map_err(|_| ClientError::Malformed("user id"))
            })
            .collect()
    }

    /// Mint an invite for a room. The token comes back once and is not recoverable.
    pub fn create_room_invite(
        &self,
        room: RoomId,
        uses: u32,
        expires_at_ms: Option<i64>,
    ) -> Result<String, ClientError> {
        let body = serde_json::json!({ "uses": uses, "expires_at_ms": expires_at_ms }).to_string();
        let response = self.call(
            "POST",
            &format!("/v1/rooms/{}/invites", room.as_uuid()),
            &self.auth("create_room_invite", Some(room.into()))?,
            Some(&body),
        )?;
        let parsed: MintedInviteResponse = serde_json::from_slice(&response.body)?;
        Ok(parsed.token)
    }

    /// Redeem an invite, joining this account to the room it names.
    pub fn redeem_room_invite(&self, token: &str) -> Result<RoomId, ClientError> {
        let body = serde_json::json!({ "token": token }).to_string();
        let response = self.call(
            "POST",
            "/v1/invites/redeem",
            &self.auth("redeem_room_invite", None)?,
            Some(&body),
        )?;
        let parsed: RedeemedInviteResponse = serde_json::from_slice(&response.body)?;
        parsed.room.parse().map_err(|_| ClientError::Malformed("room id"))
    }

    /// Claim a handle for this account. One per account, and not reassignable.
    pub fn claim_username(&self, name: &cairn_proto::Username) -> Result<(), ClientError> {
        let body = serde_json::json!({ "username": name.as_str() }).to_string();
        self.call("POST", "/v1/usernames", &self.auth("claim_username", None)?, Some(&body))?;
        Ok(())
    }

    /// Resolve a handle to an account id.
    ///
    /// Exact match: the instance offers no search, so a typo is a miss rather than a list of
    /// near-matches. That is the point — see `docs/10-roadmap.md`.
    pub fn lookup_username(&self, name: &cairn_proto::Username) -> Result<UserId, ClientError> {
        let response = self.call(
            "GET",
            &format!("/v1/usernames/{}", name.as_str()),
            &self.auth("lookup_username", None)?,
            None,
        )?;
        let parsed: ResolvedUserResponse = serde_json::from_slice(&response.body)?;
        parsed.user.parse().map_err(|_| ClientError::Malformed("user id"))
    }

    /// Upload an already-sealed attachment to a room, returning the id to reference it by.
    ///
    /// Takes ciphertext, never a file. Sealing happens in
    /// [`cairn_crypto::attachment::seal`] and the key belongs in the encrypted message body
    /// — a `Client` that took a plaintext file and encrypted it here would put the key on
    /// the same call as the bytes, which is exactly the arrangement the blob store exists
    /// to avoid.
    pub fn upload_attachment(
        &self,
        room: RoomId,
        sealed: &[u8],
    ) -> Result<cairn_proto::BlobId, ClientError> {
        let response = self.call_raw(
            "POST",
            &format!("/v1/rooms/{}/blobs", room.as_uuid()),
            &self.auth("upload_blob", Some(room.into()))?,
            Some(crate::transport::RequestBody::octets(sealed)),
        )?;
        let parsed: UploadedBlobResponse = serde_json::from_slice(&response.body)?;
        parsed.blob.parse().map_err(|_| ClientError::Malformed("blob id"))
    }

    /// Fetch a sealed attachment. Still ciphertext — open it with the key from the message.
    pub fn download_attachment(&self, blob: cairn_proto::BlobId) -> Result<Vec<u8>, ClientError> {
        let response = self.call(
            "GET",
            &format!("/v1/blobs/{}", blob.as_uuid()),
            &self.auth("download_blob", Some(blob.into()))?,
            None,
        )?;
        Ok(response.body)
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
        let parsed: PublishKeyPackagesResponse = serde_json::from_slice(&response.body)?;
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

        let claimed: Vec<ClaimedKeyPackage> = match response {
            Ok(response) => serde_json::from_slice(&response.body)?,
            Err(ClientError::Transport(TransportError::Status { status: 409, .. })) => {
                return Err(ClientError::NoKeyPackages(user))
            }
            Err(e) => return Err(e),
        };

        // Every package must name the account we asked for.
        //
        // This is the check that gives the credential its meaning. Probing the old
        // display-name credential found that a member could join a room presenting someone
        // else's label — every client then showed her as them, and because MLS refuses
        // duplicate identities, the real person could never join that room afterwards.
        //
        // Carrying the account id in the credential does not fix that by itself; **this
        // comparison does**. Without it the id would be decoration nobody ever read.
        for package in &claimed {
            let bytes = hex::decode(&package.key_package)
                .map_err(|_| ClientError::UnverifiableKeyPackage(user))?;
            let message = cairn_crypto::mls::parse_message(&bytes)
                .map_err(|_| ClientError::UnverifiableKeyPackage(user))?;
            let credential = cairn_crypto::mls::key_package_credential(&message)
                .ok_or(ClientError::UnverifiableKeyPackage(user))?;

            let identity = DeviceIdentity::parse(&credential)
                .map_err(|_| ClientError::UnverifiableKeyPackage(user))?;
            if !identity.belongs_to(user) {
                return Err(ClientError::WrongAccountInKeyPackage {
                    asked_for: user,
                    claims: identity.user(),
                });
            }
        }
        Ok(claimed)
    }

    /// Create a room, and refuse it if the instance classified it differently.
    ///
    /// Both ends derive the tier from the same published rule
    /// (`docs/02-encryption-tiers.md` §2), so agreement is the normal case and a
    /// disagreement means one of two things: the instance runs a different version of the
    /// rule, or it is lying. Neither is safe to paper over. Accepting the room anyway
    /// would leave the client encrypting a room the server treats as public, or — far
    /// worse — showing an encrypted badge over a room it is about to send in plaintext.
    ///
    /// Failing here costs a room creation. Continuing costs the user's correct belief
    /// about who can read what.
    pub fn create_room(&self, shape: RoomShape) -> Result<CreatedRoom, ClientError> {
        let seal = RoomSeal::new(shape)?;
        let body = serde_json::to_string(&CreateRoomRequest {
            is_direct: shape.is_direct,
            is_publicly_discoverable: shape.is_publicly_discoverable,
            member_ceiling: shape.member_ceiling,
        })?;
        let response =
            self.call("POST", "/v1/rooms", &self.auth("create_room", None)?, Some(&body))?;
        let parsed: CreatedRoomResponse = serde_json::from_slice(&response.body)?;

        if parsed.tier != seal.tier().label() || parsed.e2ee != seal.tier().is_e2ee() {
            return Err(ClientError::TierDisagreement {
                local: seal.tier().label(),
                server: parsed.tier,
            });
        }

        Ok(CreatedRoom { room: parsed.room, seal })
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
        Ok(serde_json::from_slice(&response.body)?)
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
        Ok(serde_json::from_slice(&response.body)?)
    }

    /// File a franking report and get the server's verdict.
    ///
    /// A `verified: false` verdict is a successful call — the mechanism worked and the
    /// evidence did not hold up. Treating it as an error would conflate "your report was
    /// rejected" with "your request was malformed".
    pub fn report(&self, report: &TranscriptReport) -> Result<ReportVerdict, ClientError> {
        let body = serde_json::to_string(report)?;
        let response = self.call("POST", "/v1/reports", &[], Some(&body))?;
        Ok(serde_json::from_slice(&response.body)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::Response;

    /// An instance that hands back whichever key package it was told to.
    ///
    /// Stands in for both a substituting server and a stale directory — from the claiming
    /// client's side those are indistinguishable, which is why the check is on the
    /// credential rather than on trusting the endpoint.
    #[derive(Debug)]
    struct KeyPackageInstance {
        package_hex: String,
        device: DeviceId,
    }

    impl Transport for KeyPackageInstance {
        fn send(
            &self,
            _method: &str,
            _path: &str,
            _headers: &[(&str, String)],
            _body: Option<crate::transport::RequestBody<'_>>,
        ) -> Result<Response, TransportError> {
            Ok(Response {
                status: 200,
                body: format!(
                    r#"[{{"device":"{}","key_package":"{}"}}]"#,
                    self.device.as_uuid(),
                    self.package_hex
                )
                .into_bytes(),
            })
        }
    }

    /// A session whose credential names `identity`, plus a published key package.
    fn packaged(identity: &DeviceIdentity) -> String {
        let session = Session::new(&identity.to_credential()).unwrap();
        hex::encode(session.key_package().unwrap().to_bytes().unwrap())
    }

    fn claiming_client(package_hex: String, device: DeviceId) -> Client<KeyPackageInstance> {
        Client::new(
            KeyPackageInstance { package_hex, device },
            Arc::new(Session::new(b"asker").unwrap()),
            UserId::new(),
            DeviceId::new(),
        )
    }

    #[test]
    fn a_key_package_naming_another_account_is_refused() {
        // The regression test for what probing found. Under the old display-name credential,
        // mallory could join a room presenting bob's label: every member's client showed her
        // as bob, and because MLS refuses duplicate identities the real bob could then never
        // join that room at all.
        //
        // The credential now carries the account id — but that alone is decoration. *This*
        // comparison is the protection: the client asked for bob and must refuse a package
        // that names anyone else.
        let bob = UserId::new();
        let mallory = DeviceIdentity::new(UserId::new(), DeviceId::new());
        let client = claiming_client(packaged(&mallory), mallory.device());

        match client.claim_key_packages(bob) {
            Err(ClientError::WrongAccountInKeyPackage { asked_for, claims }) => {
                assert_eq!(asked_for, bob);
                assert_eq!(claims, mallory.user());
            }
            other => panic!("mallory's package must be refused when bob was asked for: {other:?}"),
        }
    }

    #[test]
    fn the_right_accounts_key_package_is_accepted() {
        // Counterfactual: a check that refused every package would pass the test above and
        // make it impossible to add anyone to a room.
        let bob = DeviceIdentity::new(UserId::new(), DeviceId::new());
        let client = claiming_client(packaged(&bob), bob.device());
        let claimed = client.claim_key_packages(bob.user()).expect("bob's own package");
        assert_eq!(claimed.len(), 1);
    }

    #[test]
    fn a_legacy_display_name_credential_is_refused_rather_than_trusted() {
        // A client too old to name its account publishes `name@server`. There is no way to
        // tell which account that belongs to, so it cannot be added — refusing names the
        // problem, where guessing would put an unverified leaf in an encrypted room.
        let legacy = Session::new(b"bob@instance").unwrap();
        let package = hex::encode(legacy.key_package().unwrap().to_bytes().unwrap());
        let client = claiming_client(package, DeviceId::new());

        assert!(matches!(
            client.claim_key_packages(UserId::new()),
            Err(ClientError::UnverifiableKeyPackage(_))
        ));
    }

    /// A transport that answers room creation with whatever the test dictates.
    #[derive(Debug)]
    struct LyingInstance {
        tier: &'static str,
        e2ee: bool,
    }

    impl Transport for LyingInstance {
        fn send(
            &self,
            _method: &str,
            _path: &str,
            _headers: &[(&str, String)],
            _body: Option<crate::transport::RequestBody<'_>>,
        ) -> Result<Response, TransportError> {
            Ok(Response {
                status: 200,
                body: format!(
                    r#"{{"room":"{}","tier":"{}","e2ee":{}}}"#,
                    uuid::Uuid::new_v4(),
                    self.tier,
                    self.e2ee
                )
                .into_bytes(),
            })
        }
    }

    fn client(tier: &'static str, e2ee: bool) -> Client<LyingInstance> {
        Client::new(
            LyingInstance { tier, e2ee },
            Arc::new(Session::new(b"alice@instance").unwrap()),
            UserId::new(),
            DeviceId::new(),
        )
    }

    fn dm() -> RoomShape {
        RoomShape { is_direct: true, is_publicly_discoverable: false, member_ceiling: 2 }
    }

    #[test]
    fn a_room_the_instance_classifies_differently_is_refused() {
        // The badge must describe what this client will actually do with the messages. If
        // the instance calls a DM public, one of us is wrong about who can read it, and
        // proceeding means displaying a tier that may be a lie.
        let err = client("T3", false)
            .create_room(dm())
            .expect_err("a T1 shape returned as T3 must not be accepted");
        assert!(
            matches!(err, ClientError::TierDisagreement { local: "T1", .. }),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn an_instance_claiming_more_encryption_than_the_rule_allows_is_also_refused() {
        // The inverse, and the more tempting one to wave through: a server that upgrades
        // the label looks generous. It is not — the client would encrypt nothing extra,
        // and the badge would promise what the tier does not deliver.
        let public =
            RoomShape { is_direct: false, is_publicly_discoverable: true, member_ceiling: 500 };
        let err = client("T1", true)
            .create_room(public)
            .expect_err("a T3 shape returned as T1 must not be accepted");
        assert!(matches!(err, ClientError::TierDisagreement { local: "T3", .. }));
    }

    #[test]
    fn an_agreeing_instance_yields_the_locally_derived_seal() {
        let created = client("T1", true).create_room(dm()).unwrap();
        assert_eq!(created.tier_label(), "T1");
        assert!(created.seal.tier().is_e2ee());
    }

    #[test]
    fn a_shape_the_rule_rejects_never_reaches_the_instance() {
        // `derive_tier` refuses an oversized direct room rather than downgrading it. That
        // check has to happen before the request, or a server is free to answer with
        // whichever tier it prefers for a shape the client should not have offered.
        let oversized = RoomShape {
            is_direct: true,
            is_publicly_discoverable: false,
            member_ceiling: cairn_proto::tier::T1_MAX_MEMBERS + 1,
        };
        let err = client("T1", true).create_room(oversized).expect_err("refused locally");
        assert!(matches!(err, ClientError::Shape(_)), "unexpected error: {err}");
    }
}
