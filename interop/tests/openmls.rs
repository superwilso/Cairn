//! Cairn's MLS (`mls-rs`, through `cairn-crypto`) and OpenMLS in the same group.
//!
//! Everything crosses as serialized bytes, as it would through an instance: neither side
//! sees the other's types. Cairn's side uses only `cairn-crypto`'s public API, so these
//! tests also hold that API to what `docs/15-protocol.md` §7.1 says an implementation
//! needs.

use cairn_crypto::mls::{GroupEvent, GroupHandle, Session as CairnSession};
use cairn_proto::{DeviceId, DeviceIdentity, UserId};
use openmls::prelude::tls_codec::Deserialize as _;
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;

/// RFC 9420 ciphersuite 0x0001, the one Cairn pins.
const SUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

fn credential() -> Vec<u8> {
    DeviceIdentity::new(UserId::new(), DeviceId::new()).to_credential()
}

fn cairn() -> (CairnSession, Vec<u8>) {
    let id = credential();
    (CairnSession::new(&id).unwrap(), id)
}

/// An OpenMLS client: its provider, signing key and credential.
struct Other {
    provider: OpenMlsRustCrypto,
    signer: SignatureKeyPair,
    credential: CredentialWithKey,
    identity: Vec<u8>,
}

impl Other {
    fn new() -> Self {
        let provider = OpenMlsRustCrypto::default();
        let signer = SignatureKeyPair::new(SUITE.signature_algorithm()).unwrap();
        signer.store(provider.storage()).unwrap();
        let identity = credential();
        let credential = CredentialWithKey {
            credential: BasicCredential::new(identity.clone()).into(),
            signature_key: signer.to_public_vec().into(),
        };
        Other { provider, signer, credential, identity }
    }

    /// A key package as the bytes an instance would store and hand out.
    fn key_package(&self) -> Vec<u8> {
        let bundle = KeyPackage::builder()
            .build(SUITE, &self.provider, &self.signer, self.credential.clone())
            .unwrap();
        MlsMessageOut::from(bundle.key_package().clone()).to_bytes().unwrap()
    }

    fn join(&self, welcome: &[u8], policy: WireFormatPolicy) -> MlsGroup {
        let MlsMessageBodyIn::Welcome(welcome) = message_in(welcome).extract() else {
            panic!("expected a welcome");
        };
        // The tree in its own welcomes too (§7.1): without it, a Cairn device this client
        // adds later fails to join with `RatchetTreeNotFound`, which is how this was found.
        let config = MlsGroupJoinConfig::builder()
            .wire_format_policy(policy)
            .use_ratchet_tree_extension(true)
            .build();
        // No tree passed in: §7.1 says the welcome carries it, and a joiner has no other
        // way to get one.
        StagedWelcome::new_from_welcome(&self.provider, &config, welcome, None)
            .expect("an OpenMLS client must be able to read Cairn's welcome")
            .into_group(&self.provider)
            .unwrap()
    }

    fn send(&self, group: &mut MlsGroup, text: &[u8]) -> Vec<u8> {
        group.create_message(&self.provider, &self.signer, text).unwrap().to_bytes().unwrap()
    }

    /// Process one message and return what it carried, merging a commit if it was one.
    fn receive(&self, group: &mut MlsGroup, bytes: &[u8]) -> Result<Received, String> {
        let message = message_in(bytes).try_into_protocol_message().map_err(|e| e.to_string())?;
        let processed =
            group.process_message(&self.provider, message).map_err(|e| format!("{e:?}"))?;
        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(m) => Ok(Received::Text(m.into_bytes())),
            ProcessedMessageContent::StagedCommitMessage(commit) => {
                group.merge_staged_commit(&self.provider, *commit).unwrap();
                Ok(Received::Commit)
            }
            other => Err(format!("unexpected message: {other:?}")),
        }
    }
}

#[derive(Debug, PartialEq)]
enum Received {
    Text(Vec<u8>),
    Commit,
}

fn message_in(bytes: &[u8]) -> MlsMessageIn {
    MlsMessageIn::tls_deserialize_exact(bytes).expect("a well-formed MLSMessage")
}

/// The roster as (identity, signature key) pairs, in leaf order.
fn cairn_roster(group: &GroupHandle) -> Vec<(Vec<u8>, Vec<u8>)> {
    group.members().into_iter().map(|m| (m.identity, m.signature_key)).collect()
}

fn other_roster(group: &MlsGroup) -> Vec<(Vec<u8>, Vec<u8>)> {
    group.members().map(|m| (m.credential.serialized_content().to_vec(), m.signature_key)).collect()
}

fn cairn_reads(group: &mut GroupHandle, bytes: &[u8]) -> Vec<u8> {
    match group.process(cairn_crypto::mls::parse_message(bytes).unwrap()).unwrap() {
        GroupEvent::Application(text) => text,
        other => panic!("expected an application message, got {other:?}"),
    }
}

/// Cairn's group, as a Cairn client builds it, with an OpenMLS client added by key package.
fn cairn_group_with_other(policy: WireFormatPolicy) -> (GroupHandle, Vec<u8>, Other, MlsGroup) {
    let (alice, alice_id) = cairn();
    let mut group = alice.create_group().unwrap();
    let bob = Other::new();
    let package = cairn_crypto::mls::parse_message(&bob.key_package()).unwrap();
    let output = group.add_member(package).expect("Cairn must accept an OpenMLS key package");
    let welcome = output.welcome.unwrap().to_bytes().unwrap();
    let bob_group = bob.join(&welcome, policy);
    (group, alice_id, bob, bob_group)
}

#[test]
fn an_openmls_client_joins_a_cairn_group_and_both_read_each_other() {
    let (mut alice, _, bob, mut bob_group) =
        cairn_group_with_other(MIXED_CIPHERTEXT_WIRE_FORMAT_POLICY);

    assert_eq!(alice.epoch(), bob_group.epoch().as_u64(), "both sides in the same epoch");
    assert_eq!(
        cairn_roster(&alice),
        other_roster(&bob_group),
        "both sides must see the same leaves with the same keys — a safety number is \
         computed over this roster"
    );

    let to_bob = alice.encrypt(b"from mls-rs").unwrap().to_bytes().unwrap();
    assert_eq!(bob.receive(&mut bob_group, &to_bob), Ok(Received::Text(b"from mls-rs".to_vec())));

    let to_alice = bob.send(&mut bob_group, b"from openmls");
    assert_eq!(cairn_reads(&mut alice, &to_alice), b"from openmls");
}

#[test]
fn an_openmls_client_derives_the_same_voice_media_key() {
    // Voice frames are sealed under an exporter secret, not an MLS message, so nothing
    // above would notice if the two implementations derived different keys. A client that
    // did would hear nothing in a voice channel and see no error.
    let (alice, alice_id, bob, bob_group) =
        cairn_group_with_other(MIXED_CIPHERTEXT_WIRE_FORMAT_POLICY);
    let room = b"a room id";
    let ours = alice.media_key(room, &alice_id).unwrap();
    let label = std::str::from_utf8(cairn_crypto::media::MEDIA_KEY_LABEL).unwrap();
    let context = cairn_crypto::media::key_context(room, &alice_id);
    let theirs = bob_group.export_secret(bob.provider.crypto(), label, &context, 16).unwrap();
    assert_eq!(ours.as_bytes().as_slice(), theirs.as_slice());
}

#[test]
fn a_cairn_client_joins_an_openmls_group_and_both_read_each_other() {
    let carol = Other::new();
    // The ratchet tree goes in the welcome, as §7.1 requires: Cairn's join has nowhere else
    // to get it from.
    let config =
        MlsGroupCreateConfig::builder().ciphersuite(SUITE).use_ratchet_tree_extension(true).build();
    let mut carol_group =
        MlsGroup::new(&carol.provider, &carol.signer, &config, carol.credential.clone()).unwrap();

    let (dave, _) = cairn();
    let package = dave.key_package().unwrap().to_bytes().unwrap();
    let MlsMessageBodyIn::KeyPackage(package) = message_in(&package).extract() else {
        panic!("expected a key package");
    };
    let package = package
        .validate(carol.provider.crypto(), ProtocolVersion::Mls10)
        .expect("OpenMLS must accept a Cairn key package");
    let (_commit, welcome, _) =
        carol_group.add_members(&carol.provider, &carol.signer, &[package]).unwrap();
    carol_group.merge_pending_commit(&carol.provider).unwrap();

    let welcome = cairn_crypto::mls::parse_message(&welcome.to_bytes().unwrap()).unwrap();
    let mut dave_group = dave.join(&welcome).expect("Cairn must be able to read OpenMLS's welcome");
    assert_eq!(cairn_roster(&dave_group), other_roster(&carol_group));

    let to_dave = carol.send(&mut carol_group, b"from openmls");
    assert_eq!(cairn_reads(&mut dave_group, &to_dave), b"from openmls");
    let to_carol = dave_group.encrypt(b"from mls-rs").unwrap().to_bytes().unwrap();
    assert_eq!(
        carol.receive(&mut carol_group, &to_carol),
        Ok(Received::Text(b"from mls-rs".to_vec()))
    );
}

#[test]
fn commits_cross_in_both_directions_and_a_removed_openmls_client_is_cut_off() {
    let (mut alice, _, bob, mut bob_group) =
        cairn_group_with_other(MIXED_CIPHERTEXT_WIRE_FORMAT_POLICY);

    // OpenMLS commits an add, with an update path and encrypted, as its defaults do. Cairn
    // follows it, and the Cairn client it added joins from OpenMLS's welcome.
    let (erin, erin_id) = cairn();
    let package = erin.key_package().unwrap().to_bytes().unwrap();
    let MlsMessageBodyIn::KeyPackage(package) = message_in(&package).extract() else {
        panic!("expected a key package");
    };
    let package = package.validate(bob.provider.crypto(), ProtocolVersion::Mls10).unwrap();
    let (commit, welcome, _) =
        bob_group.add_members(&bob.provider, &bob.signer, &[package]).unwrap();
    bob_group.merge_pending_commit(&bob.provider).unwrap();
    let commit = commit.to_bytes().unwrap();
    match alice.process(cairn_crypto::mls::parse_message(&commit).unwrap()).unwrap() {
        GroupEvent::MembershipChanged { added, removed, .. } => {
            assert_eq!(added.len(), 1);
            assert_eq!(added[0].identity, erin_id, "Cairn must name who OpenMLS added");
            assert!(removed.is_empty());
        }
        other => panic!("expected a membership change, got {other:?}"),
    }
    let welcome = cairn_crypto::mls::parse_message(&welcome.to_bytes().unwrap()).unwrap();
    let mut erin_group = erin.join(&welcome).unwrap();
    assert_eq!(cairn_roster(&alice), other_roster(&bob_group));
    assert_eq!(cairn_roster(&erin_group), other_roster(&bob_group));

    // Cairn commits a removal of the OpenMLS client: a PublicMessage commit with no path.
    let bob_index = alice.members().into_iter().find(|m| m.identity == bob.identity).unwrap().index;
    let removal = alice.remove_member(bob_index).unwrap().commit.to_bytes().unwrap();
    assert_eq!(bob.receive(&mut bob_group, &removal), Ok(Received::Commit));
    assert!(!bob_group.is_active(), "OpenMLS must see that it was removed");
    erin_group.process(cairn_crypto::mls::parse_message(&removal).unwrap()).unwrap();

    let after = alice.encrypt(b"after the removal").unwrap().to_bytes().unwrap();
    assert_eq!(cairn_reads(&mut erin_group, &after), b"after the removal");
    assert!(
        bob.receive(&mut bob_group, &after).is_err(),
        "the removed OpenMLS client must not read what follows its removal"
    );
}

#[test]
fn an_openmls_client_left_on_its_default_wire_policy_cannot_follow_cairn_commits() {
    // OpenMLS's default incoming policy accepts only encrypted handshakes, and Cairn sends
    // commits as PublicMessage (§7.1). Recorded so the spec's warning stays true: an
    // implementation has to opt in to plaintext commits, and this says which way it fails
    // if it does not.
    let (mut alice, _, bob, mut bob_group) =
        cairn_group_with_other(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY);
    let (frank, _) = cairn();
    let commit = alice.add_member(frank.key_package().unwrap()).unwrap().commit.to_bytes().unwrap();
    let refused = bob.receive(&mut bob_group, &commit);
    // On the wire format, not on anything else a mismatch could have broken.
    assert_eq!(refused, Err("IncompatibleWireFormat".to_owned()));
}
