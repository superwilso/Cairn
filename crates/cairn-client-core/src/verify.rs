//! Safety numbers and contact verification, in the shape a frontend asks for them.
//!
//! ## Why this is not left to each client
//!
//! `cairn-cli` had `/safety` and `/verify` inline; the desktop client had nothing, and the
//! obvious way to give it something was to copy that logic into a second place — or worse,
//! into JavaScript. Both halves of a safety number have to come from the MLS roster
//! (`docs/01-threat-model.md` §4 records what happened when they did not), and the contact
//! store has to be told about the roster before it is asked about anyone. Those are two
//! easy things to get wrong once, and a second copy is a second chance. So the rules live
//! here, and a frontend gets plain strings back.
//!
//! ## Two things this enforces that the primitives alone did not
//!
//! Both were found by probing, not by reading:
//!
//! - **State is reported for the key the group uses now.** [`ContactStore::state_of`] answers
//!   from whatever it last *observed*, and nothing in `Session` ever called `observe`. A
//!   contact verified once — in the CLI, which shares the profile directory — then replaced
//!   by a leaf with the same credential and a different key was still reported `Verified`:
//!   the desktop drew a tick next to the substituted key. Every query here observes the
//!   roster first, so a substitution surfaces as the sticky `ChangedSinceVerified` instead.
//! - **Only the number the user was shown can be marked verified.** Verifying by position
//!   ("member 2") marks whatever key that position holds *at the moment of the click*. If a
//!   commit lands between showing the number and pressing the button, the user certifies a
//!   key they never compared. [`verify`] takes the number back and refuses if it no longer
//!   matches.

use serde::{Deserialize, Serialize};

use cairn_crypto::mls::GroupMember;
use cairn_crypto::verification::VerificationState;
use cairn_proto::{DeviceIdentity, UserId};

use crate::contacts::{ContactError, ContactStore};
use crate::conversation::{Conversation, ConversationError};

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error(transparent)]
    Contacts(#[from] ContactError),
    #[error(transparent)]
    Conversation(#[from] ConversationError),
    #[error("that device is not in this room's encrypted group")]
    NotInGroup,
    #[error("that is this device — there is nothing to compare it with")]
    OwnDevice,
    /// The key behind the number changed between being shown and being confirmed.
    #[error("the safety number changed since it was shown — compare the new one before verifying")]
    NumberChanged,
    /// Defensive: `mls-rs` will not admit two leaves with one credential (see
    /// `a_group_will_not_hold_two_leaves_claiming_one_device`), so this should be
    /// unreachable. If that ever stops holding, verifying "the" leaf for an identity would
    /// be a guess, and this refuses rather than guessing.
    #[error("more than one leaf in this group claims that device; refusing to pick one")]
    Ambiguous,
}

/// One device's safety number, as a frontend shows it.
///
/// Per device, not per account: each device holds its own leaf and its own key
/// (`docs/01-threat-model.md` §6), so someone with a phone and a laptop has two numbers, and
/// comparing one says nothing about the other.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SafetyView {
    pub user: String,
    pub device: String,
    /// Twelve groups of five digits, space-separated — the exact string [`verify`] expects
    /// back.
    pub number: String,
    pub state: VerificationState,
}

/// Record a sighting of every other leaf in the group.
///
/// Called before any verification state is reported, so the state describes the keys the
/// group holds now rather than the keys it held when someone last happened to look.
pub fn observe_roster(
    convo: &Conversation,
    contacts: &mut ContactStore,
) -> Result<(), VerifyError> {
    let own = convo.own_member()?;
    for member in convo.members() {
        if member.index != own.index {
            contacts.observe(&member)?;
        }
    }
    Ok(())
}

/// The safety number for each of `user`'s devices in this group, other than this one.
///
/// Both fingerprints come from the roster, via `Conversation::safety_number_with`. Asking
/// about your own account lists your *other* devices, which is the check that catches a
/// leaf presenting itself as one of yours.
pub fn safety_numbers(
    convo: &Conversation,
    contacts: &mut ContactStore,
    user: UserId,
) -> Result<Vec<SafetyView>, VerifyError> {
    observe_roster(convo, contacts)?;
    let own = convo.own_member()?;

    let mut out = Vec::new();
    for member in convo.members() {
        if member.index == own.index {
            continue;
        }
        let Ok(id) = DeviceIdentity::parse(&member.identity) else { continue };
        if !id.belongs_to(user) {
            continue;
        }
        out.push(SafetyView {
            user: id.user().to_string(),
            device: id.device().to_string(),
            number: convo.safety_number_with(&member)?.as_str().to_string(),
            state: contacts.state_of(&member.identity),
        });
    }
    Ok(out)
}

/// Mark one device verified, **only if** `shown` is still its safety number.
///
/// `shown` is the number the user compared, handed back exactly as [`safety_numbers`]
/// produced it. Separators are ignored, so a frontend that re-grouped the digits for
/// display does not have to undo it. Neither value is secret — both are on the user's
/// screen — so this compares digits plainly rather than in constant time.
pub fn verify(
    convo: &Conversation,
    contacts: &mut ContactStore,
    identity: &[u8],
    shown: &str,
) -> Result<(), VerifyError> {
    let own = convo.own_member()?;
    if own.identity == identity {
        return Err(VerifyError::OwnDevice);
    }
    let leaf = sole_leaf(&convo.members(), identity)?;

    // Observed first, so the record holds this leaf's fingerprint — the one the number is
    // computed from — and a key change since the last sighting is recorded rather than
    // overwritten by the verification.
    contacts.observe(&leaf)?;

    let current = convo.safety_number_with(&leaf)?;
    let shown: String = shown.chars().filter(char::is_ascii_digit).collect();
    if shown != current.digits() {
        return Err(VerifyError::NumberChanged);
    }

    if !contacts.mark_verified(identity)? {
        // Unreachable after `observe`, and treated as a failure rather than a success if it
        // ever is: reporting "verified" without having recorded it is the worse outcome.
        return Err(VerifyError::NotInGroup);
    }
    Ok(())
}

fn sole_leaf(roster: &[GroupMember], identity: &[u8]) -> Result<GroupMember, VerifyError> {
    let mut matching = roster.iter().filter(|m| m.identity == identity);
    let leaf = matching.next().ok_or(VerifyError::NotInGroup)?;
    if matching.next().is_some() {
        return Err(VerifyError::Ambiguous);
    }
    Ok(leaf.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::Arc;

    use cairn_crypto::mls::Session as MlsSession;
    use cairn_proto::{DeviceId, RoomId, RoomSeal, RoomShape};

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir()
            .join("cairn-verify")
            .join(format!("{name}-{}", uuid::Uuid::new_v4()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn group_seal() -> RoomSeal {
        RoomSeal::new(RoomShape {
            is_direct: false,
            is_publicly_discoverable: false,
            member_ceiling: 16,
        })
        .unwrap()
    }

    /// A device as the protocol knows it: account, device, and the MLS session whose
    /// credential names both.
    struct Device {
        id: DeviceIdentity,
        mls: Arc<MlsSession>,
    }

    impl Device {
        fn new(user: UserId) -> Self {
            Self::with_identity(DeviceIdentity::new(user, DeviceId::new()))
        }

        /// A fresh key under an existing credential — a reinstall, or an impostor. The
        /// group cannot tell which, and neither can this test; that is the point.
        fn with_identity(id: DeviceIdentity) -> Self {
            Self { id, mls: Arc::new(MlsSession::new(&id.to_credential()).unwrap()) }
        }

        fn credential(&self) -> Vec<u8> {
            self.id.to_credential()
        }
    }

    fn create(owner: &Device) -> Conversation {
        Conversation::create_encrypted(
            group_seal(),
            RoomId::new(),
            owner.id.user(),
            owner.id.device(),
            owner.mls.clone(),
        )
        .unwrap()
    }

    fn add(convo: &mut Conversation, device: &Device) -> cairn_crypto::mls::CommitOutput {
        convo.group_mut().unwrap().add_member(device.mls.key_package().unwrap()).unwrap()
    }

    fn leaf_of(convo: &Conversation, device: &Device) -> GroupMember {
        let credential = device.credential();
        convo.members().into_iter().find(|m| m.identity == credential).unwrap()
    }

    fn number_for(convo: &Conversation, contacts: &mut ContactStore, device: &Device) -> String {
        safety_numbers(convo, contacts, device.id.user())
            .unwrap()
            .into_iter()
            .find(|v| v.device == device.id.device().to_string())
            .unwrap()
            .number
    }

    /// Replace `device`'s leaf with a different key under the same credential.
    fn substitute(convo: &mut Conversation, device: &Device) -> Device {
        let index = leaf_of(convo, device).index;
        convo.group_mut().unwrap().remove_member(index).unwrap();
        let impostor = Device::with_identity(device.id);
        add(convo, &impostor);
        impostor
    }

    #[test]
    fn a_safety_number_changes_when_the_contacts_key_changes() {
        // The property the whole feature rests on: a substituted key cannot keep the number
        // the user already compared.
        let alice = Device::new(UserId::new());
        let bob = Device::new(UserId::new());
        let mut room = create(&alice);
        add(&mut room, &bob);
        let mut contacts = ContactStore::open(scratch("changes")).unwrap();

        let before = number_for(&room, &mut contacts, &bob);
        substitute(&mut room, &bob);
        let after = number_for(&room, &mut contacts, &bob);

        assert_ne!(before, after, "a different key under the same credential must not match");
    }

    #[test]
    fn both_ends_of_a_conversation_see_the_same_number() {
        // Otherwise there is nothing to compare: a mismatch on an honest connection teaches
        // people that mismatches are normal.
        let alice = Device::new(UserId::new());
        let bob = Device::new(UserId::new());
        let mut alice_room = create(&alice);
        let welcome = add(&mut alice_room, &bob).welcome.unwrap();
        let bob_room = Conversation::join_encrypted(
            group_seal(),
            alice_room.room(),
            bob.id.user(),
            bob.id.device(),
            bob.mls.clone(),
            bob.mls.join(&welcome).unwrap(),
        )
        .unwrap();

        let seen_by_alice =
            number_for(&alice_room, &mut ContactStore::open(scratch("ends-a")).unwrap(), &bob);
        let seen_by_bob =
            number_for(&bob_room, &mut ContactStore::open(scratch("ends-b")).unwrap(), &alice);
        assert_eq!(seen_by_alice, seen_by_bob);
        assert_eq!(seen_by_alice.split(' ').count(), 12, "twelve groups of five, as displayed");
    }

    #[test]
    fn verifying_one_contact_does_not_verify_another() {
        // Neither another account, nor another device of the same account: each holds its
        // own key, and comparing one number says nothing about a key nobody looked at.
        let alice = Device::new(UserId::new());
        let bob_phone = Device::new(UserId::new());
        let bob_laptop = Device::new(bob_phone.id.user());
        let carol = Device::new(UserId::new());
        let mut room = create(&alice);
        for device in [&bob_phone, &bob_laptop, &carol] {
            add(&mut room, device);
        }
        let mut contacts = ContactStore::open(scratch("one")).unwrap();

        let shown = number_for(&room, &mut contacts, &bob_phone);
        verify(&room, &mut contacts, &bob_phone.credential(), &shown).unwrap();

        assert_eq!(contacts.state_of(&bob_phone.credential()), VerificationState::Verified);
        assert_eq!(contacts.state_of(&bob_laptop.credential()), VerificationState::Unverified);
        assert_eq!(contacts.state_of(&carol.credential()), VerificationState::Unverified);

        let bobs = safety_numbers(&room, &mut contacts, bob_phone.id.user()).unwrap();
        assert_eq!(bobs.len(), 2, "one number per device, not one per account");
        assert_ne!(bobs[0].number, bobs[1].number);
    }

    #[test]
    fn a_key_substituted_after_verification_is_reported_even_if_nobody_observed_it() {
        // The probe that found this: Bob was verified (in the CLI, which shares the profile
        // directory), his leaf was then replaced by a different key under his credential,
        // and `Session::members` — which read the store without observing the roster —
        // reported him `Verified`. The desktop drew a tick next to the substituted key.
        let alice = Device::new(UserId::new());
        let bob = Device::new(UserId::new());
        let mut room = create(&alice);
        add(&mut room, &bob);
        let dir = scratch("unobserved");

        {
            let mut contacts = ContactStore::open(&dir).unwrap();
            let shown = number_for(&room, &mut contacts, &bob);
            verify(&room, &mut contacts, &bob.credential(), &shown).unwrap();
        }
        substitute(&mut room, &bob);

        // A fresh process: nothing has seen the new key yet.
        let mut contacts = ContactStore::open(&dir).unwrap();
        let view = safety_numbers(&room, &mut contacts, bob.id.user()).unwrap();
        assert_eq!(view[0].state, VerificationState::ChangedSinceVerified);
        assert_eq!(
            contacts.state_of(&bob.credential()),
            VerificationState::ChangedSinceVerified,
            "and the warning is now recorded, so it survives whatever is asked next"
        );
    }

    #[test]
    fn a_number_that_changed_while_on_screen_cannot_be_verified() {
        // Verifying by position would certify whatever key held the position at the moment
        // of the click — here, one the user never saw.
        let alice = Device::new(UserId::new());
        let bob = Device::new(UserId::new());
        let mut room = create(&alice);
        add(&mut room, &bob);
        let mut contacts = ContactStore::open(scratch("raced")).unwrap();

        let shown = number_for(&room, &mut contacts, &bob);
        substitute(&mut room, &bob);

        let result = verify(&room, &mut contacts, &bob.credential(), &shown);
        assert!(matches!(result, Err(VerifyError::NumberChanged)), "{result:?}");
        assert_ne!(contacts.state_of(&bob.credential()), VerificationState::Verified);

        // Re-verifying against the number now on screen is the way out, and it works.
        let fresh = number_for(&room, &mut contacts, &bob);
        verify(&room, &mut contacts, &bob.credential(), &fresh).unwrap();
        assert_eq!(contacts.state_of(&bob.credential()), VerificationState::Verified);
    }

    #[test]
    fn a_changed_key_stays_flagged_until_the_new_number_is_compared() {
        // The sticky warning from the contact store, as this layer reports it: asking again
        // must not clear it, only an explicit re-verification may.
        let alice = Device::new(UserId::new());
        let bob = Device::new(UserId::new());
        let mut room = create(&alice);
        add(&mut room, &bob);
        let mut contacts = ContactStore::open(scratch("sticky")).unwrap();

        let shown = number_for(&room, &mut contacts, &bob);
        verify(&room, &mut contacts, &bob.credential(), &shown).unwrap();
        substitute(&mut room, &bob);

        for _ in 0..3 {
            let view = safety_numbers(&room, &mut contacts, bob.id.user()).unwrap();
            assert_eq!(view[0].state, VerificationState::ChangedSinceVerified);
        }
    }

    #[test]
    fn digit_grouping_does_not_matter_but_every_digit_does() {
        let alice = Device::new(UserId::new());
        let bob = Device::new(UserId::new());
        let mut room = create(&alice);
        add(&mut room, &bob);
        let mut contacts = ContactStore::open(scratch("format")).unwrap();
        let shown = number_for(&room, &mut contacts, &bob);

        let mut wrong: Vec<char> = shown.chars().collect();
        let last = wrong.len() - 1;
        wrong[last] = if wrong[last] == '0' { '1' } else { '0' };
        let wrong: String = wrong.into_iter().collect();
        assert!(matches!(
            verify(&room, &mut contacts, &bob.credential(), &wrong),
            Err(VerifyError::NumberChanged)
        ));
        assert!(matches!(
            verify(&room, &mut contacts, &bob.credential(), ""),
            Err(VerifyError::NumberChanged)
        ));

        let regrouped =
            shown.replace(' ', "").as_bytes().chunks(20).fold(String::new(), |mut acc, chunk| {
                acc.push_str(std::str::from_utf8(chunk).unwrap());
                acc.push('\n');
                acc
            });
        verify(&room, &mut contacts, &bob.credential(), &regrouped).unwrap();
    }

    #[test]
    fn a_device_outside_the_group_cannot_be_verified() {
        // Otherwise a request naming any device id would mint a verified contact whose key
        // never came from a group.
        let alice = Device::new(UserId::new());
        let bob = Device::new(UserId::new());
        let stranger = Device::new(UserId::new());
        let mut room = create(&alice);
        add(&mut room, &bob);
        let mut contacts = ContactStore::open(scratch("stranger")).unwrap();
        let shown = number_for(&room, &mut contacts, &bob);

        let result = verify(&room, &mut contacts, &stranger.credential(), &shown);
        assert!(matches!(result, Err(VerifyError::NotInGroup)), "{result:?}");
        assert!(contacts.get(&stranger.credential()).is_none());
    }

    #[test]
    fn a_device_cannot_verify_itself() {
        let alice = Device::new(UserId::new());
        let bob = Device::new(UserId::new());
        let mut room = create(&alice);
        add(&mut room, &bob);
        let mut contacts = ContactStore::open(scratch("self")).unwrap();
        let shown = number_for(&room, &mut contacts, &bob);

        let result = verify(&room, &mut contacts, &alice.credential(), &shown);
        assert!(matches!(result, Err(VerifyError::OwnDevice)), "{result:?}");
        assert!(
            safety_numbers(&room, &mut contacts, alice.id.user()).unwrap().is_empty(),
            "your own account lists only your other devices"
        );
    }

    #[test]
    fn a_group_will_not_hold_two_leaves_claiming_one_device() {
        // `verify` identifies a leaf by credential. That is only unambiguous because the
        // group refuses a second leaf with the same one — if a future `mls-rs` stops doing
        // so, this fails and `VerifyError::Ambiguous` stops being theoretical.
        let alice = Device::new(UserId::new());
        let bob = Device::new(UserId::new());
        let mut room = create(&alice);
        add(&mut room, &bob);

        let twin = Device::with_identity(bob.id);
        let second = room.group_mut().unwrap().add_member(twin.mls.key_package().unwrap());
        assert!(second.is_err(), "a second leaf for one device was admitted");
        assert_eq!(room.members().iter().filter(|m| m.identity == bob.credential()).count(), 1);
    }
}
