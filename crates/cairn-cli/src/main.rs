//! `cairn-demo` — the vertical slice, runnable.
//!
//! Demonstrates, in-process and without a network:
//!
//! 1. Two participants establish an MLS group (a DM is a two-member group).
//! 2. Messages are encrypted and franked together.
//! 3. The server sequences and tags them without seeing plaintext.
//! 4. A recipient builds a transcript report, and the server verifies it.
//! 5. Tampering with the report is detected.
//!
//! This is what `docs/README` calls the Phase 4 exit condition, minus the network hop.
//! Run with `cargo run -p cairn-cli`.

use cairn_crypto::franking::{self, Commitment, Context, ReportedMessage, ServerFrankingKey};
use cairn_crypto::mls::Session;
use cairn_crypto::verification::{ContactVerification, SafetyNumber};
use cairn_crypto::TranscriptReport;
use cairn_proto::{DeviceId, RoomId, UserId};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Cairn vertical slice ===\n");

    // --- 1. Two participants, one MLS group -------------------------------------------
    let alice = Session::new(b"alice@example.instance")?;
    let bob = Session::new(b"bob@example.instance")?;

    let mut alice_group = alice.create_group()?;
    let commit = alice_group.add_member(bob.key_package()?)?;
    let mut bob_group = bob.join(&commit.welcome.ok_or("expected a welcome message")?)?;

    println!("1. MLS group established");
    println!("   members: {}, epoch: {}\n", alice_group.member_count(), alice_group.epoch());

    // --- 1a. Out-of-band key verification --------------------------------------------
    // MLS protects a group whose members were correctly identified. It cannot tell you
    // whether the server handed you the right key in the first place. Only comparing this
    // number over a channel the server does not control can.
    let safety = SafetyNumber::between(&alice.fingerprint(), &bob.fingerprint());
    println!("1a. Safety number (compare out of band)");
    println!("   {safety}");

    let impostor = Session::new(b"bob@example.instance")?;
    let spoofed = SafetyNumber::between(&alice.fingerprint(), &impostor.fingerprint());
    println!("   if the server substituted a key, Alice would instead see:");
    println!("   {spoofed}");
    println!("   -> mismatch is visible to the user: {}\n", safety != spoofed);

    let mut bob_record = ContactVerification::new(bob.fingerprint());
    bob_record.mark_verified();
    bob_record.observe(impostor.fingerprint());
    println!(
        "   after a key change post-verification, state = {:?}, warn = {}\n",
        bob_record.state,
        bob_record.needs_attention()
    );

    // --- 2 & 3. Send, frank, and let the "server" sequence + tag ----------------------
    // The server holds only this key and the ciphertext. It never sees plaintext.
    let server_key = ServerFrankingKey::generate();
    let room = RoomId::new();
    let alice_id = UserId::new();
    let alice_device = DeviceId::new();

    let conversation = [
        &b"hey, are you free later?"[..],
        &b"i wanted to talk about the thing"[..],
        &b"it's been bothering me"[..],
    ];

    let mut prev: Option<Commitment> = None;
    let mut seq = 0u64;
    let mut received: Vec<ReportedMessage> = Vec::new();

    for plaintext in conversation {
        // Client: commit and encrypt together.
        let (commitment, opening) = franking::commit(plaintext);
        let ciphertext = alice_group.encrypt(plaintext)?;
        let wire = ciphertext.to_bytes()?;

        // Server: sequence and tag. It sees `commitment` and `wire`, never `plaintext`.
        seq += 1;
        let context = Context {
            commitment,
            room,
            sender: alice_id,
            sender_device: alice_device,
            server_seq: seq,
            prev_commitment: prev,
        };
        let tag = server_key.tag(&context);
        prev = Some(commitment);

        // Recipient: decrypt, and retain what a future report would need.
        let decrypted = match bob_group.process(cairn_crypto::mls::parse_message(&wire)?)? {
            cairn_crypto::mls::GroupEvent::Application(data) => data,
            other => return Err(format!("expected an application message, got {other:?}").into()),
        };
        assert_eq!(decrypted, plaintext, "decrypted text must match what was sent");

        println!(
            "2. sent seq={seq} | {} bytes plaintext -> {} bytes ciphertext | server saw: ciphertext + commitment {}…",
            plaintext.len(),
            wire.len(),
            &commitment.to_hex()[..12]
        );

        received.push(ReportedMessage { plaintext: decrypted, opening, context, tag });
    }

    // --- 4. Bob reports the conversation ----------------------------------------------
    println!("\n3. Bob reports the transcript");
    let report = TranscriptReport { messages: received.clone() };
    match report.verify(&server_key) {
        Ok(()) => println!(
            "   VERIFIED: {} messages, provably sent by {alice_id} in order",
            report.messages.len()
        ),
        Err(e) => println!("   unexpectedly failed: {e}"),
    }

    // --- 5. Tampering is detected ------------------------------------------------------
    println!("\n4. Tamper checks");

    let mut edited = received.clone();
    edited[1].plaintext = b"something far worse that was never said".to_vec();
    match (TranscriptReport { messages: edited }).verify(&server_key) {
        Ok(()) => println!("   BUG: edited plaintext verified!"),
        Err(e) => println!("   edited message  -> rejected: {e}"),
    }

    let dropped = vec![received[0].clone(), received[2].clone()];
    match (TranscriptReport { messages: dropped }).verify(&server_key) {
        Ok(()) => println!("   BUG: a report with a hole verified!"),
        Err(e) => println!("   omitted context -> rejected: {e}"),
    }

    let mut reattributed = received.clone();
    reattributed[0].context.sender = UserId::new();
    match (TranscriptReport { messages: reattributed }).verify(&server_key) {
        Ok(()) => println!("   BUG: reattributed message verified!"),
        Err(e) => println!("   wrong sender    -> rejected: {e}"),
    }

    println!("\n=== done ===");
    Ok(())
}
