//! Measure how MLS group operations scale with membership.
//!
//! `docs/03-protocol-evaluation.md` owes numbers for criterion 1, and
//! `T1_MAX_MEMBERS` / `T2_MAX_MEMBERS` in `cairn-proto` are provisional placeholders that
//! block any public claim about group sizes. This produces the data to replace them.
//!
//! ADR-002 justifies MLS on the grounds that group operations are O(log n) rather than the
//! O(n²) of sender-key fanout. That is the claim under test here — if add latency or commit
//! size grows linearly in practice, the justification does not hold and the ceiling has to
//! come down.
//!
//! Run with `cargo run -p cairn-crypto --example group_scaling --release`.
//! Debug builds are 10-50x slower for this workload and will mislead you.

use std::time::{Duration, Instant};

use cairn_crypto::mls::Session;

/// Group sizes to measure. Sparse at the top because setup cost is linear in size.
const SIZES: &[usize] = &[2, 10, 50, 100, 250, 500, 1000];

/// Messages timed per size, to average out scheduler noise.
const MESSAGE_SAMPLES: usize = 20;

struct Measurement {
    size: usize,
    /// Time to commit a single additional member to a group already this large.
    /// This is the steady-state cost users actually feel when someone joins.
    add_member: Duration,
    /// Wire size of that commit, which every existing member must download.
    commit_bytes: usize,
    /// Wire size of the welcome the newcomer must download.
    welcome_bytes: usize,
    /// Per-message encrypt cost at this size.
    encrypt: Duration,
    /// Per-message decrypt cost at this size.
    decrypt: Duration,
    /// Time to build the group in the first place, for context on the harness itself.
    setup: Duration,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if cfg!(debug_assertions) {
        eprintln!("WARNING: debug build. Numbers will be far slower than reality.");
        eprintln!("         Re-run with --release before recording anything.\n");
    }

    println!("MLS group scaling — ciphersuite {:?}\n", cairn_crypto::mls::CIPHERSUITE);

    let mut results = Vec::new();
    for &size in SIZES {
        eprint!("measuring n={size}… ");
        let m = measure(size)?;
        eprintln!("done");
        results.push(m);
    }

    println!(
        "{:>6}  {:>12}  {:>12}  {:>12}  {:>10}  {:>10}  {:>10}",
        "n", "add member", "commit B", "welcome B", "encrypt", "decrypt", "setup"
    );
    println!("{}", "-".repeat(84));
    for m in &results {
        println!(
            "{:>6}  {:>12}  {:>12}  {:>12}  {:>10}  {:>10}  {:>10}",
            m.size,
            format!("{:.2?}", m.add_member),
            m.commit_bytes,
            m.welcome_bytes,
            format!("{:.2?}", m.encrypt),
            format!("{:.2?}", m.decrypt),
            format!("{:.1?}", m.setup),
        );
    }

    // The point of the table is the growth rate, not the absolute numbers, which are
    // machine-specific. Report it explicitly so nobody has to eyeball it.
    println!("\nGrowth from smallest to largest measured group:");
    if let (Some(first), Some(last)) = (results.first(), results.last()) {
        let n_ratio = last.size as f64 / first.size as f64;
        let add_ratio = last.add_member.as_secs_f64() / first.add_member.as_secs_f64().max(1e-9);
        let commit_ratio = last.commit_bytes as f64 / first.commit_bytes as f64;
        let enc_ratio = last.encrypt.as_secs_f64() / first.encrypt.as_secs_f64().max(1e-9);

        println!("  members    x{n_ratio:.0}");
        println!("  add member x{add_ratio:.1}   (log2 of member growth = {:.1})", n_ratio.log2());
        println!("  commit size x{commit_ratio:.1}");
        println!("  encrypt    x{enc_ratio:.1}   (should be ~flat: independent of group size)");
        println!(
            "\nADR-002 predicts add-member cost grows like log(n), so roughly x{:.1} here.",
            n_ratio.log2()
        );
        println!(
            "If it instead tracks x{n_ratio:.0}, the O(log n) claim does not hold in practice."
        );
    }

    Ok(())
}

fn measure(size: usize) -> Result<Measurement, Box<dyn std::error::Error>> {
    // Build a group of `size` members. Members are added in one commit per member, which
    // is the realistic pattern — people join one at a time.
    let setup_start = Instant::now();
    let creator = Session::new(b"creator")?;
    let mut group = creator.create_group()?;

    // Keep one real joined member so decrypt is measured against a peer that actually
    // processes messages. It must apply *every* subsequent commit — a member that skips
    // one is permanently out of epoch, which is exactly what MLS's strict ordering
    // requirement means in practice (ADR-002).
    let mut peer: Option<cairn_crypto::mls::GroupHandle> = None;
    for i in 1..size {
        let member = Session::new(format!("member-{i}").as_bytes())?;
        let out = group.add_member(member.key_package()?)?;

        match peer.as_mut() {
            None => {
                let welcome = out.welcome.ok_or("expected a welcome")?;
                peer = Some(member.join(&welcome)?);
            }
            Some(p) => {
                p.process(cairn_crypto::mls::parse_message(&out.commit.to_bytes()?)?)?;
            }
        }
    }
    let setup = setup_start.elapsed();

    // Steady-state cost: add one more member to a group that is already `size` large.
    let newcomer = Session::new(b"newcomer")?;
    let kp = newcomer.key_package()?;
    let t = Instant::now();
    let out = group.add_member(kp)?;
    let add_member = t.elapsed();

    let commit_bytes = out.commit.to_bytes()?.len();
    let welcome_bytes = match &out.welcome {
        Some(w) => w.to_bytes()?.len(),
        None => 0,
    };

    // The peer must apply that commit before it can decrypt anything that follows.
    if let Some(p) = peer.as_mut() {
        p.process(cairn_crypto::mls::parse_message(&out.commit.to_bytes()?)?)?;
    }

    // Application message cost. MLS derives per-message keys from the current epoch, so
    // this should be flat in group size — worth confirming rather than assuming.
    let payload = vec![0u8; 256];
    let mut encrypt_total = Duration::ZERO;
    let mut decrypt_total = Duration::ZERO;
    let mut decrypt_samples = 0;

    for _ in 0..MESSAGE_SAMPLES {
        let t = Instant::now();
        let ct = group.encrypt(&payload)?;
        encrypt_total += t.elapsed();

        if let Some(peer) = peer.as_mut() {
            let wire = ct.to_bytes()?;
            let parsed = cairn_crypto::mls::parse_message(&wire)?;
            let t = Instant::now();
            peer.process(parsed)?;
            decrypt_total += t.elapsed();
            decrypt_samples += 1;
        }
    }

    Ok(Measurement {
        size,
        add_member,
        commit_bytes,
        welcome_bytes,
        encrypt: encrypt_total / MESSAGE_SAMPLES as u32,
        decrypt: if decrypt_samples > 0 {
            decrypt_total / decrypt_samples as u32
        } else {
            Duration::ZERO
        },
        setup,
    })
}
