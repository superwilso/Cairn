// THROWAWAY PROBES

use super::*;
use crate::storage::DbStorage;

#[test]
fn probe_concurrent_sends_then_restart() {
    let dir = temp_dir("probe-conc");
    let storage = Arc::new(DbStorage::new(&dir).unwrap());
    let inst = Arc::new(Instance::open(storage.clone()).unwrap());
    let owner = TestSender::registered(&inst);
    let (room, _) = inst.create_room(public_shape(), owner.user).unwrap();
    let senders: Vec<_> = (0..8).map(|_| TestSender::registered(&inst)).collect();
    for s in &senders {
        inst.join_room(room, s.user).unwrap();
    }
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let poller = {
        let inst = inst.clone();
        let stop = stop.clone();
        let user = owner.user;
        std::thread::spawn(move || {
            let mut cursor = 0u64;
            let mut seen = std::collections::BTreeSet::new();
            while !stop.load(std::sync::atomic::Ordering::SeqCst) {
                for m in inst.messages_since(room, user, cursor, 0).unwrap() {
                    seen.insert(m.server_seq);
                    cursor = cursor.max(m.server_seq);
                }
            }
            for m in inst.messages_since(room, user, cursor, 0).unwrap() {
                seen.insert(m.server_seq);
            }
            seen
        })
    };
    std::thread::scope(|sc| {
        for s in &senders {
            let inst = inst.clone();
            sc.spawn(move || {
                for i in 0..25 {
                    let e = s.envelope(room, EnvelopePayload::Plaintext { body: format!("{i}") });
                    inst.accept(e, 0).unwrap();
                }
            });
        }
    });
    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    let seen = poller.join().unwrap();
    println!("PROBE poller saw {} of 200 by cursor", seen.len());
    drop(senders);
    drop(owner);
    drop(inst);
    let inst = Instance::open(storage.clone()).unwrap();
    let next = inst.rooms.lock().unwrap()[&room].next_seq;
    let stored = inst.storage.messages_since(room, 0).unwrap();
    let max = stored.iter().map(|m| m.server_seq).max().unwrap();
    println!("PROBE after restart: next_seq on disk {next}, stored {} max seq {max}", stored.len());
}

#[test]
fn probe_concurrent_member_adds_then_restart() {
    let dir = temp_dir("probe-members");
    let storage = Arc::new(DbStorage::new(&dir).unwrap());
    let inst = Arc::new(Instance::open(storage.clone()).unwrap());
    let owner = TestSender::registered(&inst);
    let (room, _) = inst.create_room(public_shape(), owner.user).unwrap();
    let users: Vec<UserId> = (0..64).map(|_| UserId::new()).collect();
    let ou = owner.user;
    std::thread::scope(|sc| {
        for u in &users {
            let inst = inst.clone();
            sc.spawn(move || inst.add_room_member(room, ou, *u).unwrap());
        }
    });
    let mem = inst.rooms.lock().unwrap()[&room].members.len();
    drop(inst);
    let inst = Instance::open(storage).unwrap();
    let disk = inst.rooms.lock().unwrap()[&room].members.len();
    println!("PROBE members in memory {mem}, after restart {disk} (expected 65)");
}

#[test]
fn probe_failed_writes_leak_into_memory() {
    let storage = Arc::new(FailingStorage::default());
    let inst = Instance::open(storage.clone()).unwrap();
    let o = TestSender::registered(&inst);
    let (room, _) = inst.create_room(dm_shape(), o.user).unwrap();
    let fail = |on: bool| storage.fail.store(on, std::sync::atomic::Ordering::SeqCst);

    // send
    let (c1, _) = cairn_crypto::commit(b"lost");
    let e = o
        .unsigned(room, EnvelopePayload::MlsApplication { ciphertext: vec![1] })
        .with_franking_commitment(c1.to_hex());
    fail(true);
    let r = inst.accept(o.sign(e), 0);
    fail(false);
    let rm = inst.rooms.lock().unwrap()[&room].clone();
    println!("PROBE send failed={} -> memory next_seq {} last_franked set {}", r.is_err(), rm.next_seq, rm.last_franked.is_some());

    // account
    let (u, d) = (UserId::new(), DeviceId::new());
    let identity = cairn_proto::DeviceIdentity::new(u, d).to_credential();
    let s = cairn_crypto::mls::Session::new(&identity).unwrap();
    fail(true);
    let r = inst.claim_account(u, d, s.public_key(), None, 0);
    fail(false);
    let retry = inst.claim_account(u, d, s.public_key(), None, 0);
    println!("PROBE register failed={} -> retry gives {:?}", r.is_err(), retry);

    // invite
    fail(true);
    let r = inst.create_invite("abcdefghijklmnopqrstuvwxyz", None);
    fail(false);
    println!("PROBE invite failed={} -> in memory {}", r.is_err(), inst.invites.lock().unwrap().contains_key("abcdefghijklmnopqrstuvwxyz"));

    // room create
    fail(true);
    let before = inst.rooms.lock().unwrap().len();
    let r = inst.create_room(dm_shape(), o.user);
    fail(false);
    println!("PROBE create_room failed={} -> rooms {} -> {}", r.is_err(), before, inst.rooms.lock().unwrap().len());

    // key packages
    fail(true);
    let r = inst.publish_key_packages(o.user, o.device, o.key_packages(2));
    fail(false);
    println!("PROBE publish kp failed={} -> remaining {}", r.is_err(), inst.key_packages_remaining(o.device));

    // policy
    fail(true);
    let r = inst.set_registration_policy(RegistrationPolicy::InviteOnly);
    fail(false);
    println!("PROBE policy failed={} -> policy {:?}", r.is_err(), inst.registration_policy());
}

#[derive(Debug)]
struct Jitter {
    inner: DbStorage,
}
impl crate::storage::Storage for Jitter {
    fn load_or_create_franking_key(
        &self,
    ) -> Result<cairn_crypto::franking::ServerFrankingKey, StorageError> {
        self.inner.load_or_create_franking_key()
    }
    fn load_directory(&self) -> Result<crate::storage::Directory, StorageError> {
        self.inner.load_directory()
    }
    fn commit(&self, writes: &[Write]) -> Result<(), StorageError> {
        // A thread preempted between releasing the rooms lock and opening its transaction.
        std::thread::sleep(std::time::Duration::from_micros(rand::random::<u64>() % 3000));
        self.inner.commit(writes)
    }
    fn messages_since(&self, room: RoomId, after: u64) -> Result<Vec<StoredMessage>, StorageError> {
        self.inner.messages_since(room, after)
    }
    fn blob_meta(&self, id: BlobId) -> Result<Option<BlobRecord>, StorageError> {
        self.inner.blob_meta(id)
    }
    fn blob_bytes(&self, id: BlobId) -> Result<Option<Vec<u8>>, StorageError> {
        self.inner.blob_bytes(id)
    }
}

/// Holds the commit carrying message 1 until message 2 has committed.
#[derive(Debug)]
struct Gate {
    inner: DbStorage,
    second_done: (Mutex<bool>, std::sync::Condvar),
}
impl crate::storage::Storage for Gate {
    fn load_or_create_franking_key(
        &self,
    ) -> Result<cairn_crypto::franking::ServerFrankingKey, StorageError> {
        self.inner.load_or_create_franking_key()
    }
    fn load_directory(&self) -> Result<crate::storage::Directory, StorageError> {
        self.inner.load_directory()
    }
    fn commit(&self, writes: &[Write]) -> Result<(), StorageError> {
        let seq = writes.iter().find_map(|w| match w {
            Write::Message(_, m) => Some(m.server_seq),
            _ => None,
        });
        if seq == Some(1) {
            let (m, c) = &self.second_done;
            let mut done = m.lock().unwrap();
            while !*done {
                done = c.wait_timeout(done, std::time::Duration::from_secs(2)).unwrap().0;
                break;
            }
        }
        let r = self.inner.commit(writes);
        if seq == Some(2) {
            *self.second_done.0.lock().unwrap() = true;
            self.second_done.1.notify_all();
        }
        r
    }
    fn messages_since(&self, room: RoomId, after: u64) -> Result<Vec<StoredMessage>, StorageError> {
        self.inner.messages_since(room, after)
    }
    fn blob_meta(&self, id: BlobId) -> Result<Option<BlobRecord>, StorageError> {
        self.inner.blob_meta(id)
    }
    fn blob_bytes(&self, id: BlobId) -> Result<Option<Vec<u8>>, StorageError> {
        self.inner.blob_bytes(id)
    }
}

#[test]
fn probe_reordered_commits_then_restart() {
    let dir = temp_dir("probe-gate");
    let inst = Arc::new(
        Instance::open(Arc::new(Gate {
            inner: DbStorage::new(&dir).unwrap(),
            second_done: Default::default(),
        }))
        .unwrap(),
    );
    let a = TestSender::registered(&inst);
    let b = TestSender::registered(&inst);
    let (room, _) = inst.create_room(public_shape(), a.user).unwrap();
    inst.join_room(room, b.user).unwrap();
    std::thread::scope(|sc| {
        let i1 = inst.clone();
        let ea = a.envelope(room, EnvelopePayload::Plaintext { body: "first".into() });
        sc.spawn(move || i1.accept(ea, 0).unwrap());
        std::thread::sleep(std::time::Duration::from_millis(100));
        let eb = b.envelope(room, EnvelopePayload::Plaintext { body: "second".into() });
        let i2 = inst.clone();
        sc.spawn(move || i2.accept(eb, 0).unwrap());
    });
    drop(inst);
    let inst = Instance::open(Arc::new(DbStorage::new(&dir).unwrap())).unwrap();
    println!("PROBE gate after restart: next_seq {}", inst.rooms.lock().unwrap()[&room].next_seq);
    let e = a.envelope(room, EnvelopePayload::Plaintext { body: "third".into() });
    let s = inst.accept(e, 0).unwrap();
    let bodies: Vec<_> = inst
        .storage
        .messages_since(room, 0)
        .unwrap()
        .into_iter()
        .map(|m| (m.server_seq, format!("{:?}", m.envelope.payload)))
        .collect();
    println!("PROBE gate: third got seq {}; log now {bodies:?}", s.server_seq);
}

#[test]
fn probe_jittered_sends_and_adds() {
    let dir = temp_dir("probe-jitter");
    let inst = Arc::new(
        Instance::open(Arc::new(Jitter { inner: DbStorage::new(&dir).unwrap() })).unwrap(),
    );
    let owner = TestSender::registered(&inst);
    let (room, _) = inst.create_room(public_shape(), owner.user).unwrap();
    let senders: Vec<_> = (0..8).map(|_| TestSender::registered(&inst)).collect();
    for s in &senders {
        inst.join_room(room, s.user).unwrap();
    }
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let poller = {
        let inst = inst.clone();
        let stop = stop.clone();
        let user = owner.user;
        std::thread::spawn(move || {
            let mut cursor = 0u64;
            let mut seen = std::collections::BTreeSet::new();
            while !stop.load(std::sync::atomic::Ordering::SeqCst) {
                for m in inst.messages_since(room, user, cursor, 0).unwrap() {
                    seen.insert(m.server_seq);
                    cursor = cursor.max(m.server_seq);
                }
            }
            seen
        })
    };
    let users: Vec<UserId> = (0..32).map(|_| UserId::new()).collect();
    let ou = owner.user;
    std::thread::scope(|sc| {
        for s in &senders {
            let inst = inst.clone();
            sc.spawn(move || {
                for i in 0..10 {
                    let e = s.envelope(room, EnvelopePayload::Plaintext { body: format!("{i}") });
                    inst.accept(e, 0).unwrap();
                }
            });
        }
        for u in &users {
            let inst = inst.clone();
            sc.spawn(move || inst.add_room_member(room, ou, *u).unwrap());
        }
    });
    std::thread::sleep(std::time::Duration::from_millis(200));
    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    let seen = poller.join().unwrap();
    println!("PROBE jitter: poller saw {} of 80 by cursor", seen.len());
    drop(senders);
    drop(owner);
    drop(inst);
    let inst = Instance::open(Arc::new(DbStorage::new(&dir).unwrap())).unwrap();
    let r = inst.rooms.lock().unwrap()[&room].clone();
    let stored = inst.storage.messages_since(room, 0).unwrap();
    let max = stored.iter().map(|m| m.server_seq).max().unwrap();
    println!(
        "PROBE jitter after restart: next_seq {} stored {} max {max}; members {} (expected 41)",
        r.next_seq,
        stored.len(),
        r.members.len()
    );
}
