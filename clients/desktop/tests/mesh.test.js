// The WebRTC mesh, tested without a browser.
//
// ## Why this exists
//
// `crates/cairn-server/tests/group_chat_session.rs` proves the *transport*: a signal reaches
// the peer it was addressed to, reaches nobody else, and the instance never sees the SDP.
// None of that touches the part that actually decides whether a call connects — who offers,
// whether an early ICE candidate survives, whether turning a camera on renegotiates. That
// logic is in `ui/call.js` and had no test at all.
//
// The failures it defends against are all ones that look like a network fault rather than a
// bug: glare connects the call for one person, a dropped candidate negotiates and then never
// connects, an ack loop floods the room. Every one would be blamed on somebody's broadband.
//
// Run: node --test clients/desktop/tests/
//
// No dependencies. Node's own test runner and `vm`, which is what lets two independent
// copies of call.js run in one process — it is an IIFE bound to a const, so two clients need
// two contexts rather than two imports.

const test = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const CALL_JS = fs.readFileSync(path.join(__dirname, "../ui/call.js"), "utf8");

// ---- fakes -----------------------------------------------------------------

function track(kind) {
    return {
        kind,
        enabled: true,
        muted: false,
        readyState: "live",
        stop() { this.readyState = "ended"; },
    };
}

class FakeMediaStream {
    constructor(tracks = []) { this.tracks = tracks; }
    getTracks() { return [...this.tracks]; }
    getAudioTracks() { return this.tracks.filter((t) => t.kind === "audio"); }
    getVideoTracks() { return this.tracks.filter((t) => t.kind === "video"); }
    addTrack(t) { this.tracks.push(t); }
    removeTrack(t) { this.tracks = this.tracks.filter((x) => x !== t); }
}

// Records what call.js asked of it. Deliberately does no negotiation of its own: the point
// is to observe the decisions, not to simulate ICE. Every instance registers itself in
// `built`, which is how a test reaches connections that call.js quite rightly keeps private.
function peerConnectionClass(stats, built) {
    return class FakeRTCPeerConnection {
        constructor(config) {
            this.config = config;
            built.push(this);
            this.senders = [];
            this.transceivers = [];
            this.localDescription = null;
            this.remoteDescription = null;
            this.candidates = [];
            this.connectionState = "new";
            stats.connections++;
        }
        #sender(t) {
            const s = { track: t, replaceTrack: async (x) => { s.track = x; } };
            this.senders.push(s);
            return s;
        }
        addTrack(t) {
            const tx = { sender: this.#sender(t), receiver: { track: null }, direction: "sendrecv" };
            this.transceivers.push(tx);
            return tx.sender;
        }
        addTransceiver(trackOrKind) {
            const track = typeof trackOrKind === "string" ? null : trackOrKind;
            const tx = { sender: this.#sender(track), receiver: { track: null }, direction: "sendrecv" };
            this.transceivers.push(tx);
            return tx;
        }
        getSenders() { return this.senders; }
        getTransceivers() { return this.transceivers; }
        async createOffer() { stats.offers++; return { type: "offer", sdp: "fake-offer" }; }
        async createAnswer() { stats.answers++; return { type: "answer", sdp: "fake-answer" }; }
        async setLocalDescription(d) {
            this.localDescription = d;
            // A real connection begins gathering here, and `onicecandidate` fires before the
            // description it belongs to has finished being sent. Reproducing that ordering
            // is the only way to test the buffering honestly — injecting a synthetic
            // out-of-order candidate would prove the buffer works on a case that cannot
            // happen.
            if (this.onicecandidate) {
                this.onicecandidate({ candidate: { candidate: "candidate:" + d.type } });
            }
        }
        async setRemoteDescription(d) {
            this.remoteDescription = d;
            // Applying a remote offer creates a transceiver for every m-line it could not
            // match to an existing one — and it will not match one made by `addTransceiver`.
            // Modelling that is the point: without it this fake would happily let the
            // answering side pre-create a video line, which is exactly the bug two real
            // browsers found.
            if (d.type === "offer" && !this.transceivers.some((t) => t.receiver.track)) {
                this.transceivers.push({
                    sender: this.#sender(null),
                    receiver: { track: { kind: "video" } },
                    direction: "recvonly",
                });
            }
        }
        async addIceCandidate(c) {
            // The real API throws here, which is exactly the failure call.js buffers around.
            if (!this.remoteDescription) throw new Error("remote description not set");
            this.candidates.push(c);
        }
        close() { this.closed = true; }
    };
}

// A room of clients that hands signals to each other the way `Session::poll` does: every
// participant receives every signal, minus the ones addressed to somebody else.
class Room {
    constructor() {
        this.clients = new Map();   // user -> CairnCall
        this.states = new Map();    // user -> { call, negotiated }, mirroring Session
        this.queue = [];
        this.sent = [];
    }

    invoke(from, cmd, args) {
        if (cmd === "call_config") {
            return Promise.resolve({ ice_servers: [], has_relay: false, max_participants: 6 });
        }
        // Faithful to Session::call_join, which mints the id *and* broadcasts the arrival.
        //
        // Two things here were wrong in earlier versions of this harness, and both hid a
        // real defect. Modelling call_join as a bare id meant no announcement, so the offer
        // rule never fired. Handing every client the *same* id modelled the intent rather
        // than the code: each participant really does mint its own, which is why
        // `Session::reconcile` exists. The harness mints per-participant and reconciles,
        // exactly as Rust does.
        if (cmd === "call_join") {
            const client = this.state(from);
            client.call = client.call || this.mint(from);
            this.queueSignal(from, { call: client.call, kind: "join", payload: "" });
            return Promise.resolve(client.call);
        }
        if (cmd === "call_leave") {
            const client = this.state(from);
            if (client.call) {
                this.queueSignal(from, { call: client.call, kind: "leave", payload: "" });
                client.call = null;
                client.negotiated = false;
            }
            return Promise.resolve();
        }
        if (cmd === "signal") {
            const client = this.state(from);
            // Session::signal stamps the current id over whatever the frontend sent.
            const s = { ...args.signal, call: client.call || args.signal.call };
            if (s.kind === "offer" || s.kind === "answer") client.negotiated = true;
            this.queueSignal(from, s);
            return Promise.resolve();
        }
        throw new Error("unexpected command " + cmd);
    }

    state(user) {
        if (!this.states.has(user)) this.states.set(user, { call: null, negotiated: false });
        return this.states.get(user);
    }

    mint(user) {
        // Real ids are uuids, so which participant gets the smaller one is arbitrary. The
        // test needs it to be arbitrary in a controlled way: "call-from-usr_b" sorts after
        // "call-from-usr_a", so the peer that would *not* win the offer tie-break is the one
        // holding the smaller call id. If reconciliation only worked when the same side won
        // both, this ordering would catch it.
        return "call-from-" + user;
    }

    queueSignal(from, signal) {
        this.sent.push({ from, ...signal });
        for (const [user] of this.clients) {
            if (user === from) continue;              // own signals never come back
            if (signal.to && signal.to !== user) continue;  // the Rust-side address filter
            this.queue.push({ to: user, from, signal });
        }
    }

    // Session::reconcile, ported. Returns the signal as the frontend would see it, or null
    // when it belongs to a call this participant is not in.
    reconcile(user, signal) {
        const client = this.state(user);
        if (!client.call) return null;
        if (signal.call !== client.call && signal.kind === "join" && !client.negotiated) {
            if (signal.to || signal.call < client.call) client.call = signal.call;
        }
        if (signal.call !== client.call && signal.kind !== "join") return null;
        if (signal.kind === "offer" || signal.kind === "answer") client.negotiated = true;
        return { ...signal, call: client.call };
    }

    // Drains until quiet. Signals produce signals, so this loops rather than iterating once.
    async settle(limit = 200) {
        let steps = 0;
        while (this.queue.length) {
            if (++steps > limit) throw new Error("signalling did not settle — a loop?");
            const { to, from, signal } = this.queue.shift();
            const reconciled = this.reconcile(to, signal);
            if (reconciled) await this.clients.get(to).handle(from, reconciled);
        }
        return steps;
    }
}

function client(user, room, stats, built) {
    const context = {
        console,
        JSON,
        Promise,
        Error,
        Map,
        MediaStream: FakeMediaStream,
        RTCPeerConnection: peerConnectionClass(stats, built),
        HTMLMediaElement: function () {},
        navigator: {
            mediaDevices: {
                getUserMedia: async ({ audio, video }) =>
                    new FakeMediaStream([
                        ...(audio ? [track("audio")] : []),
                        ...(video ? [track("video")] : []),
                    ]),
                getDisplayMedia: async () => new FakeMediaStream([track("video")]),
                enumerateDevices: async () => [],
            },
        },
        window: { __TAURI__: { core: { invoke: (cmd, args) => room.invoke(user, cmd, args) } } },
    };
    vm.createContext(context);
    // `const CairnCall = ...` is a lexical declaration, so it never lands on the context
    // object. The trailing expression makes it the script's completion value instead.
    const call = vm.runInContext(CALL_JS + "\n;CairnCall", context);
    room.clients.set(user, call);
    return call;
}

function group(users) {
    const room = new Room();
    const stats = { offers: 0, answers: 0, connections: 0 };
    const built = Object.fromEntries(users.map((u) => [u, []]));
    const calls = users.map((u) => client(u, room, stats, built[u]));
    const senders = (user) => built[user].flatMap((pc) => pc.getSenders());
    return { room, stats, calls, built, senders };
}

function pair() {
    const room = new Room();
    const stats = { offers: 0, answers: 0, connections: 0 };
    // Ids chosen so "usr_a" < "usr_b" lexicographically, which is the whole offer rule.
    const built = { usr_a: [], usr_b: [] };
    const a = client("usr_a", room, stats, built.usr_a);
    const b = client("usr_b", room, stats, built.usr_b);

    const senders = (user) => built[user].flatMap((pc) => pc.getSenders());
    const candidates = (user) => built[user].flatMap((pc) => pc.candidates);
    return { room, stats, a, b, senders, candidates, built };
}

// ---- tests -----------------------------------------------------------------

test("exactly one side of a pair sends the offer", async () => {
    // Glare. Both peers offering produces two half-negotiated connections, and it presents
    // as "the call works for one of us" — the single most confusing way a call can fail.
    const { room, stats, a, b } = pair();
    await a.join({ video: false, myUser: "usr_a" });
    await b.join({ video: false, myUser: "usr_b" });
    await room.settle();

    assert.strictEqual(stats.offers, 1, "one offer between two peers, not two and not none");
    assert.strictEqual(stats.answers, 1, "and it must have been answered");
});

test("the offer still comes from one side when both join at once", async () => {
    // The case the rule exists for. If ordering decided who offers, a simultaneous join
    // would produce two offers and the test above would pass anyway.
    const { room, stats, a, b } = pair();
    await a.join({ video: false, myUser: "usr_a" });
    await b.join({ video: false, myUser: "usr_b" });
    // Deliver in the opposite order to the one the previous test happened to produce.
    room.queue.reverse();
    await room.settle();

    assert.strictEqual(stats.offers, 1);
});

test("the join acknowledgement does not loop", async () => {
    // Every participant answers a broadcast join with an addressed one, so the newcomer
    // learns the roster. If an addressed join were answered in turn, a call would flood the
    // room with signalling until it fell over.
    const { room, a, b } = pair();
    await a.join({ video: false, myUser: "usr_a" });
    await b.join({ video: false, myUser: "usr_b" });
    await room.settle();

    const joins = room.sent.filter((s) => s.kind === "join");
    const broadcasts = joins.filter((j) => !j.to);
    const acks = joins.filter((j) => j.to);
    assert.strictEqual(broadcasts.length, 2, "one arrival announcement each");
    assert.strictEqual(
        acks.length, 2,
        "one acknowledgement each and no more — an ack answering an ack would not stop: " +
            JSON.stringify(joins)
    );
});

test("an ice candidate that arrives before the offer is not lost", async () => {
    // Candidates overtake the description they belong to as a matter of course: gathering
    // starts inside setLocalDescription, so a candidate is on the wire before the offer
    // finishes being sent. addIceCandidate throws in that state, and a swallowed throw is a
    // call that negotiates and then never connects.
    const { room, a, b, candidates } = pair();
    await a.join({ video: false, myUser: "usr_a" });
    await b.join({ video: false, myUser: "usr_b" });
    await room.settle();

    const order = room.sent.map((s) => s.kind);
    assert.ok(
        order.indexOf("ice") < order.indexOf("offer"),
        "the scenario only means something if the candidate really did go first: " + order
    );
    assert.deepStrictEqual(
        candidates("usr_b").map((c) => c.candidate), ["candidate:offer"],
        "the early candidate must be replayed once the description lands"
    );
});

test("a signal from a call that already ended is ignored", async () => {
    // A hang-up and redial must not leave a peer negotiating with the previous call.
    const { room, stats, a, b } = pair();
    await a.join({ video: false, myUser: "usr_a" });
    await b.join({ video: false, myUser: "usr_b" });
    await room.settle();
    const before = stats.offers;

    await b.handle("usr_a", {
        call: "some-older-call",
        kind: "join",
        payload: "",
    });
    await room.settle();

    assert.strictEqual(stats.offers, before, "a stale call id must not start a negotiation");
});

test("turning a camera on during a voice call does not renegotiate", async () => {
    // The reason every connection is built with an empty video transceiver. Without it,
    // addTrack on a live connection needs a fresh offer — and a fresh offer in a mesh is
    // where glare comes back.
    const { room, stats, a, b, senders } = pair();
    await a.join({ video: false, myUser: "usr_a" });
    await b.join({ video: false, myUser: "usr_b" });
    await room.settle();

    const offersBefore = stats.offers;
    const stream = await a.setCameraOn(true);
    await room.settle();

    assert.strictEqual(stats.offers, offersBefore, "no new offer was needed");
    assert.strictEqual(stream.getVideoTracks().length, 1, "the camera is capturing");
    assert.ok(
        senders("usr_a").some((s) => s.track && s.track.kind === "video"),
        "and the track was put into the already-negotiated video line"
    );
});

test("a voice call still negotiates a video line", async () => {
    // Counterfactual for the camera test: if a voice call negotiated audio only, the camera
    // switch would have nowhere to put its track and would silently do nothing.
    const { room, a, b, senders } = pair();
    await a.join({ video: false, myUser: "usr_a" });
    await b.join({ video: false, myUser: "usr_b" });
    await room.settle();

    assert.strictEqual(senders("usr_a").length, 2, "one audio sender and one empty video sender");
});

test("the answering side does not pre-create the video line", async () => {
    // Two real browsers found this and no amount of reading did. `addTransceiver` produces a
    // transceiver that a remote offer will not reuse, so pre-creating one on the answering
    // side strands it and leaves the offer's video m-line to a third, receive-only
    // transceiver. The call still reports "connected"; video simply never goes back.
    const { room, a, b, built } = pair();
    await a.join({ video: true, myUser: "usr_a" });
    await b.join({ video: true, myUser: "usr_b" });
    await room.settle();

    // usr_b is the answering side, because "usr_a" sorts first and therefore offers.
    const answering = built.usr_b.flatMap((pc) => pc.getTransceivers());
    const video = answering.filter((t) => t.receiver.track || (t.sender.track && t.sender.track.kind === "video"));
    assert.strictEqual(
        video.length, 1,
        "exactly one video line on the answering side, the one the offer created"
    );
    assert.strictEqual(video[0].direction, "sendrecv", "and it must be claimed for sending too");
    assert.ok(video[0].sender.track, "with our own camera track put into it");
});

test("a call refuses the person who would exceed the mesh ceiling", async () => {
    // Not "how many people are in this room" — a group chat of eight can hold a call
    // between two of them, and an earlier version refused exactly that, naming the room's
    // size as the reason. The ceiling is about peer connections, because that is what runs
    // out of upstream, so it is checked where the count is real.
    const users = ["usr_1", "usr_2", "usr_3", "usr_4", "usr_5", "usr_6", "usr_7"];
    const { room, calls } = group(users);

    const notices = [];
    calls[0].bind({ onNotice: (t) => notices.push(t) });

    for (let i = 0; i < users.length; i++) {
        await calls[i].join({ video: false, myUser: users[i] });
        await room.settle();
    }

    // Six people means five peers each. The seventh is refused, and told so.
    assert.strictEqual(calls[0].peerCount, 5, "five peers, which is a call of six");
    assert.ok(
        notices.some((t) => t.includes("full at 6")),
        "and the refusal is said out loud rather than looking like a dropped call: " +
            JSON.stringify(notices)
    );
});

test("a small call in a large room is not refused", async () => {
    // The counterfactual, and the bug that was actually there: the ceiling used to count the
    // room's members, so two people in a group of eight could not call each other at all.
    const { room, calls } = group(["usr_1", "usr_2"]);
    await calls[0].join({ video: false, myUser: "usr_1" });
    await calls[1].join({ video: false, myUser: "usr_2" });
    await room.settle();

    assert.strictEqual(calls[0].peerCount, 1, "two people in a call, connected");
});

test("leaving tells the peer, who tears the connection down", async () => {
    // Without the announcement a peer waits for an ICE timeout, so a participant who hung up
    // stays on screen as a frozen tile for the better part of a minute.
    const { room, a, b } = pair();
    await a.join({ video: false, myUser: "usr_a" });
    await b.join({ video: false, myUser: "usr_b" });
    await room.settle();

    let dropped = null;
    b.bind({ onPeer: (user, stream) => { if (!stream) dropped = user; } });
    await a.leave();
    await room.settle();

    assert.strictEqual(dropped, "usr_a", "bob must be told alice left");
});
