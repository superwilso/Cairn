// A voice channel, through the real SFU, between real Chromium pages.
//
// ## What is real here
//
// Everything below `invoke`. `crates/cairn-server/examples/sfu_harness.rs` runs a real
// instance with the real SFU on a UDP socket, and a real `cairn-client-core` Session per
// person in one real MLS group. Each page's `window.__TAURI__.core.invoke` is forwarded to
// that person's session, so the keys a page seals with are derived from the group by Rust,
// exactly as in the desktop app. The pages run `ui/voicechannel.js`, `ui/mediaframe.js` and
// the transform worker unchanged, with Chromium's fake microphone (a tone).
//
// ## What it proves
//
// 1. Audio flows through the SFU: each listener's received track carries the tone.
// 2. Frames are transformed: the sender sealed, the listener opened — and, from the SFU's own
//    tap, every frame the SFU held was sealed, and opens under the sender's key with the
//    *Rust* implementation into an Opus frame. The SFU held ciphertext, and the two
//    implementations agree.
// 3. Attribution is by key: the listener knows who is on a slot from the key the frames open
//    under, not from the SFU.
// 4. §5's fallback: a participant whose webview cannot transform makes the call
//    transport-only for everyone, everyone is told, the SFU then holds unsealed frames (the
//    counterfactual that shows check 2 can fail) — and leaving returns it to end to end.
// 5. Removal: a member removed from the room is dropped from the voice channel.
//
// Run: node --test clients/desktop/tests/voicechannel.browser.test.js
// Skips, saying so, without Playwright's Chromium or a Rust toolchain — unless
// CAIRN_REQUIRE_BROWSER_TEST=1, as in CI, where a skip is a failure.

const test = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");
const http = require("node:http");
const { spawn, spawnSync } = require("node:child_process");
const readline = require("node:readline");

const ROOT = path.join(__dirname, "../../..");
const UI = path.join(__dirname, "../ui");
const REQUIRED = process.env.CAIRN_REQUIRE_BROWSER_TEST === "1";

function playwright() {
    for (const base of [null, "/opt/node22/lib/node_modules", "/usr/lib/node_modules"]) {
        try { return require(base ? path.join(base, "playwright") : "playwright"); } catch (_) {}
    }
    return null;
}

function findChromium() {
    const root = process.env.PLAYWRIGHT_BROWSERS_PATH || "/opt/pw-browsers";
    if (!fs.existsSync(root)) return null;
    for (const dir of fs.readdirSync(root)) {
        const exe = path.join(root, dir, "chrome-linux", "chrome");
        if (fs.existsSync(exe)) return exe;
    }
    return null;
}

async function launch(pw) {
    const args = ["--use-fake-device-for-media-stream", "--use-fake-ui-for-media-stream",
        "--autoplay-policy=no-user-gesture-required"];
    try { return await pw.chromium.launch({ args }); } catch (first) {
        const executablePath = findChromium();
        if (!executablePath) throw first;
        return await pw.chromium.launch({ args, executablePath });
    }
}

// Build the harness if it is not there. It needs the `test-tap` feature, which no build
// anyone runs has.
function harnessBinary() {
    const target = process.env.CARGO_TARGET_DIR || path.join(ROOT, "target");
    const exe = path.join(target, "debug", "examples", process.platform === "win32" ? "sfu_harness.exe" : "sfu_harness");
    const built = spawnSync("cargo", ["build", "-q", "-p", "cairn-server", "--example", "sfu_harness", "--features", "test-tap"],
        { cwd: ROOT, stdio: "inherit" });
    if (built.error || built.status !== 0) return fs.existsSync(exe) ? exe : null;
    return exe;
}

class Harness {
    constructor(exe) {
        this.proc = spawn(exe, [], { stdio: ["pipe", "pipe", "inherit"] });
        this.waiting = new Map();
        this.next = 1;
        this.ready = new Promise((resolve) => { this.onReady = resolve; });
        readline.createInterface({ input: this.proc.stdout }).on("line", (line) => {
            let msg;
            try { msg = JSON.parse(line); } catch (_) { return; }
            if (msg.ready) return this.onReady(msg.ready);
            const w = this.waiting.get(msg.id);
            if (!w) return;
            this.waiting.delete(msg.id);
            if ("err" in msg) w.reject(new Error(msg.err)); else w.resolve(msg.ok);
        });
    }
    call(req) {
        const id = this.next++;
        return new Promise((resolve, reject) => {
            this.waiting.set(id, { resolve, reject });
            this.proc.stdin.write(JSON.stringify({ id, ...req }) + "\n");
        });
    }
    close() { this.proc.kill(); }
}

// ui/ over http://localhost — a secure context, which getUserMedia and workers need.
function serveUi() {
    const page = `<!doctype html><meta charset="utf-8"><body>
<script src="mediaframe.js"></script><script src="voicechannel.js"></script><script src="callaudio.js"></script></body>`;
    const server = http.createServer((req, res) => {
        const name = decodeURIComponent(req.url.split("?")[0]).replace(/^\/+/, "");
        if (name === "" || name === "harness.html") {
            res.writeHead(200, { "content-type": "text/html" }); return res.end(page);
        }
        const file = path.join(UI, path.normalize(name));
        if (!file.startsWith(UI) || !fs.existsSync(file)) { res.writeHead(404); return res.end(); }
        res.writeHead(200, { "content-type": "text/javascript" });
        res.end(fs.readFileSync(file));
    });
    return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(server)));
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function until(what, fn, ms = 15000) {
    const end = Date.now() + ms;
    let last;
    while (Date.now() < end) {
        last = await fn();
        if (last) return last;
        await sleep(250);
    }
    throw new Error("timed out waiting for " + what + " (last: " + JSON.stringify(last) + ")");
}

async function openPage(browser, base, harness, name, notes) {
    const ctx = await browser.newContext({ permissions: ["microphone"] });
    const page = await ctx.newPage();
    page.on("pageerror", (e) => console.error(name + " page error:", e.message));
    await page.exposeFunction("harnessInvoke", (cmd, args) =>
        harness.call({ op: "invoke", as: name, cmd, args: args || {} }));
    await page.exposeFunction("harnessNote", (kind, text) => notes.push({ who: name, kind, text }));
    await page.addInitScript(() => {
        window.__TAURI__ = { core: { invoke: (cmd, args) => window.harnessInvoke(cmd, args) } };
    });
    await page.goto(base + "/harness.html");
    await page.evaluate(() => {
        CairnVoiceChannel.bind({
            onProtection: (a, b, by) => window.harnessNote("protection", a + "->" + b + ":" + by.join(",")),
            onNotice: (t) => window.harnessNote("notice", t),
        });
    });
    return page;
}

// RMS of what a listener actually receives on any slot, measured from the decoded track.
async function loudestSlot(page) {
    return page.evaluate(async () => {
        const ctx = new AudioContext();
        let best = 0;
        for (const el of CairnVoiceChannel.audio.values()) {
            if (!el.srcObject) continue;
            const src = ctx.createMediaStreamSource(el.srcObject);
            const an = ctx.createAnalyser();
            an.fftSize = 2048;
            src.connect(an);
            const buf = new Float32Array(an.fftSize);
            for (let i = 0; i < 20; i++) {
                await new Promise((r) => setTimeout(r, 50));
                an.getFloatTimeDomainData(buf);
                best = Math.max(best, Math.sqrt(buf.reduce((s, v) => s + v * v, 0) / buf.length));
            }
        }
        await ctx.close();
        return best;
    });
}

test("a voice channel carries sealed audio through the SFU", { timeout: 180_000 }, async (t) => {
    const pw = playwright();
    if (!pw) {
        if (REQUIRED) throw new Error("Playwright is required here and missing");
        return t.skip("Playwright is not installed");
    }
    const exe = harnessBinary();
    if (!exe) {
        if (REQUIRED) throw new Error("could not build the SFU harness");
        return t.skip("no Rust toolchain to build the SFU harness");
    }

    const harness = new Harness(exe);
    const server = await serveUi();
    const base = "http://localhost:" + server.address().port;
    const browser = await launch(pw);
    const notes = [];
    let polling = true;
    try {
        await harness.ready;
        const { users } = await harness.call({ op: "setup", names: ["alice", "bob", "carol"] });
        const alice = await openPage(browser, base, harness, "alice", notes);
        const bob = await openPage(browser, base, harness, "bob", notes);

        // The desktop app polls the open room; announcements arrive that way.
        const poller = (async () => {
            while (polling) {
                for (const n of ["alice", "bob", "carol"]) {
                    await harness.call({ op: "invoke", as: n, cmd: "poll" }).catch(() => {});
                }
                await sleep(300);
            }
        })();

        const aj = await alice.evaluate(() => CairnVoiceChannel.join());
        assert.strictEqual(aj.path, "script", "Chromium should use RTCRtpScriptTransform");
        await bob.evaluate(() => CairnVoiceChannel.join());

        await until("both connected", async () => {
            const s = await Promise.all([alice, bob].map((p) => p.evaluate(() => CairnVoiceChannel.pc && CairnVoiceChannel.pc.connectionState)));
            return s.every((x) => x === "connected") && s;
        });
        const state = await bob.evaluate(() => CairnVoiceChannel.refresh().then(() => CairnVoiceChannel.state));
        assert.strictEqual(state.protection, "e2ee");
        assert.strictEqual(state.participants.length, 2);
        assert.ok(state.participants.every((p) => p.in_group), "both are leaves of the room's group");

        // 1. Audio flows: bob hears alice's tone, alice hears bob's.
        await harness.call({ op: "tap_clear" });
        const heardByBob = await until("bob hears alice", async () => { const r = await loudestSlot(bob); return r > 0.01 && r; });
        const heardByAlice = await until("alice hears bob", async () => { const r = await loudestSlot(alice); return r > 0.01 && r; });
        console.log("received RMS: bob", heardByBob.toFixed(3), "alice", heardByAlice.toFixed(3));

        // 2. Transformed: sealed on one side, opened on the other, sealed at the SFU.
        const aStats = await alice.evaluate(() => CairnVoiceChannel.readStats());
        const bStats = await bob.evaluate(() => CairnVoiceChannel.readStats());
        console.log("alice", aStats, "bob", bStats);
        assert.ok(aStats.sealed > 20 && bStats.sealed > 20, "both senders sealed frames");
        assert.ok(aStats.opened > 20 && bStats.opened > 20, "both listeners opened frames");
        assert.strictEqual(aStats.passed + bStats.passed, 0, "nothing passed through unsealed");
        const tap = await harness.call({ op: "tap" });
        console.log("what the SFU held:", JSON.stringify(tap));
        for (const who of ["alice", "bob"]) {
            const r = tap[who];
            assert.ok(r && r.frames > 20, who + "'s frames reached the SFU");
            assert.strictEqual(r.sealed, r.frames, "every frame the SFU held from " + who + " was sealed");
            assert.strictEqual(r.opened, r.frames, "every one opens under " + who + "'s key, in Rust");
            assert.strictEqual(r.leaf_matches, r.frames, "and names " + who + "'s own leaf");
            // An Opus TOC byte: config in the top five bits. 0 would be suspicious; any CELT/
            // SILK/hybrid config is fine. What matters is that it decoded *to audio*.
            assert.ok(r.toc !== null, "the opened plaintext is a codec frame");
        }

        // 3. Attribution by key, not by the SFU.
        const owner = await bob.evaluate(() => {
            for (const i of CairnVoiceChannel.audio.keys()) { const o = CairnVoiceChannel.slotOwner(i); if (o) return o; }
            return null;
        });
        assert.ok(owner && owner.attested, "the slot is attributed by the key its frames open under");
        assert.strictEqual(owner.user, users.alice);

        // 3b. A soundboard clip goes out on its own track: sealed like the voice, marked as a
        // clip inside the seal, attributed by key — and a listener's per-person mute silences
        // that slot while the speaker's voice slot plays on.
        await harness.call({ op: "tap_clear" });
        await alice.evaluate(async () => {
            const rate = 48000;
            const buf = new AudioBuffer({ length: rate * 2, sampleRate: rate, numberOfChannels: 1 });
            const d = buf.getChannelData(0);
            for (let i = 0; i < d.length; i++) d[i] = 0.8 * Math.sin((2 * Math.PI * 2600 * i) / rate);
            await CairnVoiceChannel.playClip(buf);
        });
        const slots = await until("bob finds alice's voice and soundboard slots", async () => {
            const found = await bob.evaluate(() => {
                const out = {};
                for (const i of CairnVoiceChannel.audio.keys()) {
                    const o = CairnVoiceChannel.slotOwner(i);
                    if (o) out[o.track] = { index: i, ...o };
                }
                return out;
            });
            return found.board && found.voice && found;
        });
        assert.strictEqual(slots.board.user, users.alice);
        assert.ok(slots.board.attested, "the soundboard slot is known by the key and the sealed flag");
        assert.notStrictEqual(slots.board.index, slots.voice.index);
        await sleep(1500);
        const boardTap = await harness.call({ op: "tap" });
        const ab = boardTap["alice:board"];
        console.log("alice's soundboard at the SFU:", JSON.stringify(ab));
        assert.ok(ab && ab.frames > 10, "alice's clip crossed the SFU on her soundboard track");
        assert.strictEqual(ab.sealed, ab.frames, "every soundboard frame the SFU held was sealed");
        assert.strictEqual(ab.opened, ab.frames, "and opens under alice's key, in Rust");
        assert.strictEqual(ab.board_flag, ab.opened, "and is marked as a clip inside the seal");
        assert.ok(boardTap.alice && boardTap.alice.board_flag === 0, "her voice frames are not marked as clips");
        const levels = await bob.evaluate(([b, v, who]) => {
            CairnCallAudio.setBoardMuted(who, true);
            const el = (i) => CairnVoiceChannel.audio.get(i);
            return { board: el(b).muted, voice: el(v).muted };
        }, [slots.board.index, slots.voice.index, users.alice]);
        assert.deepStrictEqual(levels, { board: true, voice: false },
            "muting alice's soundboard silences her clip slot and leaves her voice playing");
        await bob.evaluate((who) => CairnCallAudio.setBoardMuted(who, false), users.alice);

        // 4. The §5 fallback. Carol's webview "cannot transform".
        const carol = await openPage(browser, base, harness, "carol", notes);
        const cj = await carol.evaluate(() => CairnVoiceChannel.join({ simulateNoTransforms: true }));
        assert.strictEqual(cj.path, "none");
        await until("everyone sees the fallback", async () => {
            const ps = await Promise.all([alice, bob, carol].map((p) => p.evaluate(() => CairnVoiceChannel.refresh().then(() => CairnVoiceChannel.state && CairnVoiceChannel.state.protection))));
            return ps.every((p) => p === "transport_only") && ps;
        }, 20000);
        const told = notes.filter((n) => n.kind === "protection" && n.text.startsWith("e2ee->transport_only"));
        assert.ok(told.some((n) => n.who === "alice") && told.some((n) => n.who === "bob"),
            "the fallback is announced to everyone already in the call: " + JSON.stringify(notes));
        assert.ok(told.every((n) => n.text.endsWith(users.carol)), "naming who caused it");
        const fb = await bob.evaluate(() => CairnVoiceChannel.state.fallback_by);
        assert.deepStrictEqual(fb, [users.carol]);

        await sleep(1500);
        await harness.call({ op: "tap_clear" });
        await until("carol hears alice in the clear", async () => { const r = await loudestSlot(carol); return r > 0.01 && r; });
        const plainTap = await harness.call({ op: "tap" });
        console.log("what the SFU held during the fallback:", JSON.stringify(plainTap));
        assert.ok(plainTap.alice.frames > 10);
        assert.strictEqual(plainTap.alice.sealed, 0, "in a transport-only call the SFU holds unsealed frames — and the test can see it");

        await carol.evaluate(() => CairnVoiceChannel.leave());
        await until("back to end to end", async () => {
            const ps = await Promise.all([alice, bob].map((p) => p.evaluate(() => CairnVoiceChannel.refresh().then(() => CairnVoiceChannel.state.protection))));
            return ps.every((p) => p === "e2ee") && ps;
        }, 20000);
        assert.ok(notes.some((n) => n.who === "bob" && n.text.startsWith("transport_only->e2ee")), "the return is announced too");
        await sleep(1500);
        await harness.call({ op: "tap_clear" });
        await sleep(1500);
        const back = await harness.call({ op: "tap" });
        assert.strictEqual(back.alice.sealed, back.alice.frames, "sealed again once the fallback participant left");

        // 5. Removal. Alice (owner) removes bob from the room.
        await harness.call({ op: "remove", as: "alice", target: "bob" });
        await until("bob is dropped", async () => {
            const gone = await bob.evaluate(() => CairnVoiceChannel.session === null);
            const roster = await alice.evaluate(() => CairnVoiceChannel.refresh().then(() => CairnVoiceChannel.state.participants.map((p) => p.user)));
            return gone && !roster.includes(users.bob) && roster;
        }, 20000);

        if (process.env.CAIRN_SHOTS_DIR) {
            fs.mkdirSync(process.env.CAIRN_SHOTS_DIR, { recursive: true });
        }
        polling = false;
        await poller;
    } finally {
        polling = false;
        await browser.close();
        server.close();
        harness.close();
    }
});
