// The soundboard, tested between two real browsers: a clip played by one participant is
// heard by the other **on its own track**, so the listener can silence it — per person, or
// everyone's — while the speaker's voice keeps flowing. And playing it sends no signal.
//
// Runs `ui/call.js` and `ui/callaudio.js` unchanged in two Chromium pages with fake media
// devices, wired together by a relay that stands in for Rust (the same shape as
// call.browser.test.js). Alice plays a pure tone with `CairnCall.playClip`. Bob measures two
// things: what his device actually plays for Alice's soundboard (callaudio.js's output for
// that track, after his settings), and the voice track he receives from her. The owner's
// requirement this pins: muting one person's soundboard silences the clip, not the person.
//
// The signal count is checked across each play: a "play X" announcement would cross the
// instance with a timestamp. (The separate track has a cost of its own — a relay or SFU sees
// when it carries audio — which docs/13-customisation.md states.)
//
// Run: node --test clients/desktop/tests/soundboard.browser.test.js

const test = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");

const CALL_JS = fs.readFileSync(path.join(__dirname, "../ui/call.js"), "utf8");
const CALLAUDIO_JS = fs.readFileSync(path.join(__dirname, "../ui/callaudio.js"), "utf8");
const TONE_HZ = 2600;

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
    const args = [
        "--use-fake-device-for-media-stream",
        "--use-fake-ui-for-media-stream",
        // An AudioContext created without a gesture starts suspended otherwise, and the
        // measurement on the receiving side would read silence for the wrong reason.
        "--autoplay-policy=no-user-gesture-required",
    ];
    try {
        return await pw.chromium.launch({ args });
    } catch (first) {
        const executablePath = findChromium();
        if (!executablePath) throw first;
        return await pw.chromium.launch({ args, executablePath });
    }
}

function playwright() {
    for (const base of [null, "/opt/node22/lib/node_modules", "/usr/lib/node_modules"]) {
        try {
            return require(base ? path.join(base, "playwright") : "playwright");
        } catch (_) { /* try the next */ }
    }
    return null;
}

// A two-party relay: one call id, signals queued per recipient and delivered one at a time.
class Relay {
    constructor() { this.pages = new Map(); this.queues = new Map(); this.busy = new Set(); this.sent = 0; }
    async invoke(user, cmd, args) {
        if (cmd === "call_config") return { ice_servers: [], has_relay: false, max_participants: 6 };
        if (cmd === "call_join") { this.fanout(user, { call: "c1", kind: "join", payload: "" }); return "c1"; }
        if (cmd === "call_leave") return null;
        if (cmd === "signal") { this.sent += 1; this.fanout(user, { ...args.signal, call: "c1" }); return null; }
        throw new Error("unexpected command " + cmd);
    }
    fanout(from, signal) {
        for (const [user] of this.pages) {
            if (user === from || (signal.to && signal.to !== user)) continue;
            if (!this.queues.has(user)) this.queues.set(user, []);
            this.queues.get(user).push({ from, signal });
            this.pump(user);
        }
    }
    async pump(user) {
        if (this.busy.has(user)) return;
        this.busy.add(user);
        try {
            const q = this.queues.get(user);
            while (q && q.length) {
                const { from, signal } = q.shift();
                await this.pages.get(user)
                    .evaluate(([f, s]) => window.CairnCall.handle(f, s), [from, signal])
                    .catch((e) => console.error(user + " handle failed:", e.message));
            }
        } finally { this.busy.delete(user); }
    }
}

async function openClient(browser, relay, user) {
    const page = await browser.newPage();
    page.on("pageerror", (e) => console.error(user + " page error:", e.message));
    await page.exposeFunction("__relay", (cmd, args) => relay.invoke(user, cmd, args));
    await page.addInitScript(`
        window.__TAURI__ = { core: { invoke: (cmd, args) => window.__relay(cmd, args) } };
        window.__seen = { states: [], remote: null };
        // Kept so the test can read WebRTC's own packet counts; call.js is otherwise untouched.
        window.__pcs = [];
        const Native = window.RTCPeerConnection;
        window.RTCPeerConnection = class extends Native {
            constructor(...a) { super(...a); window.__pcs.push(this); }
        };
    `);
    await page.route("http://localhost/cairn", (route) =>
        route.fulfill({ contentType: "text/html", body: "<!doctype html><title>cairn</title>" }));
    await page.goto("http://localhost/cairn");
    await page.addScriptTag({ content: CALL_JS + "\n;window.CairnCall = CairnCall;" });
    await page.addScriptTag({ content: CALLAUDIO_JS + "\n;window.CairnCallAudio = CairnCallAudio;" });
    await page.evaluate(() => {
        window.CairnCall.bind({
            onPeer: (u, s) => { if (s) window.__seen.remote = s; },
            // As callui.js wires it: a peer's soundboard track goes to callaudio.js.
            onBoard: (u, s) => { if (s) window.CairnCallAudio.attachBoard(u, s); else window.CairnCallAudio.detachBoard(u); },
            onState: (u, st) => window.__seen.states.push(st),
            onNotice: () => {},
        });
    });
    relay.pages.set(user, page);
    return page;
}

// In the receiving page: the loudest level, in dB, near `hz` over `ms`, of either the voice
// track received from the peer ("voice") or what this device plays for the peer's soundboard
// after its own settings ("board", callaudio.js's output for that track).
async function loudestNear(page, which, hz, ms) {
    return page.evaluate(async ([which, hz, ms]) => {
        window.__meters = window.__meters || {};
        if (!window.__meters[which]) {
            const stream = which === "voice"
                ? window.__seen.remote
                : window.CairnCallAudio.boardOutput("usr_a");
            if (!stream) throw new Error("no " + which + " stream to measure");
            // Chromium only feeds a remote WebRTC stream to WebAudio while a media element
            // is also consuming it.
            if (which === "voice") {
                const el = document.createElement("audio");
                el.muted = true;
                el.srcObject = stream;
                document.body.append(el);
                await el.play().catch(() => {});
            }
            const ctx = new AudioContext();
            const analyser = ctx.createAnalyser();
            analyser.fftSize = 4096;
            analyser.smoothingTimeConstant = 0;
            ctx.createMediaStreamSource(stream).connect(analyser);
            window.__meters[which] = { ctx, analyser };
        }
        const { ctx, analyser } = window.__meters[which];
        const bins = new Float32Array(analyser.frequencyBinCount);
        const at = Math.round(hz / (ctx.sampleRate / analyser.fftSize));
        let loudest = -Infinity;
        const end = performance.now() + ms;
        while (performance.now() < end) {
            analyser.getFloatFrequencyData(bins);
            for (let i = at - 3; i <= at + 3; i++) loudest = Math.max(loudest, bins[i]);
            await new Promise((r) => setTimeout(r, 30));
        }
        return loudest;
    }, [which, hz, ms]);
}

// Audio packets received on the peer's voice track so far, from WebRTC's own statistics.
async function voicePackets(page) {
    return page.evaluate(async () => {
        const track = window.__seen.remote && window.__seen.remote.getAudioTracks()[0];
        if (!track) return 0;
        let n = 0;
        for (const pc of window.__pcs || []) {
            const report = await pc.getStats(track).catch(() => null);
            if (report) report.forEach((r) => { if (r.type === "inbound-rtp") n += r.packetsReceived; });
        }
        return n;
    });
}

async function playTone(page, hz) {
    await page.evaluate(async (hz) => {
        const rate = 48000;
        const buffer = new AudioBuffer({ length: rate * 3, sampleRate: rate, numberOfChannels: 1 });
        const data = buffer.getChannelData(0);
        for (let i = 0; i < data.length; i++) data[i] = 0.8 * Math.sin((2 * Math.PI * hz * i) / rate);
        await window.CairnCall.playClip(buffer);
    }, hz);
}

const pw = playwright();
const REQUIRED = process.env.CAIRN_REQUIRE_BROWSER_TEST === "1";
if (!pw && REQUIRED) throw new Error("CAIRN_REQUIRE_BROWSER_TEST=1 but playwright is not installed");

test("a soundboard clip is heard by the other participant, and sends no signal", {
    skip: pw ? false : "playwright is not installed",
}, async (t) => {
    let browser;
    try {
        browser = await launch(pw);
    } catch (e) {
        if (REQUIRED) throw e;
        return t.skip("no Chromium for Playwright: " + e.message);
    }
    try {
        const relay = new Relay();
        const a = await openClient(browser, relay, "usr_a");
        const b = await openClient(browser, relay, "usr_b");
        await a.evaluate(() => window.CairnCall.join({ video: false, myUser: "usr_a" }));
        await b.evaluate(() => window.CairnCall.join({ video: false, myUser: "usr_b" }));
        for (const page of [a, b]) {
            await page.waitForFunction(() => window.__seen.states.includes("connected"), null, { timeout: 20000 });
        }
        await b.waitForFunction(() => window.__seen.remote && window.__seen.remote.getAudioTracks().length > 0,
            null, { timeout: 15000 });

        await b.waitForFunction(() => window.CairnCallAudio.boardOutput("usr_a") !== null,
            null, { timeout: 15000 });

        // 1. The clip arrives on the soundboard track, and not in the voice.
        const quiet = await loudestNear(b, "board", TONE_HZ, 1000);
        const voiceQuiet = await loudestNear(b, "voice", TONE_HZ, 500);
        let before = relay.sent;
        await playTone(a, TONE_HZ);
        const loud = await loudestNear(b, "board", TONE_HZ, 1200);
        const inVoice = await loudestNear(b, "voice", TONE_HZ, 600);
        console.log(`board ${quiet.toFixed(1)} -> ${loud.toFixed(1)} dB; voice at the tone ${voiceQuiet.toFixed(1)} -> ${inVoice.toFixed(1)} dB`);
        assert.ok(loud - quiet > 20, `bob must hear alice's clip: ${quiet.toFixed(1)} dB before, ${loud.toFixed(1)} dB during`);
        // Not "silent": Chromium's fake microphone beeps, with energy near any frequency. A clip
        // mixed into the voice — as before this change — would arrive there at the clip's own
        // level; separate, the voice sits tens of dB below it.
        assert.ok(loud - inVoice > 30, `the clip must not be in alice's voice track: ${inVoice.toFixed(1)} dB there, ${loud.toFixed(1)} dB on the soundboard`);
        assert.strictEqual(relay.sent, before, "playing a clip must send no signal");
        await b.waitForTimeout(2500);   // the 3 s clip ends

        // 2. Bob mutes Alice's soundboard. Her next clip is silent for him, her voice is not.
        await b.evaluate(() => window.CairnCallAudio.setBoardMuted("usr_a", true));
        // Let the meter drain the previous clip's tail before measuring this one.
        await loudestNear(b, "board", TONE_HZ, 800);
        const packetsBefore = await voicePackets(b);
        before = relay.sent;
        await playTone(a, TONE_HZ);
        const muted = await loudestNear(b, "board", TONE_HZ, 1200);
        const packetsAfter = await voicePackets(b);
        const voiceLevel = await b.evaluate(() => ({ live: window.__seen.remote.getAudioTracks()[0].readyState }));
        console.log(`muted board ${muted.toFixed(1)} dB; voice packets ${packetsBefore} -> ${packetsAfter}, track ${voiceLevel.live}`);
        assert.ok(loud - muted > 30, `alice's clip must be silent once bob mutes her soundboard: ${muted.toFixed(1)} dB, against ${loud.toFixed(1)} dB unmuted`);
        assert.ok(packetsAfter - packetsBefore > 20, `alice's voice must keep flowing: ${packetsBefore} -> ${packetsAfter} packets`);
        assert.strictEqual(voiceLevel.live, "live");
        assert.strictEqual(relay.sent, before, "muting is local: no signal");
        // Hers, nobody else's: the setting is per person and stays on bob's device.
        const prefs = await b.evaluate(() => window.CairnCallAudio.prefsFor("usr_a"));
        assert.deepStrictEqual([prefs.boardMuted, prefs.muted, prefs.volume], [true, false, 100]);
        await b.waitForTimeout(2500);

        // 3. Unmuted, it plays again; "mute everyone's soundboard" silences it the same way.
        await b.evaluate(() => window.CairnCallAudio.setBoardMuted("usr_a", false));
        await playTone(a, TONE_HZ);
        const back = await loudestNear(b, "board", TONE_HZ, 1000);
        assert.ok(loud - back < 6, `unmuting brings the clip back: ${back.toFixed(1)} dB`);
        await b.waitForTimeout(2500);
        await b.evaluate(() => window.CairnCallAudio.setAllBoardsMuted(true));
        await loudestNear(b, "board", TONE_HZ, 800);
        await playTone(a, TONE_HZ);
        const allMuted = await loudestNear(b, "board", TONE_HZ, 1000);
        assert.ok(loud - allMuted > 30, `"mute everyone's soundboard" must silence it: ${allMuted.toFixed(1)} dB, against ${loud.toFixed(1)} dB`);
        await b.evaluate(() => window.CairnCallAudio.setAllBoardsMuted(false));
        await b.waitForTimeout(2000);

        // Muting still mutes, and a muted participant cannot play a clip over it.
        await a.evaluate(() => window.CairnCall.setMuted(true));
        const refused = await a.evaluate(async () => {
            try { await window.CairnCall.playClip(new AudioBuffer({ length: 480, sampleRate: 48000 })); return null; }
            catch (e) { return String(e.message); }
        });
        assert.match(refused || "", /unmute/);
    } finally {
        await browser.close();
    }
});
