// The soundboard's one claim, tested between two real browsers: a clip played by one
// participant is *heard by the other*, carried inside the microphone track — and playing it
// sends no signal at all.
//
// Runs `ui/call.js` unchanged in two Chromium pages with fake media devices, wired together
// by a relay that stands in for Rust (the same shape as call.browser.test.js). Alice mixes a
// pure tone into her outgoing audio with `CairnCall.mixIntoMic`; Bob measures the audio he
// receives and must see that tone rise out of the noise floor. The signal count is checked
// across the play, because a "play X" announcement would cross the instance with a timestamp
// — the thing mixing exists to avoid.
//
// Run: node --test clients/desktop/tests/soundboard.browser.test.js

const test = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");

const CALL_JS = fs.readFileSync(path.join(__dirname, "../ui/call.js"), "utf8");
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
    `);
    await page.route("http://localhost/cairn", (route) =>
        route.fulfill({ contentType: "text/html", body: "<!doctype html><title>cairn</title>" }));
    await page.goto("http://localhost/cairn");
    await page.addScriptTag({ content: CALL_JS + "\n;window.CairnCall = CairnCall;" });
    await page.evaluate(() => {
        window.CairnCall.bind({
            onPeer: (u, s) => { if (s) window.__seen.remote = s; },
            onState: (u, st) => window.__seen.states.push(st),
            onNotice: () => {},
        });
    });
    relay.pages.set(user, page);
    return page;
}

// In the receiving page: the loudest level, in dB, near `hz` over `ms` of incoming audio.
async function loudestNear(page, hz, ms) {
    return page.evaluate(async ([hz, ms]) => {
        if (!window.__meter) {
            // Chromium only feeds a remote WebRTC stream to WebAudio while a media element
            // is also consuming it.
            const el = document.createElement("audio");
            el.muted = true;
            el.srcObject = window.__seen.remote;
            document.body.append(el);
            await el.play().catch(() => {});
            const ctx = new AudioContext();
            const analyser = ctx.createAnalyser();
            analyser.fftSize = 4096;
            ctx.createMediaStreamSource(window.__seen.remote).connect(analyser);
            window.__meter = { ctx, analyser };
        }
        const { ctx, analyser } = window.__meter;
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
    }, [hz, ms]);
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

        const quiet = await loudestNear(b, TONE_HZ, 1500);
        const before = relay.sent;
        await a.evaluate(async (hz) => {
            const rate = 48000;
            const buffer = new AudioBuffer({ length: rate * 3, sampleRate: rate, numberOfChannels: 1 });
            const data = buffer.getChannelData(0);
            for (let i = 0; i < data.length; i++) data[i] = 0.8 * Math.sin((2 * Math.PI * hz * i) / rate);
            await window.CairnCall.mixIntoMic(buffer);
        }, TONE_HZ);
        const loud = await loudestNear(b, TONE_HZ, 1500);
        assert.ok(loud - quiet > 20,
            `bob must hear alice's clip: ${quiet.toFixed(1)} dB before, ${loud.toFixed(1)} dB during`);
        assert.strictEqual(relay.sent, before, "playing a clip must send no signal");

        // Muting still mutes, and a muted participant cannot play a clip over it.
        await a.evaluate(() => window.CairnCall.setMuted(true));
        const refused = await a.evaluate(async () => {
            try { await window.CairnCall.mixIntoMic(new AudioBuffer({ length: 480, sampleRate: 48000 })); return null; }
            catch (e) { return String(e.message); }
        });
        assert.match(refused || "", /unmute/);
    } finally {
        await browser.close();
    }
});
