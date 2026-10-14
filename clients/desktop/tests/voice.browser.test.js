// Voice notes, in the real UI, in a real browser with a fake microphone.
//
// Serves `ui/` unchanged over http://localhost (getUserMedia needs a secure context) and
// stubs only `window.__TAURI__.core.invoke`. Chromium's fake capture device feeds a real
// MediaRecorder, so what is checked is an actual recording: that it leaves as raw bytes
// with an audio type Rust treats as playable, that hold-to-talk, click-to-lock, cancel and
// Escape do what they say, and that a received note gets the waveform player and plays.
// Rust's side — that `audio/webm;codecs=opus` is playable audio — is in cargo.
//
// Run: node --test clients/desktop/tests/voice.browser.test.js
// Set CAIRN_SCREENSHOT_DIR to keep screenshots of the recording bar and the player.

const test = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const http = require("node:http");
const path = require("node:path");

const UI = path.join(__dirname, "../ui");
const TYPES = { ".html": "text/html", ".js": "text/javascript", ".css": "text/css" };

function playwright() {
    for (const base of [null, "/opt/node22/lib/node_modules", "/usr/lib/node_modules"]) {
        try {
            return require(base ? path.join(base, "playwright") : "playwright");
        } catch (_) { /* try the next */ }
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
    const args = [
        "--use-fake-device-for-media-stream",
        "--use-fake-ui-for-media-stream",
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

function serve() {
    const server = http.createServer((req, res) => {
        const rel = decodeURIComponent(new URL(req.url, "http://x").pathname).replace(/^\/+/, "") || "index.html";
        const file = path.join(UI, rel);
        if (!file.startsWith(UI) || !fs.existsSync(file)) {
            res.writeHead(404);
            return res.end();
        }
        res.writeHead(200, { "content-type": TYPES[path.extname(file)] || "application/octet-stream" });
        res.end(fs.readFileSync(file));
    });
    return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(server)));
}

// The stand-in for Rust. A sent file is kept, so fetching it back returns the recording the
// page made: the player is tested on real recorder output, not a hand-made fixture.
function stub() {
    window.__calls = [];
    const stored = {};
    // One second of a 440 Hz tone that fades out, as WAV, for a received note.
    function wav() {
        const rate = 8000, n = rate;
        const b = new DataView(new ArrayBuffer(44 + n * 2));
        const s = (o, t) => [...t].forEach((ch, i) => b.setUint8(o + i, ch.charCodeAt(0)));
        s(0, "RIFF"); b.setUint32(4, 36 + n * 2, true); s(8, "WAVE"); s(12, "fmt ");
        b.setUint32(16, 16, true); b.setUint16(20, 1, true); b.setUint16(22, 1, true);
        b.setUint32(24, rate, true); b.setUint32(28, rate * 2, true); b.setUint16(32, 2, true);
        b.setUint16(34, 16, true); s(36, "data"); b.setUint32(40, n * 2, true);
        for (let i = 0; i < n; i++) {
            const v = Math.sin(2 * Math.PI * 440 * i / rate) * (1 - i / n) * 20000;
            b.setInt16(44 + i * 2, v, true);
        }
        return b.buffer;
    }
    stored.blob_wav = wav();
    const history = [
        { sender: "usr_alice000", body: "Voice note.wav", sent_at_ms: 1, historic: true,
          attachment: { id: "blob_wav", name: "Voice note.wav", size: 16044, mime: "audio/wav", kind: "audio" } },
    ];
    let n = 0;
    const answers = {
        sign_in: () => ({ user: "usr_me000000", tls: true }),
        rooms: () => [{ id: "rom_room0000", e2ee: true, tier: "T1", joined: true }],
        open_room: () => history,
        open_room_tier: () => "T1",
        members: () => [],
        poll: () => [],
        call_config: () => ({ ice_servers: [], has_relay: false, max_participants: 8 }),
        attachment_limits: () => ({ max_bytes: 25 * 1024 * 1024 }),
        room_timer: () => null,
        fetch_attachment: ({ id }) => stored[id].slice(0),
        send_file: (body, o) => {
            const meta = JSON.parse(o.headers["x-cairn-file"]);
            const id = "blob_sent" + (n++);
            stored[id] = body.slice().buffer;
            const audio = /^audio\/(webm|ogg|mp4)/.test(meta.mime);
            return { sender: "usr_me000000", body: meta.name, sent_at_ms: 9, historic: false,
                     attachment: { id, name: meta.name, size: body.length, mime: meta.mime, kind: audio ? "audio" : "file" } };
        },
    };
    window.__TAURI__ = { core: { invoke: async (cmd, args, o) => {
        const rec = { cmd };
        if (args instanceof Uint8Array) {
            rec.raw = true;
            rec.length = args.length;
            rec.header = o && o.headers && o.headers["x-cairn-file"];
        } else {
            rec.args = args;
        }
        window.__calls.push(rec);
        const answer = answers[cmd];
        return answer ? answer(args, o) : null;
    } } };
}

async function openApp(browser, base) {
    const context = await browser.newContext({ viewport: { width: 1100, height: 750 } });
    await context.grantPermissions(["microphone"], { origin: base });
    const page = await context.newPage();
    const errors = [];
    page.setDefaultTimeout(10000);
    page.on("pageerror", (e) => errors.push(String(e)));
    await page.addInitScript(stub);
    await page.goto(base + "/index.html");
    await page.click("#go");
    await page.click("#rooms li");
    await page.waitForSelector("#timeline .voice-player");
    return { page, errors, context };
}

const sends = (page) => page.evaluate(() => window.__calls.filter((c) => c.cmd === "send_file"));
const shots = process.env.CAIRN_SCREENSHOT_DIR;

const pw = playwright();
const REQUIRED = process.env.CAIRN_REQUIRE_BROWSER_TEST === "1";
if (!pw && REQUIRED) {
    throw new Error("CAIRN_REQUIRE_BROWSER_TEST=1 but playwright is not installed");
}
const skip = pw ? false : "Playwright is not installed; skipping the voice note UI test";

test("voice notes in the real UI", { skip }, async (t) => {
    const server = await serve();
    const base = "http://localhost:" + server.address().port;
    let browser;
    try {
        browser = await launch(pw);
    } catch (e) {
        server.close();
        if (REQUIRED) throw e;
        return t.skip("no Chromium for Playwright: " + e.message);
    }

    try {
        await t.test("a received note gets a waveform player that decodes and plays", async () => {
            const { page, errors, context } = await openApp(browser, base);
            await page.waitForSelector(".voice-player.decoded");
            // The decoded length, not the element's guess.
            assert.strictEqual(await page.$eval(".voice-player .voice-time", (e) => e.textContent), "0:01");
            const heights = await page.$$eval(".voice-wave span", (l) => l.map((s) => parseFloat(s.style.height)));
            assert.ok(heights[0] > heights[heights.length - 1], "a fading tone draws a falling waveform: " + heights);
            await page.click(".voice-play");
            await page.waitForSelector(".voice-player.is-playing");
            await page.waitForFunction(() => document.querySelectorAll(".voice-wave span.played").length > 0);
            if (shots) await page.screenshot({ path: path.join(shots, "voice-player.png") });
            // The stock audio element is still there underneath, for the attachments test.
            assert.ok(await page.$eval(".attach-audio audio", (a) => a.src.startsWith("blob:")));
            assert.deepStrictEqual(errors, []);
            await context.close();
        });

        await t.test("a click locks recording on, and Send sends a real recording as audio", async () => {
            const { page, errors, context } = await openApp(browser, base);
            await page.click("#voice");
            await page.waitForSelector(".voice-bar.locked:not([hidden])");
            assert.strictEqual(await page.$eval("#text", (e) => getComputedStyle(e).visibility), "hidden");
            await page.waitForFunction(() => /^0:0[1-9] \/ 2:00$/.test(document.querySelector(".voice-timer").textContent));
            if (shots) await page.screenshot({ path: path.join(shots, "voice-recording.png") });
            await page.click(".voice-send");
            await page.waitForFunction(() => window.__calls.some((c) => c.cmd === "send_file"));
            const [sent] = await sends(page);
            assert.strictEqual(sent.raw, true, "the recording is the raw IPC body");
            const meta = JSON.parse(sent.header);
            assert.match(meta.mime, /^audio\/(webm|ogg)(;codecs=opus)?$/, meta.mime);
            assert.match(meta.name, /^Voice note \d{4}-\d\d-\d\d \d\d-\d\d\.(webm|ogg)$/, meta.name);
            assert.ok(sent.length > 1000, "a second of audio is more than a header: " + sent.length);
            // Our own note is drawn from what Rust handed back, and decodes.
            await page.waitForFunction(() => document.querySelectorAll(".voice-player.decoded").length === 2);
            assert.strictEqual(await page.$eval("#composer", (c) => c.classList.contains("voice-recording")), false);
            assert.deepStrictEqual(errors, []);
            await context.close();
        });

        await t.test("holding the mic records and releasing on it sends", async () => {
            const { page, context } = await openApp(browser, base);
            const box = await page.$eval("#voice", (b) => { const r = b.getBoundingClientRect(); return { x: r.x + r.width / 2, y: r.y + r.height / 2 }; });
            await page.mouse.move(box.x, box.y);
            await page.mouse.down();
            await page.waitForSelector(".voice-bar:not(.locked):not([hidden])");
            assert.match(await page.$eval(".voice-hint", (e) => e.textContent), /Release to send/);
            await page.waitForTimeout(1200);
            await page.mouse.up();
            await page.waitForFunction(() => window.__calls.some((c) => c.cmd === "send_file"));
            assert.strictEqual((await sends(page)).length, 1);
            await context.close();
        });

        await t.test("releasing off the mic, or Escape, throws the recording away", async () => {
            const { page, context } = await openApp(browser, base);
            const box = await page.$eval("#voice", (b) => { const r = b.getBoundingClientRect(); return { x: r.x + r.width / 2, y: r.y + r.height / 2 }; });
            await page.mouse.move(box.x, box.y);
            await page.mouse.down();
            await page.waitForSelector(".voice-bar:not([hidden])");
            await page.waitForTimeout(900);
            await page.mouse.move(box.x - 300, box.y - 200);
            await page.mouse.up();
            await page.waitForSelector(".voice-bar", { state: "hidden" });

            await page.click("#voice");
            await page.waitForSelector(".voice-bar.locked:not([hidden])");
            await page.waitForTimeout(900);
            await page.keyboard.press("Escape");
            await page.waitForSelector(".voice-bar", { state: "hidden" });
            await page.waitForTimeout(300);
            assert.strictEqual((await sends(page)).length, 0, "nothing may be sent");
            // And the microphone is released, not left live behind a hidden bar.
            assert.strictEqual(await page.$eval("#voice", (b) => b.classList.contains("on")), false);
            await context.close();
        });

        await t.test("a slip of the finger is not sent", async () => {
            const { page, context } = await openApp(browser, base);
            await page.click("#voice");
            await page.waitForSelector(".voice-bar.locked:not([hidden])");
            await page.click(".voice-send");
            await page.waitForFunction(() => /too short/.test(document.getElementById("error").textContent));
            assert.strictEqual((await sends(page)).length, 0);
            await context.close();
        });
    } finally {
        await browser.close();
        server.close();
    }
});
