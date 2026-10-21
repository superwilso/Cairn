// Rooms that are not open, in the whole desktop UI, against real sessions and the real SFU.
//
// ## What is real here
//
// Everything below `invoke`, as in voicechannel.browser.test.js: `crates/cairn-server/
// examples/sfu_harness.rs` runs a real instance and SFU and a real `cairn-client-core`
// Session per person. Bob's page is the shipped `ui/index.html`, under the app's CSP, and
// every command it sends goes to his real session — so the unread counts, the mention flag
// and the ring are what Rust decided from messages it decrypted, not what a stub said.
// Alice is driven through the harness, plus a bare page for her microphone.
//
// ## What it proves
//
// 1. A message in a room bob does not have open is counted on that room in the sidebar, a
//    mention of him is marked as one, and nothing from it lands in the open room's timeline.
// 2. A ring in a room bob does not have open reaches him: the incoming-call screen names the
//    room, and declining it reaches alice — addressed to her, in that room.
// 3. Opening the room clears its count and shows the mention highlighted.
// 4. A voice channel survives switching rooms: bob joins in room A, opens room B, and the
//    voice bar is there with the call's own badge, alice's audio still arrives, and mute and
//    leave work from the bar.
//
// Run: node --test clients/desktop/tests/background.browser.test.js
// Skips, saying so, without Playwright's Chromium or a Rust toolchain — unless
// CAIRN_REQUIRE_BROWSER_TEST=1, as in CI. CAIRN_SCREENSHOT_DIR saves the screens.

const test = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");
const http = require("node:http");
const { spawn, spawnSync } = require("node:child_process");
const readline = require("node:readline");

const ROOT = path.join(__dirname, "../../..");
const UI = path.join(__dirname, "../ui");
const CONF = JSON.parse(fs.readFileSync(path.join(__dirname, "../src-tauri/tauri.conf.json"), "utf8"));
const REQUIRED = process.env.CAIRN_REQUIRE_BROWSER_TEST === "1";
const SHOTS = process.env.CAIRN_SCREENSHOT_DIR || null;
const TYPES = {
    ".html": "text/html", ".js": "text/javascript", ".css": "text/css",
    ".svg": "image/svg+xml", ".woff2": "font/woff2", ".png": "image/png", ".jpg": "image/jpeg",
};

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
    as(name, cmd, args = {}) { return this.call({ op: "invoke", as: name, cmd, args }); }
    close() { this.proc.kill(); }
}

// ui/ over http://localhost — a secure context — with the shipped CSP, and a bare page for
// alice's microphone.
function serveUi() {
    const bare = `<!doctype html><meta charset="utf-8"><body>
<script src="mediaframe.js"></script><script src="voicechannel.js"></script><script src="callaudio.js"></script></body>`;
    const server = http.createServer((req, res) => {
        const name = decodeURIComponent(req.url.split("?")[0]).replace(/^\/+/, "") || "index.html";
        if (name === "bare.html") {
            res.writeHead(200, { "content-type": "text/html" }); return res.end(bare);
        }
        const file = path.join(UI, path.normalize(name));
        if (!file.startsWith(UI) || !fs.existsSync(file) || fs.statSync(file).isDirectory()) {
            res.writeHead(404); return res.end();
        }
        res.writeHead(200, {
            "content-type": TYPES[path.extname(file)] || "application/octet-stream",
            "content-security-policy": CONF.app.security.csp,
        });
        res.end(fs.readFileSync(file));
    });
    return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(server)));
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function until(what, fn, ms = 20000) {
    const end = Date.now() + ms;
    let last;
    while (Date.now() < end) {
        last = await fn();
        if (last) return last;
        await sleep(250);
    }
    throw new Error("timed out waiting for " + what + " (last: " + JSON.stringify(last) + ")");
}

async function shot(page, name) {
    if (!SHOTS) return;
    fs.mkdirSync(SHOTS, { recursive: true });
    await page.screenshot({ path: path.join(SHOTS, name + ".png") });
}

async function pageFor(browser, url, harness, name) {
    const ctx = await browser.newContext({ permissions: ["microphone"], viewport: { width: 1280, height: 800 } });
    const page = await ctx.newPage();
    page.on("pageerror", (e) => console.error(name + " page error:", e.message));
    await page.exposeFunction("harnessInvoke", (cmd, args) => harness.as(name, cmd, args || {}));
    await page.addInitScript(() => {
        window.__TAURI__ = { core: { invoke: (cmd, args) => window.harnessInvoke(cmd, args) } };
    });
    await page.goto(url);
    return page;
}

// RMS of what a listener receives on any voice-channel slot, from the decoded tracks.
async function loudest(page) {
    return page.evaluate(async () => {
        const ctx = new AudioContext();
        let best = 0;
        for (const el of CairnVoiceChannel.audio.values()) {
            if (!el.srcObject) continue;
            const an = ctx.createAnalyser();
            an.fftSize = 2048;
            ctx.createMediaStreamSource(el.srcObject).connect(an);
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

test("rings, unreads and a voice channel reach the user from rooms that are not open", { timeout: 240_000 }, async (t) => {
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
    let polling = true;
    const aliceEvents = [];
    try {
        await harness.ready;
        const { users, rooms } = await harness.call({ op: "setup", names: ["alice", "bob"], rooms: 2 });
        const [A, B] = rooms;
        const shortBob = users.bob.replace(/^usr_/, "").replace(/-/g, "").slice(0, 8);

        // Alice has no full UI; her session is polled here, as the app would.
        const poller = (async () => {
            while (polling) {
                const evs = await harness.as("alice", "poll").catch(() => []);
                aliceEvents.push(...(evs || []));
                await sleep(300);
            }
        })();

        const bob = await pageFor(browser, base + "/index.html", harness, "bob");
        await bob.click("#go");
        await bob.waitForSelector("#app:not([hidden])");
        await bob.click(`#rooms li[data-room="${A}"]`);
        await until("room A open", () => bob.evaluate((a) => document.getElementById("room-id").title === a, A));

        // 1. Unread, and a mention, in room B while A is open.
        await harness.as("alice", "open_room", { room: B });
        await harness.as("alice", "send", { text: "anyone around?" });
        await harness.as("alice", "send", { text: "@" + shortBob + " can you look at this" });
        const pillB = await until("room B shows its unread and the mention", () => bob.evaluate((b) => {
            const p = document.querySelector(`#rooms li[data-room="${b}"] .unread`);
            return p && { text: p.textContent, mention: p.classList.contains("mentioned"), title: p.title };
        }, B));
        assert.deepStrictEqual({ text: pillB.text, mention: pillB.mention }, { text: "@", mention: true });
        assert.match(pillB.title, /^2 unread, 1 mentioning you$/);
        const timelineA = await bob.evaluate(() => document.getElementById("timeline").textContent);
        assert.ok(!timelineA.includes("anyone around"), "room B's message is not drawn in room A");
        assert.strictEqual(await bob.evaluate((a) => !!document.querySelector(`#rooms li[data-room="${a}"] .unread`), A), false);
        await shot(bob, "01-unread-and-mention-in-another-room");

        // 2. A ring in room B reaches bob in room A, and his decline reaches alice.
        await harness.as("alice", "call_join");
        await until("the incoming-call screen", () => bob.evaluate(() => !document.getElementById("ringing").hidden));
        const ringText = await bob.evaluate(() => document.getElementById("ringing-text").textContent);
        assert.match(ringText, /^is calling in /, ringText);
        await shot(bob, "02-ring-from-another-room");
        await bob.click("#decline");
        await until("alice hears the decline", () => aliceEvents.some((e) =>
            e.kind === "signal" && e.signal.kind === "decline" && e.from === users.bob));
        await harness.as("alice", "call_leave");
        assert.ok(await bob.evaluate(() => document.getElementById("ringing").hidden));

        // 3. Opening room B clears its count and shows the mention highlighted.
        await bob.click(`#rooms li[data-room="${B}"]`);
        await until("room B's history", () => bob.evaluate(() => document.querySelectorAll("#timeline .msg").length >= 2));
        const marks = await bob.evaluate(() => [...document.querySelectorAll("#timeline .msg")].map((li) => li.classList.contains("mention")));
        assert.deepStrictEqual(marks, [false, true], "only the message naming bob is highlighted");
        assert.strictEqual(await bob.evaluate((b) => !!document.querySelector(`#rooms li[data-room="${b}"] .unread`), B), false);
        await shot(bob, "03-mention-highlighted");

        // 4. The voice channel in room A survives bob opening room B.
        await harness.as("alice", "open_room", { room: A });
        const alice = await pageFor(browser, base + "/bare.html", harness, "alice");
        await alice.evaluate(() => CairnVoiceChannel.join());
        await bob.click(`#rooms li[data-room="${A}"]`);
        await until("room A's voice channel", () => bob.evaluate(() => !document.getElementById("voice-channel").hidden));
        await bob.click("#vc-join");
        await until("bob connected", () => bob.evaluate(() => CairnVoiceChannel.pc && CairnVoiceChannel.pc.connectionState === "connected"));
        await until("bob hears alice in room A", async () => (await loudest(bob)) > 0.01);

        await bob.click(`#rooms li[data-room="${B}"]`);
        await until("room B open", () => bob.evaluate((b) => document.getElementById("room-id").title === b, B));
        await sleep(2500);   // several voice_call refreshes and polls, from room B
        const bar = await bob.evaluate(() => ({
            shown: !document.getElementById("voice-bar").hidden,
            badge: document.getElementById("vb-badge").textContent,
            room: document.getElementById("vb-room").textContent,
            session: !!CairnVoiceChannel.session,
            state: CairnVoiceChannel.pc && CairnVoiceChannel.pc.connectionState,
        }));
        assert.deepStrictEqual(
            { shown: bar.shown, badge: bar.badge, session: bar.session, state: bar.state },
            { shown: true, badge: "End-to-end", session: true, state: "connected" },
            "still connected from room B, and the bar carries the call's own badge: " + JSON.stringify(bar));
        assert.strictEqual(bar.room, A.replace(/^rom_/, "").slice(0, 8));
        const before = await bob.evaluate(() => CairnVoiceChannel.readStats());
        const level = await until("bob still hears alice from room B", async () => { const r = await loudest(bob); return r > 0.01 && r; });
        const after = await bob.evaluate(() => CairnVoiceChannel.readStats());
        console.log("from room B: RMS", level.toFixed(3), "frames opened", before.opened, "->", after.opened);
        assert.ok(after.opened > before.opened, "sealed frames keep opening after the switch");
        assert.strictEqual(after.passed, 0, "and nothing arrives unsealed");
        await until("alice still hears bob", async () => (await loudest(alice)) > 0.01);
        await shot(bob, "04-voice-bar-in-another-room");

        await bob.click("#vb-mute");
        assert.strictEqual(await bob.evaluate(() => [CairnVoiceChannel.muted, document.getElementById("vb-mute").getAttribute("aria-pressed")]).then((x) => x.join()), "true,true");
        await shot(bob, "05-voice-bar-muted");
        await bob.click("#vb-leave");
        await until("left from the bar", () => bob.evaluate(() => !CairnVoiceChannel.session && document.getElementById("voice-bar").hidden));
        const roster = await alice.evaluate(() => CairnVoiceChannel.refresh().then(() => CairnVoiceChannel.state.participants.map((p) => p.user)));
        assert.deepStrictEqual(roster, [users.alice], "the instance saw bob leave");

        polling = false;
        await poller;
    } finally {
        polling = false;
        await browser.close();
        server.close();
        harness.close();
    }
});
