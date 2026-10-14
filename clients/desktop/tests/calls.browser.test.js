// Calls, as people use them: rung, answered or declined, muted, turned down — in the real
// UI, between two real Chromium pages with fake devices.
//
// ## Why this exists on top of call.browser.test.js
//
// That test drives `call.js` alone and proves two peer connections carry media. Everything a
// person touches sits above it — the incoming-call screen, decline, mute and deafen, the
// speaking ring, per-person volume, push-to-talk, the relay switch — and all of it is in
// app.js, callui.js and callaudio.js, which that test never loads. Each failure here would
// look like a network fault or a broken speaker, not a bug.
//
// Each page is the shipped `ui/` directory with the CSP from tauri.conf.json. Rust is stood
// in for by a relay in node that ports what `Session` does with signals: one id per call,
// `reconcile` at delivery, the ring remembered with who rang, and `call_decline` addressed to
// them. Signals reach a page the way they do in the app, as events from `poll`.
//
// Run: node --test clients/desktop/tests/calls.browser.test.js
// Skipped when Playwright or its Chromium is missing; CAIRN_REQUIRE_BROWSER_TEST=1 turns the
// skip into a failure. CAIRN_SCREENSHOT_DIR saves screenshots of each screen.

const test = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");

const UI = path.join(__dirname, "../ui");
const CONF = JSON.parse(
    fs.readFileSync(path.join(__dirname, "../src-tauri/tauri.conf.json"), "utf8")
);
const TYPES = {
    ".html": "text/html", ".js": "text/javascript", ".css": "text/css",
    ".svg": "image/svg+xml", ".woff2": "font/woff2", ".png": "image/png",
};
const SHOTS = process.env.CAIRN_SCREENSHOT_DIR || null;

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
    // A container has no camera or microphone. These give Chromium synthetic ones — the
    // microphone is a periodic beep, which is what the speaking ring is tested against.
    const args = ["--use-fake-device-for-media-stream", "--use-fake-ui-for-media-stream"];
    try {
        return await pw.chromium.launch({ args });
    } catch (first) {
        const executablePath = findChromium();
        if (!executablePath) throw first;
        return await pw.chromium.launch({ args, executablePath });
    }
}

// Alice's id sorts first, so she is the one who offers.
const ALICE = "usr_a11ce000000040008000000000000001";
const BOB = "usr_b0b00000000040008000000000000002";
const ROOM = "rom_d1ec7000000040008000000000000003";

function profile(user, name) {
    const hex = user.replace(/^usr_/, "");
    return {
        user, short_id: hex.slice(0, 8), tag: hex.slice(0, 12), label: name,
        ambiguous: false, display_name: name, nickname: null, pronouns: null, about: null,
        status: null, colors: user === ALICE ? ["#b5412a", "#e2a93b"] : ["#2f5d62", "#93c47d"],
        avatar: null, banner: null, is_me: false,
    };
}

// What `Session` does with call signals, ported. The browsers have no Rust.
class Relay {
    constructor({ iceServers = [], hasRelay = false } = {}) {
        this.state = new Map();
        this.queues = new Map();
        this.log = [];  // every signal any page sent, as sent
        this.iceServers = iceServers;
        this.hasRelay = hasRelay;
    }

    peer(user) {
        if (!this.state.has(user)) {
            this.state.set(user, { call: null, negotiated: false, ringing: null });
            this.queues.set(user, []);
        }
        return this.state.get(user);
    }

    fanout(from, signal) {
        this.log.push({ from, ...signal });
        for (const user of this.state.keys()) {
            if (user === from) continue;
            if (signal.to && signal.to !== user) continue;
            this.queues.get(user).push({ from, signal });
        }
    }

    // `Session::reconcile`, including the ring.
    reconcile(user, from, signal) {
        const me = this.peer(user);
        if (!me.call) {
            if (signal.kind === "join") { me.ringing = { call: signal.call, from }; return signal; }
            if (signal.kind === "leave") {
                if (me.ringing && me.ringing.call === signal.call) me.ringing = null;
                return signal;
            }
            return null;
        }
        if (signal.call !== me.call && signal.kind === "join" && !me.negotiated) {
            if (signal.to || signal.call < me.call) me.call = signal.call;
        }
        if (signal.call !== me.call && signal.kind !== "join") return null;
        if (signal.kind === "offer" || signal.kind === "answer") me.negotiated = true;
        return { ...signal, call: me.call };
    }

    poll(user) {
        const queue = this.queues.get(user);
        const out = [];
        while (queue.length) {
            const { from, signal } = queue.shift();
            const s = this.reconcile(user, from, signal);
            if (s) out.push({ kind: "signal", from, signal: s });
        }
        return out;
    }

    call(user, cmd, args) {
        const me = this.peer(user);
        switch (cmd) {
            case "call_config":
                return { ice_servers: this.iceServers, has_relay: this.hasRelay, max_participants: 6, direct: true };
            case "call_join":
                me.call = me.call || (me.ringing && me.ringing.call) || "call-from-" + user;
                me.ringing = null;
                this.fanout(user, { call: me.call, kind: "join", payload: "" });
                return me.call;
            case "call_leave":
                if (me.call) this.fanout(user, { call: me.call, kind: "leave", payload: "" });
                me.call = null;
                me.negotiated = false;
                return null;
            case "call_decline":
                if (!me.call && me.ringing) {
                    this.fanout(user, { call: me.ringing.call, kind: "decline", to: me.ringing.from, payload: "" });
                }
                me.ringing = null;
                return null;
            case "signal": {
                const s = { ...args.signal, call: me.call || args.signal.call };
                if (s.kind === "offer" || s.kind === "answer") me.negotiated = true;
                this.fanout(user, s);
                return null;
            }
            case "poll": return this.poll(user);
            default: return undefined;
        }
    }
}

function fake(relay, me) {
    relay.peer(me);
    const profiles = [profile(ALICE, "Alice"), profile(BOB, "Bob")]
        .map((p) => ({ ...p, is_me: p.user === me }));
    return async (cmd, args) => {
        const answer = relay.call(me, cmd, args);
        if (answer !== undefined) return answer;
        switch (cmd) {
            case "sign_in": return { user: me, tls: true };
            case "publish_key_packages": return 5;
            case "rooms": return [{ id: ROOM, tier: "T1", e2ee: true, joined: true }];
            case "open_room": return [];
            case "open_room_tier": return "T1";
            case "room_timer": return null;
            case "members": return profiles.map((p) => ({
                user: p.user, role: "member", in_group: true, verified: false, key_changed: false, profile: p,
            }));
            case "profiles": return profiles;
            case "my_profile": return profiles.find((p) => p.user === me);
            case "attachment_limits": return { max_bytes: 1 << 20 };
            case "link_previews": return null;
            default: return null;
        }
    };
}

async function openApp(browser, relay, me, { theme } = {}) {
    const page = await browser.newPage({ viewport: { width: 1180, height: 760 } });
    page.setDefaultTimeout(15000);
    const errors = [];
    page.on("pageerror", (e) => errors.push(e.message));
    page.on("console", (m) => { if (m.type() === "error") errors.push(m.text()); });
    const answer = fake(relay, me);
    await page.exposeFunction("__invoke", (cmd, args) => answer(cmd, args));
    await page.addInitScript(([look]) => {
        window.__TAURI__ = { core: { invoke: (cmd, args) => window.__invoke(cmd, args) } };
        if (look) {
            try { localStorage.setItem("cairn.look.v1", JSON.stringify({ theme: look, base: look })); } catch (_) {}
        }
    }, [theme || null]);
    await page.route("http://localhost/**", (route) => {
        const rel = new URL(route.request().url()).pathname.replace(/^\/+/, "") || "index.html";
        const file = path.join(UI, rel);
        if (!file.startsWith(UI) || !fs.existsSync(file)) return route.fulfill({ status: 404 });
        return route.fulfill({
            contentType: TYPES[path.extname(file)] || "application/octet-stream",
            headers: { "content-security-policy": CONF.app.security.csp },
            body: fs.readFileSync(file),
        });
    });
    await page.goto("http://localhost/index.html");
    await page.click("#go");
    await page.waitForSelector("#rooms li");
    await page.click("#rooms li");
    await page.waitForFunction(() => document.getElementById("room-tier").textContent === "T1");
    page.errors = errors;
    return page;
}

const tileSel = (user) => "#tile-" + user.replace(/[^a-zA-Z0-9_-]/g, "");
const timeline = (page) => page.$eval("#timeline", (t) => t.textContent);

async function connected(page, peer) {
    await page.waitForSelector(tileSel(peer) + " .dot.live", { timeout: 20000 });
}

async function shot(page, name) {
    if (!SHOTS) return;
    fs.mkdirSync(SHOTS, { recursive: true });
    await page.screenshot({ path: path.join(SHOTS, name + ".png") });
}

// Alice calls, Bob is rung and accepts. Returns once both tiles are live.
async function ringAndAccept(browser, relay, opts = {}) {
    const a = await openApp(browser, relay, ALICE, opts);
    const b = await openApp(browser, relay, BOB, opts);
    await a.click("#start-voice");
    await b.waitForSelector("#ringing:not([hidden])");
    await b.click("#accept-voice");
    await Promise.all([connected(a, BOB), connected(b, ALICE)]);
    return { a, b };
}

const pw = playwright();
const REQUIRED = process.env.CAIRN_REQUIRE_BROWSER_TEST === "1";
if (!pw && REQUIRED) throw new Error("CAIRN_REQUIRE_BROWSER_TEST=1 but playwright is not installed");
const skip = pw ? false : "Playwright is not installed; skipping the calls UI test";

test("calls in the real UI", { skip }, async (t) => {
    let browser;
    try {
        browser = await launch(pw);
    } catch (e) {
        if (REQUIRED) throw e;
        return t.skip("no Chromium for Playwright: " + e.message);
    }
    try {
        await t.test("a ring shows who is calling, and accepting connects both sides", async () => {
            const relay = new Relay();
            const a = await openApp(browser, relay, ALICE);
            const b = await openApp(browser, relay, BOB);
            await a.click("#start-voice");
            await a.waitForFunction(() => document.getElementById("call-status").textContent === "Ringing…");

            await b.waitForSelector("#ringing:not([hidden])");
            // The caller's profile name, drawn by profile.js — not an id fragment.
            assert.strictEqual(await b.$eval("#ringing-name .pf-name", (n) => n.textContent), "Alice");
            assert.match(await b.$eval("#ringing-text", (n) => n.textContent), /calling you/);
            assert.ok(await b.$("#ringing-avatar .pf-avatar"), "the caller's avatar is on the ring");
            await shot(b, "incoming-call");

            await b.click("#accept-voice");
            assert.ok(await b.$eval("#ringing", (r) => r.hidden), "answering takes the ring down");
            await Promise.all([connected(a, BOB), connected(b, ALICE)]);
            await a.waitForFunction(() => document.getElementById("call-status").textContent === "Connected");
            // A voice call shows the other person's avatar, not a black rectangle where a
            // camera would be.
            await b.waitForSelector(tileSel(ALICE) + ".audio-only .pf-avatar", { timeout: 5000 });
            // One call, not two: accepting adopted the announced id.
            const joins = relay.log.filter((s) => s.kind === "join" && !s.to);
            assert.deepStrictEqual([...new Set(joins.map((s) => s.call))], ["call-from-" + ALICE]);
            assert.deepStrictEqual(a.errors, []);
            assert.deepStrictEqual(b.errors, []);
            await a.close(); await b.close();
        });

        await t.test("declining tells the caller, and a declined DM call ends", async () => {
            const relay = new Relay();
            const a = await openApp(browser, relay, ALICE);
            const b = await openApp(browser, relay, BOB);
            await a.click("#start-voice");
            await b.waitForSelector("#ringing:not([hidden])");
            await b.click("#decline");

            await a.waitForFunction(() => document.getElementById("timeline").textContent.includes("Bob declined the call."));
            await a.waitForFunction(() => document.getElementById("call-status").textContent === "Declined");
            await shot(a, "declined");
            // A DM call nobody will answer ends, like a phone call.
            await a.waitForSelector("#stage", { state: "hidden", timeout: 5000 });
            assert.match(await timeline(b), /You declined a call from Alice/);

            const declines = relay.log.filter((s) => s.kind === "decline");
            assert.strictEqual(declines.length, 1);
            assert.strictEqual(declines[0].to, ALICE, "addressed to whoever rang, not broadcast");
            assert.strictEqual(declines[0].call, "call-from-" + ALICE);
            await a.close(); await b.close();
        });

        await t.test("a caller who hangs up first leaves a missed call with a way back", async () => {
            const relay = new Relay();
            const a = await openApp(browser, relay, ALICE);
            const b = await openApp(browser, relay, BOB);
            await a.click("#start-voice");
            await b.waitForSelector("#ringing:not([hidden])");
            await a.click("#hangup");
            await b.waitForSelector("#ringing", { state: "hidden" });
            await b.waitForSelector("#timeline li.call-notice.missed .call-back");
            assert.match(await timeline(b), /Missed call from Alice/);
            await a.close(); await b.close();
        });

        await t.test("mute and deafen reach the other side, and never through the instance", async () => {
            const relay = new Relay();
            const { a, b } = await ringAndAccept(browser, relay);
            const signalsBefore = relay.log.length;

            await a.click("#mute");
            await b.waitForSelector(tileSel(ALICE) + " .tile-badge.muted");
            assert.strictEqual(
                await a.evaluate(() => document.querySelector("#tile-" + "usr_a11ce000000040008000000000000001" + " .tile-badge.muted") !== null),
                true, "your own tile shows it too"
            );
            assert.strictEqual(await a.$eval("#mute", (m) => m.getAttribute("aria-pressed")), "true");
            await shot(b, "peer-muted");

            await a.click("#mute");
            await b.waitForSelector(tileSel(ALICE) + " .tile-badge.muted", { state: "detached" });

            await a.click("#deafen");
            await b.waitForSelector(tileSel(ALICE) + " .tile-badge.deafened");
            await a.click("#deafen");
            await b.waitForSelector(tileSel(ALICE) + " .tile-badge", { state: "detached" });

            // The property the data channel exists for: the instance relays signals, and a
            // mute that went through it would be a timestamped log of when each person spoke.
            const later = relay.log.slice(signalsBefore).filter((s) => s.kind !== "ice");
            assert.deepStrictEqual(later, [], "mute state must not travel as a signal");
            await a.close(); await b.close();
        });

        await t.test("the speaking ring lights when the other side's microphone has sound", async () => {
            const relay = new Relay();
            const { a, b } = await ringAndAccept(browser, relay);
            // The fake microphone beeps about once a second.
            await b.waitForSelector(tileSel(ALICE) + ".speaking", { timeout: 10000 });
            await shot(b, "speaking");
            // Counterfactual: a muted microphone sends silence, so the ring must go out and
            // stay out.
            await a.click("#mute");
            await b.waitForSelector(tileSel(ALICE) + ".speaking", { state: "detached", timeout: 5000 });
            await b.waitForTimeout(2500);
            assert.strictEqual(await b.$(tileSel(ALICE) + ".speaking"), null, "a muted participant is not shown speaking");
            await a.close(); await b.close();
        });

        await t.test("a participant's volume is this device's alone, and persists", async () => {
            const relay = new Relay();
            const { a, b } = await ringAndAccept(browser, relay);
            await b.hover(tileSel(ALICE));
            await b.click(tileSel(ALICE) + " .tile-menu");
            await b.waitForSelector("#volume-pop:not([hidden])");
            await b.$eval("#volume-range", (r) => { r.value = "160"; r.dispatchEvent(new Event("input")); });
            await b.waitForSelector(tileSel(ALICE) + " .tile-badge.local");
            assert.strictEqual(await b.$eval(tileSel(ALICE) + " .tile-badge.local", (x) => x.textContent), "160%");
            // Above 100% the voice moves to the WebAudio path and the tile's own element goes
            // quiet, or she would be heard twice.
            const elementMuted = () => b.$eval(tileSel(ALICE) + " video", (v) => v.muted);
            assert.strictEqual(await elementMuted(), true);
            await shot(b, "volume");
            await b.click("#volume-mute");
            await b.waitForSelector(tileSel(ALICE) + ' .tile-badge.local[title="Muted for you"]');

            const saved = await b.evaluate(() => JSON.parse(localStorage.getItem("cairn.callvol.v1")));
            assert.deepStrictEqual(saved["usr_a11ce000000040008000000000000001"], { volume: 160, muted: true });

            // Back to 100%: the plain element path, which every webview plays reliably.
            await b.click("#volume-reset");
            assert.strictEqual(await elementMuted(), false);
            assert.strictEqual(await b.$eval(tileSel(ALICE) + " video", (v) => v.volume), 1);
            // Deafen silences every voice on this device, whichever path it is on.
            await b.click("#deafen");
            assert.strictEqual(await elementMuted(), true);
            await b.click("#deafen");
            assert.strictEqual(await elementMuted(), false);
            // Alice is not told she was turned down.
            assert.strictEqual(await a.$(tileSel(ALICE) + " .tile-badge.local"), null);
            await a.close(); await b.close();
        });

        await t.test("push-to-talk opens the microphone only while the key is held", async () => {
            const relay = new Relay();
            const a = await openApp(browser, relay, ALICE);
            const b = await openApp(browser, relay, BOB);
            await a.click("#open-settings");
            await a.check("#pref-mode-ptt");
            await shot(a, "settings-voice");
            await a.click("#settings-close");
            await a.click("#start-voice");
            await b.waitForSelector("#ringing:not([hidden])");
            await b.click("#accept-voice");
            await Promise.all([connected(a, BOB), connected(b, ALICE)]);

            const open = () => a.evaluate(() => CairnCall.transmitting);
            assert.strictEqual(await open(), false, "closed until the key is held");
            assert.ok(!(await a.$eval("#ptt-hint", (h) => h.hidden)), "the call bar says how to talk");
            await a.keyboard.down("Backquote");
            assert.strictEqual(await open(), true);
            await a.keyboard.up("Backquote");
            assert.strictEqual(await open(), false);
            // Losing focus releases it: alt-tabbing away mid-sentence must not leave it open.
            await a.keyboard.down("Backquote");
            await a.evaluate(() => window.dispatchEvent(new Event("blur")));
            assert.strictEqual(await open(), false);
            await a.keyboard.up("Backquote");
            await a.close(); await b.close();
        });

        await t.test("relay-only with no relay is refused before the microphone opens", async () => {
            const relay = new Relay({ hasRelay: false });
            const a = await openApp(browser, relay, ALICE);
            await a.click("#open-settings");
            await a.check("#pref-relay-only");
            assert.match(await a.$eval("#relay-only-note", (n) => n.textContent), /no relay/);
            await a.click("#settings-close");
            await a.click("#start-voice");
            await a.waitForFunction(() => /Always use the relay/.test(document.getElementById("error").textContent));
            assert.ok(await a.$eval("#stage", (s) => s.hidden));
            assert.strictEqual(relay.log.length, 0, "nothing was announced");
            await a.close();
        });

        await t.test("relay-only offers no address of this device to the other side", async () => {
            // A relay that is not there: the browser can gather nothing from it, so under
            // the relay policy it must offer nothing at all — no host address, no reflexive
            // one — and the call must not connect directly behind the user's back.
            const unreachable = [{ urls: ["turn:127.0.0.1:9"], username: "1:usr_x", credential: "c" }];
            const relay = new Relay({ iceServers: unreachable, hasRelay: true });
            const a = await openApp(browser, relay, ALICE);
            const b = await openApp(browser, relay, BOB);
            for (const p of [a, b]) {
                await p.click("#open-settings");
                await p.check("#pref-relay-only");
                await p.click("#settings-close");
            }
            await a.click("#start-voice");
            await b.waitForSelector("#ringing:not([hidden])");
            await b.click("#accept-voice");
            // Long enough for host candidates to have been gathered and sent many times over.
            await a.waitForTimeout(6000);
            const candidates = relay.log.filter((s) => s.kind === "ice").map((s) => JSON.parse(s.payload).candidate || "");
            const exposed = candidates.filter((c) => !/ typ relay /.test(c + " "));
            assert.deepStrictEqual(exposed, [], "only relay candidates may be offered");
            // Nor smuggled inside the SDP itself, where a description created after
            // gathering would carry its candidates inline.
            for (const s of relay.log.filter((x) => x.kind === "offer" || x.kind === "answer")) {
                const sdp = JSON.parse(s.payload).sdp;
                assert.ok(!/typ (host|srflx|prflx)/.test(sdp), "an SDP offered a direct address:\n" + sdp);
            }
            assert.strictEqual(await a.$(tileSel(BOB) + " .dot.live"), null, "and nothing connected directly");
            assert.ok(relay.log.some((s) => s.kind === "offer"), "the call did negotiate");
            await a.close(); await b.close();

            // Counterfactual: the same call with the setting off does offer host candidates
            // and connects. Without this the assertion above could pass on a broken gather.
            const direct = new Relay({ iceServers: unreachable, hasRelay: true });
            const { a: a2, b: b2 } = await ringAndAccept(browser, direct);
            const host = direct.log.filter((s) => s.kind === "ice").map((s) => JSON.parse(s.payload).candidate || "");
            assert.ok(host.some((c) => / typ host/.test(c)), "a direct call offers host candidates: " + JSON.stringify(host));
            await a2.close(); await b2.close();
        });

        await t.test("the call screens wear the theme: Slate and Fieldbook", async () => {
            for (const theme of ["slate", "fieldbook"]) {
                const relay = new Relay();
                const a = await openApp(browser, relay, ALICE, { theme });
                const b = await openApp(browser, relay, BOB, { theme });
                await a.click("#start-video");
                await b.waitForSelector("#ringing:not([hidden])");
                await shot(b, theme + "-incoming");
                const card = await b.$eval(".incoming-card", (c) => getComputedStyle(c).backgroundColor);
                const surface = await b.evaluate(() => getComputedStyle(document.documentElement).getPropertyValue("--surface").trim());
                assert.ok(card && surface, "the card is painted from the theme's tokens");
                await b.click("#accept-voice");
                await Promise.all([connected(a, BOB), connected(b, ALICE)]);
                await a.click("#mute");
                await b.waitForSelector(tileSel(ALICE) + " .tile-badge.muted");
                await b.waitForTimeout(600);
                await shot(b, theme + "-in-call");
                await b.click("#open-settings");
                await b.$eval("#prefs-voice", (p) => p.scrollIntoView());
                await shot(b, theme + "-settings-voice");
                assert.deepStrictEqual(a.errors, []);
                assert.deepStrictEqual(b.errors, []);
                await a.close(); await b.close();
            }
        });
    } finally {
        await browser.close();
    }
});
