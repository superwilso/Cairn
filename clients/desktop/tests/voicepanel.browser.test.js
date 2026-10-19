// The voice-channel panel in the whole UI, against a stand-in for the Rust session.
//
// voicechannel.browser.test.js proves the media: real SFU, real keys, real Chromium. This
// proves the half a person looks at, with `voice_state` answered by a fake so each state can
// be drawn on demand: that the room shows who is in its voice channel, that the call carries
// **its own** badge, that a transport-only fallback changes the call's badge and leaves the
// room's tier badge alone (§5 of docs/12-realtime-media.md), and that the participant who
// caused it is marked. And that an instance with no SFU shows no voice channel. The
// announcement to people *in* the call is voicechannel.browser.test.js's, where it is real.
//
// Screenshots: set CAIRN_SCREENSHOT_DIR.
// Run: node --test clients/desktop/tests/voicepanel.browser.test.js

const test = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");

const UI = path.join(__dirname, "../ui");
const CONF = JSON.parse(fs.readFileSync(path.join(__dirname, "../src-tauri/tauri.conf.json"), "utf8"));
const SHOTS = process.env.CAIRN_SCREENSHOT_DIR || null;

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
    try { return await pw.chromium.launch(); } catch (first) {
        const executablePath = findChromium();
        if (!executablePath) throw first;
        return await pw.chromium.launch({ executablePath });
    }
}

const ROOM = "rom_0a1b2c3d4e5f60718293a4b5c6d7e8f9";
const ME = "usr_a11ce000000000000000000000000000";
const BOB = "usr_b0b00000000000000000000000000000";
const CAROL = "usr_ca401000000000000000000000000000";
const DEV = (n) => "dev_" + String(n).repeat(32).slice(0, 32);

const person = (user, n, extra = {}) =>
    ({ user, device: DEV(n), joined_at_ms: 1000 * n, me: false, in_group: true, media: "e2ee", ...extra });

class FakeSession {
    constructor() { this.voice = { available: false }; this.events = []; }
    async invoke(cmd, args) {
        switch (cmd) {
            case "sign_in": return { user: ME, tls: true };
            case "publish_key_packages": return 5;
            case "rooms": return [{ id: ROOM, tier: "T2", e2ee: true, joined: true }];
            case "open_room": return [];
            case "open_room_tier": return "T2";
            case "members": return [
                { user: ME, role: "owner", in_group: true, verified: false },
                { user: BOB, role: "member", in_group: true, verified: false },
                { user: CAROL, role: "member", in_group: true, verified: false },
            ];
            case "poll": { const out = this.events; this.events = []; return out; }
            case "call_config": return { ice_servers: [], has_relay: false, max_participants: 6 };
            case "room_timer": return null;
            case "voice_state": return this.voice;
            default: return null;
        }
    }
}

async function openApp(browser, fake) {
    const page = await browser.newPage({ viewport: { width: 1180, height: 760 } });
    const errors = [];
    page.on("pageerror", (e) => errors.push(e.message));
    await page.exposeFunction("__invoke", (cmd, args) => fake.invoke(cmd, args));
    await page.addInitScript(`window.__TAURI__ = { core: { invoke: (cmd, args) => window.__invoke(cmd, args) } };`);
    await page.route("http://localhost/**", (route) => {
        const rel = new URL(route.request().url()).pathname.replace(/^\/+/, "") || "index.html";
        const file = path.join(UI, rel);
        if (!file.startsWith(UI) || !fs.existsSync(file)) return route.fulfill({ status: 404 });
        const type = { ".html": "text/html", ".js": "text/javascript", ".css": "text/css" }[path.extname(file)]
            || "application/octet-stream";
        return route.fulfill({ contentType: type, headers: { "content-security-policy": CONF.app.security.csp }, body: fs.readFileSync(file) });
    });
    await page.goto("http://localhost/index.html");
    await page.click("#go");
    await page.waitForSelector("#rooms li");
    await page.click("#rooms li");
    await page.waitForFunction(() => document.getElementById("room-id").textContent !== "");
    page.errors = errors;
    return page;
}

async function shoot(page, name) {
    if (!SHOTS) return;
    fs.mkdirSync(SHOTS, { recursive: true });
    await page.screenshot({ path: path.join(SHOTS, name + ".png") });
}

const pw = playwright();
const REQUIRED = process.env.CAIRN_REQUIRE_BROWSER_TEST === "1";
if (!pw && REQUIRED) throw new Error("CAIRN_REQUIRE_BROWSER_TEST=1 but playwright is not installed");
const skip = pw ? false : "playwright is not installed";

test("no SFU, no voice channel", { skip }, async () => {
    const browser = await launch(pw);
    try {
        const page = await openApp(browser, new FakeSession());
        await page.waitForTimeout(300);
        assert.strictEqual(await page.isHidden("#voice-channel"), true);
        assert.deepStrictEqual(page.errors, []);
    } finally { await browser.close(); }
});

test("the room shows who is in its voice channel, under the call's own badge", { skip }, async () => {
    const browser = await launch(pw);
    try {
        const fake = new FakeSession();
        fake.voice = {
            available: true, joined: false, session: null, protection: "e2ee", fallback_by: [],
            participants: [person(BOB, 1), person(CAROL, 2)], slots: [],
        };
        const page = await openApp(browser, fake);
        await page.waitForSelector("#voice-channel:not([hidden]) .vc-person");
        const people = await page.$$eval("#vc-people .vc-person", (els) => els.map((e) => e.dataset.user));
        assert.deepStrictEqual(people, [BOB, CAROL]);
        assert.strictEqual(await page.textContent("#vc-badge"), "End-to-end");
        assert.ok(await page.isVisible("#vc-join"));
        await shoot(page, "voice-channel-e2ee");

        // Carol's client announces it cannot seal. The call's badge changes; the room's does
        // not; and it is said in the timeline, not only in the panel.
        fake.voice = {
            ...fake.voice, protection: "transport_only", fallback_by: [CAROL],
            participants: [person(BOB, 1), person(CAROL, 2, { media: "transport_only" })],
        };
        fake.events.push({ kind: "voice_media", user: CAROL, device: DEV(2), e2ee: false });
        await page.waitForFunction(() => document.getElementById("vc-badge").textContent === "Transport only");
        assert.strictEqual(await page.textContent("#room-tier"), "T2", "the room's tier badge must not move");
        assert.match(await page.getAttribute("#vc-badge", "class"), /warn/);
        const flags = await page.$$eval("#vc-people .vc-flag", (els) => els.map((e) => e.textContent));
        assert.ok(flags.includes("no E2EE media"), "the participant who caused it is marked");
        await shoot(page, "voice-channel-transport-only");
        assert.deepStrictEqual(page.errors, []);
    } finally { await browser.close(); }
});

test("a device the encrypted group does not contain is marked, not shown like the others", { skip }, async () => {
    const browser = await launch(pw);
    try {
        const fake = new FakeSession();
        fake.voice = {
            available: true, joined: false, session: null, protection: "e2ee", fallback_by: [],
            participants: [person(BOB, 1), person(CAROL, 3, { in_group: false, media: "unknown" })], slots: [],
        };
        const page = await openApp(browser, fake);
        await page.waitForSelector("#voice-channel:not([hidden]) .vc-person");
        const carol = await page.$eval(`#vc-people [data-user="${CAROL}"]`, (e) => e.textContent);
        assert.match(carol, /not in the encrypted group/);
        await shoot(page, "voice-channel-unlisted-device");
    } finally { await browser.close(); }
});
