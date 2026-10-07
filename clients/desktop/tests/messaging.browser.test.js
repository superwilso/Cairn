// The everyday-messaging UI, in a real browser, against a stand-in for the Rust session.
//
// ## Why this exists
//
// `crates/cairn-server/tests/*_session.rs` prove what `Session` decides — the timer the
// instance holds, which messages expire, what a reply points at. None of that touches the
// part a user looks at: whether the header shows the timer, whether an expired message
// actually leaves the screen, whether a notice appears at all. That is all in `ui/*.js` and
// `cargo test` cannot see a line of it.
//
// The page is the shipped `ui/` directory, served from `http://localhost` with the CSP from
// `tauri.conf.json`, and `window.__TAURI__.core.invoke` is answered by `FakeSession` below —
// which records every command, so a test can assert what the UI *asked Rust to do* rather
// than only what it drew. The fake decides nothing interesting: it hands back what a test
// told it to, because the deciding is Rust's and is tested there.
//
// Run: node --test clients/desktop/tests/messaging.browser.test.js
// Screenshots: set CAIRN_SCREENSHOT_DIR and each test leaves a PNG there.
//
// **Skipped when Playwright or its Chromium is not installed**, as call.browser.test.js is,
// and for the same reason; CAIRN_REQUIRE_BROWSER_TEST=1 turns the skip into a failure.

const test = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");

const UI = path.join(__dirname, "../ui");
const CONF = JSON.parse(
    fs.readFileSync(path.join(__dirname, "../src-tauri/tauri.conf.json"), "utf8")
);
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
    try {
        return await pw.chromium.launch();
    } catch (first) {
        const executablePath = findChromium();
        if (!executablePath) throw first;
        return await pw.chromium.launch({ executablePath });
    }
}

const ROOM = "rom_0a1b2c3d4e5f60718293a4b5c6d7e8f9";
const ME = "usr_a11ce000000000000000000000000000";
const BOB = "usr_b0b00000000000000000000000000000";
const CAROL = "usr_ca401000000000000000000000000000";

// Answers `invoke` the way `Session` would, from data a test sets up. Every call is logged.
class FakeSession {
    constructor() {
        this.calls = [];
        this.history = [];
        this.events = [];
        this.timer = null;
        this.handlers = {};
    }

    on(cmd, fn) { this.handlers[cmd] = fn; }

    async invoke(cmd, args) {
        this.calls.push([cmd, args || {}]);
        if (this.handlers[cmd]) return this.handlers[cmd](args || {});
        switch (cmd) {
            case "sign_in": return { user: ME, tls: true };
            case "publish_key_packages": return 5;
            case "rooms": return [{ id: ROOM, tier: "T2", e2ee: true, joined: true }];
            case "open_room": return this.history;
            case "open_room_tier": return "T2";
            case "members": return [
                { user: ME, role: "owner", in_group: true, verified: false },
                { user: BOB, role: "member", in_group: true, verified: true },
                { user: CAROL, role: "member", in_group: true, verified: false },
            ];
            case "poll": { const out = this.events; this.events = []; return out; }
            case "call_config": return { ice_servers: [], has_relay: false, max_participants: 6 };
            case "room_timer": return this.timer;
            case "set_room_timer": this.timer = args.ttlMs; return this.timer;
            default: throw new Error("FakeSession: unhandled command " + cmd);
        }
    }

    asked(cmd) { return this.calls.filter(([c]) => c === cmd).map(([, a]) => a); }
}

async function openApp(browser, fake) {
    const page = await browser.newPage({ viewport: { width: 1180, height: 760 } });
    const errors = [];
    page.on("pageerror", (e) => errors.push(e.message));
    page.on("console", (m) => { if (m.type() === "error") errors.push(m.text()); });
    await page.exposeFunction("__invoke", (cmd, args) => fake.invoke(cmd, args));
    await page.addInitScript(`
        window.__TAURI__ = { core: { invoke: (cmd, args) => window.__invoke(cmd, args) } };
    `);
    // Served with the app's real CSP, so an inline handler or a stray fetch fails here the
    // way it would in the shipped webview instead of passing in a permissive test page.
    await page.route("http://localhost/**", (route) => {
        const rel = new URL(route.request().url()).pathname.replace(/^\/+/, "") || "index.html";
        const file = path.join(UI, rel);
        if (!file.startsWith(UI) || !fs.existsSync(file)) return route.fulfill({ status: 404 });
        const type = { ".html": "text/html", ".js": "text/javascript", ".css": "text/css" }[
            path.extname(file)
        ] || "application/octet-stream";
        return route.fulfill({
            contentType: type,
            headers: { "content-security-policy": CONF.app.security.csp },
            body: fs.readFileSync(file),
        });
    });
    await page.goto("http://localhost/index.html");
    await page.click("#go");
    await page.waitForSelector("#rooms li");
    await page.click("#rooms li");
    await page.waitForFunction(() => document.getElementById("room-id").textContent !== "");
    page.errors = errors;
    return page;
}

// One poll's worth of events, then wait for the UI's own poll loop to collect them.
async function deliver(page, fake, events) {
    fake.events.push(...events);
    const deadline = Date.now() + 5000;
    while (fake.events.length > 0) {
        if (Date.now() > deadline) throw new Error("the UI never polled");
        await new Promise((r) => setTimeout(r, 50));
    }
    // The poll has been answered; give its handlers a moment to draw.
    await page.waitForTimeout(100);
}

async function shoot(page, name) {
    if (!SHOTS) return;
    fs.mkdirSync(SHOTS, { recursive: true });
    await page.screenshot({ path: path.join(SHOTS, name + ".png") });
}

function msg(sender, body, at, extra = {}) {
    return { sender, body, sent_at_ms: at, historic: true, ...extra };
}

const pw = playwright();
const REQUIRED = process.env.CAIRN_REQUIRE_BROWSER_TEST === "1";
if (!pw && REQUIRED) {
    throw new Error("CAIRN_REQUIRE_BROWSER_TEST=1 but playwright is not installed");
}
const skip = pw ? false : "playwright is not installed";

let browser = null;
test.before(async () => { if (pw) browser = await launch(pw); });
test.after(async () => { if (browser) await browser.close(); });

test("the header shows the timer the instance holds, not a default", { skip }, async () => {
    // A room someone else put on a one-week timer must not read "Off" here: a member who
    // believed it was off would write things they meant to keep.
    const fake = new FakeSession();
    fake.timer = 7 * 24 * 3600 * 1000;
    const page = await openApp(browser, fake);
    await page.waitForFunction(() => !document.getElementById("room-timer").disabled);
    assert.strictEqual(await page.$eval("#room-timer", (s) => s.value), String(fake.timer));
    assert.ok(await page.$eval("label.timer", (l) => l.classList.contains("on")));
    assert.deepStrictEqual(page.errors, []);
    await page.close();
});

test("a timer the presets do not cover still reads as a duration", { skip }, async () => {
    // The CLI takes seconds, so another member can set 90 s. Showing "Off", or nothing, for
    // a value the dropdown does not list would be the header lying about the room.
    const fake = new FakeSession();
    fake.timer = 90_000;
    const page = await openApp(browser, fake);
    await page.waitForFunction(() => !document.getElementById("room-timer").disabled);
    const shown = await page.$eval("#room-timer", (s) => s.selectedOptions[0].textContent);
    assert.strictEqual(shown, "90 seconds");
    await page.close();
});

test("choosing a timer asks Rust, then warns that it reaches back", { skip }, async () => {
    const fake = new FakeSession();
    fake.history = [msg(BOB, "said before the timer", 1_000)];
    const page = await openApp(browser, fake);
    await page.waitForFunction(() => !document.getElementById("room-timer").disabled);

    // The warning has to be visible before a value is picked, which means in the dropdown.
    const label = await page.$eval("#room-timer optgroup", (g) => g.label);
    assert.match(label, /older messages already sent/i);

    await page.selectOption("#room-timer", String(3_600_000));
    await page.waitForFunction(() =>
        [...document.querySelectorAll("#timeline .notice")].some((n) =>
            n.textContent.includes("1 hour"))
    );
    assert.deepStrictEqual(fake.asked("set_room_timer"), [{ ttlMs: 3_600_000 }]);
    const notice = await page.$$eval("#timeline .notice", (ns) => ns.map((n) => n.textContent));
    assert.ok(
        notice.some((t) => /including messages sent before now/.test(t)),
        "the notice must say the timer deleted what was already there: " + notice
    );
    await shoot(page, "timer-set");
    await page.close();
});

test("a change made by another member is announced and updates the header", { skip }, async () => {
    const fake = new FakeSession();
    const page = await openApp(browser, fake);
    await deliver(page, fake, [{ kind: "timer", ttl_ms: 300_000 }]);
    assert.strictEqual(await page.$eval("#room-timer", (s) => s.value), "300000");
    const notices = await page.$$eval("#timeline .notice", (ns) => ns.map((n) => n.textContent));
    assert.ok(notices.some((t) => t.includes("now 5 minutes")), notices.join(" | "));

    await deliver(page, fake, [{ kind: "timer", ttl_ms: null }]);
    assert.strictEqual(await page.$eval("#room-timer", (s) => s.value), "");
    await page.close();
});

test("an expired message leaves the screen, and a live one stays", { skip }, async () => {
    // Rust has already deleted it from disk by the time this event arrives. A message still
    // on screen after that has disappeared from everywhere but where its user is looking.
    const fake = new FakeSession();
    fake.timer = 300_000;
    fake.history = [msg(BOB, "old enough to go", 1_000), msg(BOB, "still alive", 9_000)];
    const page = await openApp(browser, fake);
    await page.waitForSelector("#timeline li.msg");
    await deliver(page, fake, [{ kind: "expired", before_ms: 5_000 }]);
    const left = await page.$$eval("#timeline li.msg", (ls) => ls.map((l) => l.textContent));
    assert.strictEqual(left.length, 1, "exactly the expired message must go: " + left);
    assert.match(left[0], /still alive/);
    await page.close();
});
