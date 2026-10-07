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
            case "send": return view(ME, args.text, { id: nextId() });
            // The quote is whatever a test put in `resolved`, deliberately unlike anything on
            // screen: the UI must show the quote Rust resolved, not build its own.
            case "reply": return view(ME, args.text, {
                id: nextId(),
                reply_to: { sender: args.sender, id: args.id, snippet: this.resolved, sent_at_ms: 1_000 },
            });
            case "react": return args.emoji ? [{ emoji: args.emoji, by: [ME] }] : [];
            case "search": return this.found || { hits: [], unsearched: [] };
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
    return { sender, body, sent_at_ms: at, historic: true, id: null, reply_to: null, reactions: [], ...extra };
}

let idCounter = 0;
const nextId = () => (++idCounter).toString(16).padStart(64, "0");
const ID1 = "a1".repeat(32);
const ID2 = "b2".repeat(32);
const HEART = "\u2764\uFE0F";

function view(sender, body, extra = {}) {
    return msg(sender, body, Date.now(), { historic: false, ...extra });
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

// ---- replies and reactions --------------------------------------------------

test("hovering a message offers a reaction, and the chip shows what Rust returned", { skip }, async () => {
    const fake = new FakeSession();
    fake.history = [msg(BOB, "ship it", 1_000, { id: ID1 })];
    const page = await openApp(browser, fake);
    const li = await page.waitForSelector("#timeline li.msg");

    assert.ok(!(await page.isVisible("#timeline .actions")), "the buttons wait for a hover");
    await li.hover();
    assert.ok(await page.isVisible("#timeline .actions .act-react"));
    await page.click("#timeline .act-react");
    assert.ok(await page.isVisible("#react-picker"), "the picker opens");
    await shoot(page, "react-picker");
    await page.click("#react-picker button >> nth=0");

    await page.waitForSelector("#timeline .reactions .chip.mine");
    assert.ok(!(await page.isVisible("#react-picker")), "and closes once used");
    assert.deepStrictEqual(fake.asked("react"), [{ sender: BOB, id: ID1, emoji: HEART }]);

    // Clicking your own chip takes it back.
    await page.click("#timeline .reactions .chip.mine");
    await page.waitForFunction(() => !document.querySelector("#timeline .reactions .chip"));
    assert.deepStrictEqual(fake.asked("react")[1], { sender: BOB, id: ID1, emoji: null });
    assert.deepStrictEqual(page.errors, []);
    await page.close();
});

test("double-clicking a message sends a heart", { skip }, async () => {
    const fake = new FakeSession();
    fake.history = [msg(BOB, "we got the grant", 1_000, { id: ID1 })];
    const page = await openApp(browser, fake);
    await page.dblclick("#timeline li.msg .body");
    await page.waitForSelector("#timeline .reactions .chip.mine");
    assert.deepStrictEqual(fake.asked("react"), [{ sender: BOB, id: ID1, emoji: HEART }]);
    const selected = await page.evaluate(() => String(window.getSelection()));
    assert.strictEqual(selected, "", "the double-click must not also select a word");
    await page.close();
});

test("a reply sends a reference and shows the quote Rust resolved", { skip }, async () => {
    const fake = new FakeSession();
    fake.history = [msg(BOB, "lunch at noon?", 1_000, { id: ID1 })];
    fake.resolved = "as resolved by rust";
    const page = await openApp(browser, fake);
    assert.ok(!(await page.isVisible("#reply-bar")), "no reply bar until asked for");

    await (await page.$("#timeline li.msg")).hover();
    await page.click("#timeline .act-reply");
    assert.ok(await page.isVisible("#reply-bar"));
    assert.strictEqual(await page.textContent("#reply-bar .reply-text"), "lunch at noon?");
    await shoot(page, "reply-composing");

    await page.fill("#text", "yes, see you there");
    await page.press("#text", "Enter");
    await page.waitForSelector("#timeline li.msg.mine .quote");

    assert.deepStrictEqual(fake.asked("reply"), [{ text: "yes, see you there", sender: BOB, id: ID1 }]);
    assert.deepStrictEqual(fake.asked("send"), [], "a reply is not also sent as a plain message");
    assert.strictEqual(
        await page.textContent("#timeline li.msg.mine .quote-text"),
        "as resolved by rust",
        "the quote must be Rust's, not one built from the screen"
    );
    assert.ok(!(await page.isVisible("#reply-bar")), "the bar closes once sent");
    await shoot(page, "reply-sent");
    await page.close();
});

test("escape abandons a reply, and the next message is an ordinary one", { skip }, async () => {
    const fake = new FakeSession();
    fake.history = [msg(BOB, "hm", 1_000, { id: ID1 })];
    const page = await openApp(browser, fake);
    await (await page.$("#timeline li.msg")).hover();
    await page.click("#timeline .act-reply");
    await page.press("#text", "Escape");
    assert.ok(!(await page.isVisible("#reply-bar")));
    await page.fill("#text", "never mind");
    await page.press("#text", "Enter");
    // Also the first time the sender's own message appears without reopening the room.
    await page.waitForSelector("#timeline li.msg.mine");
    assert.deepStrictEqual(fake.asked("reply"), []);
    assert.deepStrictEqual(fake.asked("send"), [{ text: "never mind" }]);
    await page.close();
});

test("swiping a message right on a touch screen starts a reply", { skip }, async () => {
    const fake = new FakeSession();
    fake.history = [msg(BOB, "swipe me", 1_000, { id: ID1 })];
    const page = await openApp(browser, fake);
    await page.$eval("#timeline li.msg", (li) => {
        const r = li.getBoundingClientRect();
        const at = (type, dx) => li.dispatchEvent(new PointerEvent(type, {
            pointerType: "touch", bubbles: true, clientX: r.left + 20 + dx, clientY: r.top + 5,
        }));
        at("pointerdown", 0);
        at("pointermove", 40);
        at("pointermove", 80);
        at("pointerup", 80);
    });
    assert.ok(await page.isVisible("#reply-bar"));
    assert.strictEqual(await page.textContent("#reply-bar .reply-text"), "swipe me");
    await page.close();
});

test("someone else's reaction is drawn, and an expired original blanks its quote", { skip }, async () => {
    const fake = new FakeSession();
    fake.history = [
        msg(BOB, "the original", 1_000, { id: ID1 }),
        msg(ME, "the reply", 9_000, {
            id: ID2,
            reply_to: { sender: BOB, id: ID1, snippet: "the original", sent_at_ms: 1_000 },
        }),
    ];
    const page = await openApp(browser, fake);
    await page.waitForSelector("#timeline .quote:not(.gone)");

    await deliver(page, fake, [{ kind: "reactions", sender: ME, id: ID2, reactions: [{ emoji: "\u{1F602}", by: [BOB, CAROL] }] }]);
    const chip = await page.$eval("#timeline .chip", (c) => ({ text: c.textContent, mine: c.classList.contains("mine") }));
    assert.deepStrictEqual(chip, { text: "\u{1F602} 2", mine: false });

    // Rust has forgotten the original; a quote still showing its words would be the one
    // place on this device a disappeared message survived.
    await deliver(page, fake, [{ kind: "expired", before_ms: 5_000 }]);
    const quote = await page.$eval("#timeline .quote", (q) => ({ gone: q.classList.contains("gone"), text: q.textContent }));
    assert.ok(quote.gone, "the quote must be marked unavailable");
    assert.ok(!quote.text.includes("the original"), quote.text);
    assert.strictEqual(await page.$$eval("#timeline li.msg", (l) => l.length), 1);
    await page.close();
});

test("a quote this device cannot resolve says so instead of showing anything", { skip }, async () => {
    const fake = new FakeSession();
    fake.history = [msg(BOB, "re: something", 9_000, {
        id: ID2, reply_to: { sender: CAROL, id: ID1, snippet: null, sent_at_ms: null },
    })];
    const page = await openApp(browser, fake);
    const text = await page.textContent("#timeline .quote.gone .quote-text");
    assert.strictEqual(text, "Original message unavailable");
    await page.close();
});

// ---- search -----------------------------------------------------------------

function hit(extra = {}) {
    return {
        room: ROOM, sender: BOB, sent_at_ms: 1_000, id: ID1,
        before: "so ", matched: "Quarterly numbers", after: " are in", ...extra,
    };
}

test("search asks Rust, marks the match Rust returned, and jumps to it", { skip }, async () => {
    const fake = new FakeSession();
    fake.history = [msg(BOB, "so Quarterly numbers are in", 1_000, { id: ID1 })];
    fake.found = { hits: [hit()], unsearched: [] };
    const page = await openApp(browser, fake);
    await page.fill("#search", "quarterly");
    await page.waitForSelector("#search-hits li");

    assert.deepStrictEqual(fake.asked("search").at(-1), { query: "quarterly" });
    assert.strictEqual(await page.textContent("#search-hits mark"), "Quarterly numbers");
    assert.ok(!(await page.isVisible("#rooms")), "results replace the room list");
    assert.match(await page.textContent("#search-note"), /never sent to the instance/);
    await shoot(page, "search");

    await page.click("#search-hits li");
    await page.waitForSelector("#timeline li.msg.flash");
    assert.strictEqual(await page.$eval("#timeline li.msg.flash", (l) => l.dataset.id), ID1);
    assert.deepStrictEqual(page.errors, []);
    await page.close();
});

test("a hit's text is drawn as text, not markup", { skip }, async () => {
    const fake = new FakeSession();
    fake.found = { hits: [hit({ before: "<img src=x onerror=alert(1)>", matched: "<b>x</b>" })], unsearched: [] };
    const page = await openApp(browser, fake);
    await page.fill("#search", "x");
    await page.waitForSelector("#search-hits li");
    assert.strictEqual(await page.$$eval("#search-hits img, #search-hits b", (n) => n.length), 0);
    assert.strictEqual(await page.textContent("#search-hits mark"), "<b>x</b>");
    await page.close();
});

test("rooms that could not be searched are named, and clearing restores the list", { skip }, async () => {
    const fake = new FakeSession();
    fake.found = { hits: [], unsearched: [ROOM] };
    const page = await openApp(browser, fake);
    await page.fill("#search", "anything");
    await page.waitForFunction(() => document.getElementById("search-note").textContent !== "");
    const note = await page.textContent("#search-note");
    assert.match(note, /No messages found/);
    assert.match(note, /1 room was not searched/, "a skipped room must not read as 'never said there'");

    await page.press("#search", "Escape");
    assert.ok(await page.isVisible("#rooms"));
    assert.ok(!(await page.isVisible("#search-results")));
    await page.close();
});
