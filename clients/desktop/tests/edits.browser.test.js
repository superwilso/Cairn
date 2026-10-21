// Replies, edits and delete-for-everyone in the real UI, against a stand-in for the Rust
// session.
//
// ## What this checks, and what it does not
//
// Rust decides everything that matters here — who may edit or delete which message
// (`can_edit`, `can_delete`), what an edited message now says and what it said before, what
// a reply quotes after its original changes — and `crates/cairn-server/tests/edits_session.rs`
// attacks those decisions against a real instance and a hostile member. None of that reaches
// the part a user looks at: whether the buttons appear only where Rust allowed them, whether
// "(edited)" is shown and opens the history, whether the delete warning says what delete
// actually is, and whether every quote follows the edit. That is `ui/messages.js`, and
// `cargo test` cannot see it.
//
// The page is the shipped `ui/` directory served from `http://localhost` with the CSP from
// `tauri.conf.json`; `invoke` is answered by `FakeSession`, which logs every command so a test
// can assert what the UI asked Rust to do.
//
// Run: node --test clients/desktop/tests/edits.browser.test.js
// Screenshots: set CAIRN_SCREENSHOT_DIR and each test leaves a PNG there.
//
// **Skipped when Playwright or its Chromium is not installed**; CAIRN_REQUIRE_BROWSER_TEST=1
// turns the skip into a failure.

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
const ID_MINE = "a1".repeat(32);
const ID_BOB = "b2".repeat(32);
const ID_REPLY = "c3".repeat(32);
const T0 = Date.UTC(2026, 9, 20, 9, 14);

function msg(sender, body, at, extra = {}) {
    return {
        sender, body, sent_at_ms: at, historic: true, id: null, reply_to: null, reactions: [],
        edited_at_ms: null, revisions: [], deleted: false, can_edit: false, can_delete: false,
        ...extra,
    };
}

// Rust's answer to an edit or delete: the message as it now stands, and its quote. The fake
// builds it from what a test set up; the rules that produce it are tested in cargo.
function revised(message, quote) { return { message, quote }; }

class FakeSession {
    constructor() {
        this.calls = [];
        this.history = [];
        this.events = [];
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
            ];
            case "poll": { const out = this.events; this.events = []; return out; }
            case "call_config": return { ice_servers: [], has_relay: false, max_participants: 6 };
            case "room_timer": return null;
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

async function deliver(page, fake, events) {
    fake.events.push(...events);
    const deadline = Date.now() + 5000;
    while (fake.events.length > 0) {
        if (Date.now() > deadline) throw new Error("the UI never polled");
        await new Promise((r) => setTimeout(r, 50));
    }
    await page.waitForTimeout(150);
}

async function shoot(page, name) {
    if (!SHOTS) return;
    fs.mkdirSync(SHOTS, { recursive: true });
    await page.screenshot({ path: path.join(SHOTS, name + ".png") });
}

const li = (id) => `#timeline li.msg[data-id="${id}"]`;

// A short conversation: bob asks, alice (this user) answers, bob replies to the answer.
function conversation() {
    return [
        msg(BOB, "Are we still on for the station at six?", T0, { id: ID_BOB }),
        msg(ME, "Yes, see you at the station", T0 + 60_000, {
            id: ID_MINE, can_edit: true, can_delete: true,
        }),
        msg(BOB, "Great, I'll bring the maps", T0 + 120_000, {
            id: ID_REPLY,
            reply_to: { sender: ME, id: ID_MINE, snippet: "Yes, see you at the station", sent_at_ms: T0 + 60_000 },
        }),
    ];
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

test("edit and delete are offered only where Rust allowed them", { skip }, async () => {
    const fake = new FakeSession();
    fake.history = conversation();
    const page = await openApp(browser, fake);
    await page.hover(li(ID_MINE));
    assert.ok(await page.isVisible(li(ID_MINE) + " .act-edit"));
    assert.ok(await page.isVisible(li(ID_MINE) + " .act-delete"));
    await shoot(page, "actions-own-message");
    await page.hover(li(ID_BOB));
    assert.ok(await page.isVisible(li(ID_BOB) + " .act-reply"), "anyone's message can be answered");
    assert.strictEqual(await page.$(li(ID_BOB) + " .act-edit"), null, "but not edited by someone else");
    assert.strictEqual(await page.$(li(ID_BOB) + " .act-delete"), null);
    assert.deepStrictEqual(page.errors, []);
    await page.close();
});

test("a reply's quote jumps to the original", { skip }, async () => {
    const fake = new FakeSession();
    fake.history = conversation();
    const page = await openApp(browser, fake);
    await page.click(li(ID_REPLY) + " .quote");
    await page.waitForSelector(li(ID_MINE) + ".flash");
    await page.close();
});

test("editing asks Rust, and shows Rust's text, the marker and the history", { skip }, async () => {
    const fake = new FakeSession();
    fake.history = conversation();
    const edited = msg(ME, "Yes, see you at the library instead", T0 + 60_000, {
        id: ID_MINE, can_edit: true, can_delete: true, edited_at_ms: T0 + 300_000,
        revisions: [{ body: "Yes, see you at the station", at_ms: T0 + 60_000 }],
    });
    fake.on("edit_message", () => revised(edited, {
        sender: ME, id: ID_MINE, snippet: "Yes, see you at the library instead",
        sent_at_ms: T0 + 60_000, deleted: false, edited: true,
    }));
    const page = await openApp(browser, fake);
    await page.hover(li(ID_MINE));
    await page.click(li(ID_MINE) + " .act-edit");
    const box = li(ID_MINE) + " .edit-input";
    assert.strictEqual(await page.inputValue(box), "Yes, see you at the station", "starts from the text");
    await page.fill(box, "Yes, see you at the library instead");
    await shoot(page, "editing");
    await page.press(box, "Enter");
    await page.waitForSelector(li(ID_MINE) + " .edited");

    assert.deepStrictEqual(fake.asked("edit_message"), [{ id: ID_MINE, text: "Yes, see you at the library instead" }]);
    assert.strictEqual(await page.textContent(li(ID_MINE) + " .content > .body"), "Yes, see you at the library instead");
    assert.strictEqual(await page.$(li(ID_MINE) + " .edit-box"), null, "the editor closes");
    // The reply's quote follows the edit, with what Rust resolved — not the text on screen.
    assert.strictEqual(
        await page.textContent(li(ID_REPLY) + " .quote-text"),
        "Yes, see you at the library instead (edited)"
    );
    // The avatar and time are the original message's; an edit is not a new message.
    assert.strictEqual(await page.$$eval("#timeline li.msg", (l) => l.length), 3);
    assert.ok(await page.$(li(ID_MINE) + " .avatar"));

    assert.ok(!(await page.isVisible(li(ID_MINE) + " .revisions")), "history waits to be asked for");
    await page.click(li(ID_MINE) + " .edited");
    assert.ok(await page.isVisible(li(ID_MINE) + " .revisions"));
    assert.match(await page.textContent(li(ID_MINE) + " .revisions"), /see you at the station/);
    await shoot(page, "edited-with-history");
    assert.deepStrictEqual(page.errors, []);
    await page.close();
});

test("escape abandons an edit and sends nothing", { skip }, async () => {
    const fake = new FakeSession();
    fake.history = conversation();
    const page = await openApp(browser, fake);
    await page.hover(li(ID_MINE));
    await page.click(li(ID_MINE) + " .act-edit");
    await page.fill(li(ID_MINE) + " .edit-input", "never mind");
    await page.press(li(ID_MINE) + " .edit-input", "Escape");
    assert.strictEqual(await page.$(li(ID_MINE) + " .edit-box"), null);
    assert.strictEqual(await page.textContent(li(ID_MINE) + " .content > .body"), "Yes, see you at the station");
    assert.deepStrictEqual(fake.asked("edit_message"), []);
    await page.close();
});

test("delete says what it is before it happens, and keeps nothing on screen", { skip }, async () => {
    const fake = new FakeSession();
    fake.history = conversation();
    fake.on("delete_message", () => revised(
        msg(ME, "", T0 + 60_000, { id: ID_MINE, deleted: true }),
        { sender: ME, id: ID_MINE, snippet: null, sent_at_ms: T0 + 60_000, deleted: true, edited: false },
    ));
    const page = await openApp(browser, fake);
    await page.hover(li(ID_MINE));
    await page.click(li(ID_MINE) + " .act-delete");
    const warning = await page.textContent(li(ID_MINE) + " .delete-confirm");
    // Never a promise the protocol cannot keep: it is a request honest clients honour.
    assert.match(warning, /honest/i);
    assert.match(warning, /modified client/i);
    assert.doesNotMatch(warning, /permanently|guarantee|cannot be recovered/i);
    await shoot(page, "delete-confirm");

    await page.click(li(ID_MINE) + " .delete-confirm button.ghost");
    assert.deepStrictEqual(fake.asked("delete_message"), [], "keeping it sends nothing");
    assert.strictEqual(await page.$(li(ID_MINE) + " .delete-confirm"), null);

    await page.hover(li(ID_MINE));
    await page.click(li(ID_MINE) + " .act-delete");
    await page.click(li(ID_MINE) + " .delete-confirm button.danger");
    await page.waitForSelector(li(ID_MINE) + ".deleted");
    assert.deepStrictEqual(fake.asked("delete_message"), [{ id: ID_MINE }]);
    const shown = await page.textContent(li(ID_MINE));
    assert.ok(!shown.includes("see you at the station"), shown);
    assert.match(shown, /You deleted this message/);
    assert.strictEqual(await page.$(li(ID_MINE) + " .actions"), null, "nothing left to act on");
    assert.strictEqual(
        await page.textContent(li(ID_REPLY) + " .quote-text"),
        "Original message was deleted"
    );
    await shoot(page, "deleted");
    assert.deepStrictEqual(page.errors, []);
    await page.close();
});

test("another member's edit and delete arrive as updates and redraw in place", { skip }, async () => {
    const fake = new FakeSession();
    fake.history = [
        msg(BOB, "Meet at the station", T0, { id: ID_BOB }),
        msg(ME, "On my way", T0 + 60_000, {
            id: ID_MINE, can_edit: true, can_delete: true,
            reply_to: { sender: BOB, id: ID_BOB, snippet: "Meet at the station", sent_at_ms: T0 },
        }),
    ];
    const page = await openApp(browser, fake);
    await deliver(page, fake, [{
        kind: "updated",
        message: msg(BOB, "Meet at the library", T0, {
            id: ID_BOB, historic: false, edited_at_ms: T0 + 90_000,
            revisions: [{ body: "Meet at the station", at_ms: T0 }],
        }),
        quote: { sender: BOB, id: ID_BOB, snippet: "Meet at the library", sent_at_ms: T0, deleted: false, edited: true },
    }]);
    assert.strictEqual(await page.textContent(li(ID_BOB) + " .content > .body"), "Meet at the library");
    assert.ok(await page.$(li(ID_BOB) + " .edited"));
    assert.strictEqual(await page.$(li(ID_BOB) + " .act-edit"), null, "still not ours to edit");
    assert.strictEqual(await page.textContent(li(ID_MINE) + " .quote-text"), "Meet at the library (edited)");
    await shoot(page, "edited-by-someone-else");

    await deliver(page, fake, [{
        kind: "updated",
        message: msg(BOB, "", T0, { id: ID_BOB, historic: false, deleted: true }),
        quote: { sender: BOB, id: ID_BOB, snippet: null, sent_at_ms: T0, deleted: true, edited: false },
    }]);
    assert.match(await page.textContent(li(ID_BOB)), /Message deleted/);
    assert.ok(!(await page.textContent(li(ID_BOB))).includes("library"));
    assert.ok(await page.$(li(ID_MINE) + " .quote.gone.deleted"));
    assert.deepStrictEqual(page.errors, []);
    await page.close();
});
