// The safety-number panel, run as the real UI in a real Chromium with the Rust side stubbed.
//
// ## What this can and cannot prove
//
// Every security decision behind the panel is in Rust (`cairn_client_core::verify`) and
// tested there: where the number comes from, whether a changed key is flagged, whether a
// number that changed on screen can be verified. A stub cannot test any of that — it agrees
// with whatever it is told.
//
// What it *can* prove is the part only the page decides, and each of these is a way the
// panel could quietly undo the Rust side:
//
// - the button hands back the **exact** number Rust supplied, never one the page computed;
// - a refusal from Rust is shown, and the panel does not then claim the contact is verified;
// - the "key changed" warning is on screen when Rust says so, and absent when it does not;
// - someone with no key in the group is not offered a number at all.
//
// Run: node --test clients/desktop/tests/safety.browser.test.js
// Skipped, with a note, when Playwright or its Chromium is missing — unless
// CAIRN_REQUIRE_BROWSER_TEST=1, as in CI, where a skip would be a pass for the wrong reason.

const test = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");

const UI = path.join(__dirname, "../ui");

function playwright() {
    for (const base of [null, "/opt/node22/lib/node_modules", "/usr/lib/node_modules"]) {
        try {
            return require(base ? path.join(base, "playwright") : "playwright");
        } catch (_) { /* try the next */ }
    }
    return null;
}

// Same fallback as call.browser.test.js: this container's Chromium lives at /opt/pw-browsers.
async function launch(pw) {
    try {
        return await pw.chromium.launch();
    } catch (first) {
        const root = process.env.PLAYWRIGHT_BROWSERS_PATH || "/opt/pw-browsers";
        const dir = fs.existsSync(root)
            ? fs.readdirSync(root).map((d) => path.join(root, d, "chrome-linux", "chrome"))
                .find((exe) => fs.existsSync(exe))
            : null;
        if (!dir) throw first;
        return await pw.chromium.launch({ executablePath: dir });
    }
}

const ME = "usr_" + "a".repeat(32);
const BOB = "usr_" + "b".repeat(32);
const CAROL = "usr_" + "c".repeat(32);
const DAVE = "usr_" + "e".repeat(32);
const ROOM = "rom_" + "1".repeat(32);
const BOB_DEVICE = "dev_" + "d".repeat(32);
// Deliberately not a real safety number: if the page ever derived one itself, it could not
// produce this string, and the assertion on what it hands back would fail.
const NUMBER = "11111 22222 33333 44444 55555 66666 77777 88888 99999 00000 12345 67890";

// The fake Rust side. Runs inside the page; records every call so the test can check what
// the UI sent, not just what it drew.
function fakeBackend({ me, bob, carol, dave, room, device, number, initialState, refuseVerify }) {
    let state = initialState;
    window.__calls = [];
    const view = () => [{ user: bob, device, number, state }];
    const handlers = {
        sign_in: () => ({ user: me, tls: true }),
        publish_key_packages: () => 5,
        rooms: () => [{ id: room, tier: "T2", e2ee: true, joined: true }],
        open_room: () => [],
        open_room_tier: () => "T2",
        poll: () => [],
        call_config: () => ({ ice_servers: [], has_relay: true, max_participants: 6 }),
        members: () => [
            { user: me, role: "owner", in_group: true, verified: false, key_changed: false },
            {
                user: bob, role: "member", in_group: true,
                verified: state === "Verified", key_changed: state === "ChangedSinceVerified",
            },
            { user: carol, role: "member", in_group: false, verified: false, key_changed: false },
            // In the group's roster, left off the instance's list: Rust reports them anyway.
            { user: dave, role: "unlisted", in_group: true, verified: false, key_changed: false },
        ],
        safety_numbers: (args) => (args.user === bob ? view() : []),
        mark_verified: (args) => {
            if (refuseVerify) {
                throw "the safety number changed since it was shown — compare the new one " +
                    "before verifying";
            }
            if (args.number !== number) throw "stub: wrong number handed back";
            state = "Verified";
            return view();
        },
    };
    window.__TAURI__ = {
        core: {
            invoke: async (cmd, args) => {
                window.__calls.push([cmd, args || {}]);
                const handler = handlers[cmd];
                if (!handler) throw "stub: unexpected command " + cmd;
                return handler(args || {});
            },
        },
    };
}

async function openApp(browser, options) {
    const page = await browser.newPage({ viewport: { width: 1180, height: 760 } });
    const errors = [];
    page.on("pageerror", (e) => errors.push(e.message));

    // Served from http://localhost rather than file://, which is a secure context — the same
    // reason the call test does it, and what `getUserMedia` in call.js expects.
    await page.route("http://localhost/**", (route) => {
        const name = new URL(route.request().url()).pathname.replace(/^\//, "") || "index.html";
        const file = path.join(UI, path.basename(name));
        if (!fs.existsSync(file)) return route.fulfill({ status: 404, body: "" });
        const type = { ".html": "text/html", ".js": "text/javascript", ".css": "text/css" };
        return route.fulfill({
            contentType: type[path.extname(file)] || "application/octet-stream",
            body: fs.readFileSync(file),
        });
    });
    await page.addInitScript(fakeBackend, {
        me: ME, bob: BOB, carol: CAROL, dave: DAVE, room: ROOM, device: BOB_DEVICE, number: NUMBER,
        ...options,
    });
    await page.goto("http://localhost/index.html");
    await page.click("#go");
    await page.waitForSelector("#app:not([hidden])");
    await page.click("#rooms li");
    await page.waitForSelector("#member-list li.openable");
    page.errors = errors;
    return page;
}

async function shoot(page, name) {
    const dir = process.env.CAIRN_SCREENSHOT_DIR;
    if (dir) await page.screenshot({ path: path.join(dir, name + ".png") });
}

async function openBob(page) {
    const rows = page.locator("#member-list li");
    await rows.filter({ hasText: BOB.slice(4, 12) }).click();
    await page.waitForSelector("#safety:not([hidden])");
}

const pw = playwright();
const REQUIRED = process.env.CAIRN_REQUIRE_BROWSER_TEST === "1";
if (!pw && REQUIRED) {
    throw new Error("CAIRN_REQUIRE_BROWSER_TEST=1 but playwright is not installed");
}
const skip = pw ? false : "playwright is not installed";

test("the number shown is the one Rust supplied, and the same string goes back", { skip }, async () => {
    const browser = await launch(pw);
    try {
        const page = await openApp(browser, { initialState: "Unverified" });
        await openBob(page);
        await shoot(page, "safety-unverified");

        const groups = await page.locator("#safety-devices .digits span").allTextContents();
        assert.deepStrictEqual(groups, NUMBER.split(" "), "all twelve groups, in order");
        assert.ok(await page.locator("#safety-changed").isHidden(), "no alarm when nothing changed");
        assert.match(await page.locator("#safety-how").textContent(), /in person/);

        await page.click("#safety-devices button.primary");
        await page.waitForSelector("#safety-devices .badge.ok");
        await shoot(page, "safety-verified");

        const sent = await page.evaluate(() => window.__calls.filter(([c]) => c === "mark_verified"));
        assert.deepStrictEqual(
            sent.map(([, args]) => args),
            [{ user: BOB, device: BOB_DEVICE, number: NUMBER }],
            "the UI must hand back exactly what it was shown, and nothing it computed"
        );
        assert.strictEqual(await page.locator("#safety-devices button.primary").count(), 0);
        assert.ok(await page.locator("#member-list .tick").count() === 1, "the tick appears");
        assert.deepStrictEqual(page.errors, []);
    } finally {
        await browser.close();
    }
});

test("a refusal is shown, and the contact is not then drawn as verified", { skip }, async () => {
    const browser = await launch(pw);
    try {
        const page = await openApp(browser, { initialState: "Unverified", refuseVerify: true });
        await openBob(page);
        await page.click("#safety-devices button.primary");
        await page.waitForFunction(() => document.getElementById("safety-error").textContent);
        await shoot(page, "safety-refused");

        assert.match(await page.locator("#safety-error").textContent(), /changed since it was shown/);
        assert.strictEqual(await page.locator("#safety-devices .badge.ok").count(), 0);
        assert.strictEqual(await page.locator("#member-list .tick").count(), 0);
        assert.deepStrictEqual(page.errors, []);
    } finally {
        await browser.close();
    }
});

test("a key changed since verification is impossible to miss", { skip }, async () => {
    const browser = await launch(pw);
    try {
        const page = await openApp(browser, { initialState: "ChangedSinceVerified" });
        assert.strictEqual(
            await page.locator("#member-list .badge.bad").count(), 1,
            "flagged in the member list before anyone opens anything"
        );
        await openBob(page);
        await shoot(page, "safety-changed");

        assert.ok(await page.locator("#safety-changed").isVisible());
        assert.match(
            await page.locator("#safety-devices button.primary").textContent(),
            /verify again/
        );
        assert.deepStrictEqual(page.errors, []);
    } finally {
        await browser.close();
    }
});

test("someone with no key in the group is not offered a number", { skip }, async () => {
    const browser = await launch(pw);
    try {
        const page = await openApp(browser, { initialState: "Unverified" });
        const carol = page.locator("#member-list li.pending");
        assert.strictEqual(await carol.count(), 1);
        await carol.click();
        assert.ok(await page.locator("#safety").isHidden(), "a waiting member has nothing to compare");
        const asked = await page.evaluate(() => window.__calls.filter(([c]) => c === "safety_numbers"));
        assert.deepStrictEqual(asked, []);
    } finally {
        await browser.close();
    }
});

test("a group member the instance did not list is shown, and flagged", { skip }, async () => {
    const browser = await launch(pw);
    try {
        const page = await openApp(browser, { initialState: "Unverified" });
        const dave = page.locator("#member-list li").filter({ hasText: DAVE.slice(4, 12) });
        assert.strictEqual(await dave.count(), 1, "they can read the room, so they are listed");
        assert.strictEqual(await dave.locator(".badge.warn").textContent(), "unlisted");
        assert.ok(await dave.evaluate((li) => li.classList.contains("openable")));
        await shoot(page, "members-unlisted");
    } finally {
        await browser.close();
    }
});
