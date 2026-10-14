// Appearance settings, in the real UI, in a real browser.
//
// ## Why this exists
//
// settings.js is the one part of the client that is *meant* to change how everything looks,
// which makes it the one part that could change how the encryption badge looks.
// docs/13-customisation.md §5 says a theme must never be able to do that. This file checks
// both halves: that customisation actually works (themes, accent, custom CSS, export and
// import survive a reload), and that none of it reaches the security indicators — including
// the attacks that do not go through the badge directly.
//
// The page is the shipped `ui/` directory, served from http://localhost with the CSP from
// tauri.conf.json, and `window.__TAURI__.core.invoke` answers from a fixed stand-in.
//
// Run: node --test clients/desktop/tests/settings.browser.test.js
// Skipped when Playwright or its Chromium is missing; CAIRN_REQUIRE_BROWSER_TEST=1 turns the
// skip into a failure, as for the other browser tests.

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
    ".svg": "image/svg+xml", ".woff2": "font/woff2",
};

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

// The stand-in for Rust. One end-to-end room (T1), one that is not (T3), and a member who is
// in the room but not the encrypted group, so every kind of indicator is on screen.
function stub() {
    const ME = "usr_me000000";
    const answers = {
        sign_in: () => ({ user: ME, tls: false }),
        rooms: () => [
            { id: "rom_secret00", e2ee: true, tier: "T1", joined: true },
            { id: "rom_public00", e2ee: false, tier: "T3", joined: true },
        ],
        open_room: () => [
            { sender: "usr_alice000", body: "hello from alice", sent_at_ms: Date.UTC(2026, 0, 1, 15, 4), historic: false,
              id: "a1".repeat(32), reply_to: null, reactions: [] },
        ],
        open_room_tier: () => "T1",
        room_timer: () => null,
        members: () => [
            { user: ME, role: "owner", in_group: true, verified: false, key_changed: false },
            { user: "usr_carol000", role: "member", in_group: false, verified: false, key_changed: false },
        ],
        poll: () => [],
        call_config: () => ({ ice_servers: [], has_relay: false, max_participants: 8 }),
        attachment_limits: () => ({ max_bytes: 1 << 20 }),
    };
    window.__TAURI__ = { core: { invoke: async (cmd, args) => (answers[cmd] ? answers[cmd](args) : null) } };
}

async function openPage(browser) {
    const page = await browser.newPage({ viewport: { width: 1100, height: 750 } });
    page.setDefaultTimeout(10000);
    const errors = [];
    page.on("pageerror", (e) => errors.push(e.message));
    page.on("console", (m) => { if (m.type() === "error") errors.push(m.text()); });
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
    await page.addInitScript(stub);
    await page.goto("http://localhost/index.html");
    page.errors = errors;
    return page;
}

async function signIn(page) {
    await page.click("#go");
    await page.waitForSelector("#rooms li");
    await page.click("#rooms li >> nth=0");
    await page.waitForSelector("#timeline li.msg");
    await page.waitForFunction(() => document.getElementById("room-tier").textContent === "T1");
}

async function reload(page) {
    await page.reload();
    await signIn(page);
}

const cssVar = (page, name) =>
    page.evaluate((n) => getComputedStyle(document.documentElement).getPropertyValue(n).trim(), name);

// What the security layer paints an end-to-end badge, whatever the theme.
const E2EE_BG = "rgb(29, 107, 67)";

async function badge(page, selector) {
    return page.$eval(selector, (b) => {
        const cs = getComputedStyle(b);
        const r = b.getBoundingClientRect();
        return {
            visible: b.checkVisibility({ opacityProperty: true, visibilityProperty: true }),
            display: cs.display,
            bg: cs.backgroundColor,
            width: r.width,
        };
    });
}

async function applyCss(page, css) {
    await page.click("#open-settings");
    await page.fill("#set-css", css);
    await page.click("#set-css-apply");
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

test("choosing a theme repaints the app and survives a reload", { skip }, async () => {
    const page = await openPage(browser);
    await signIn(page);
    assert.strictEqual(await page.getAttribute("html", "data-theme"), "slate", "the signature theme is the default");
    const before = await cssVar(page, "--bg");

    await page.click("#open-settings");
    await page.click('.theme-card[data-pick="fieldbook"]');
    assert.strictEqual(await page.getAttribute("html", "data-theme"), "fieldbook");
    const after = await cssVar(page, "--bg");
    assert.notStrictEqual(after, before, "--bg must change with the theme");
    const body = await page.$eval("main", (m) => getComputedStyle(m).backgroundColor);
    assert.strictEqual(body, "rgb(239, 232, 215)", "and the page must actually be painted with it");

    await reload(page);
    assert.strictEqual(await page.getAttribute("html", "data-theme"), "fieldbook", "the choice persists");
    assert.deepStrictEqual(page.errors, []);
    await page.close();
});

test("a custom accent colour persists across a reload", { skip }, async () => {
    const page = await openPage(browser);
    await signIn(page);
    await page.click("#open-settings");
    await page.$eval("#set-accent", (i) => {
        i.value = "#3366ff";
        i.dispatchEvent(new Event("input", { bubbles: true }));
    });
    assert.strictEqual(await cssVar(page, "--accent"), "#3366ff");

    await reload(page);
    assert.strictEqual(await cssVar(page, "--accent"), "#3366ff");
    const send = await page.$eval("#composer button[type=submit]", (b) => getComputedStyle(b).backgroundColor);
    assert.strictEqual(send, "rgb(51, 102, 255)", "the primary button is drawn in the accent");
    // An accent is a theme colour; the end-to-end badge is not one.
    assert.strictEqual((await badge(page, "#room-tier")).bg, E2EE_BG);
    await page.close();
});

test("custom CSS applies locally and survives a reload", { skip }, async () => {
    const page = await openPage(browser);
    await signIn(page);
    await applyCss(page, ".msg .body { letter-spacing: 3px; }");
    const spacing = () => page.$eval("#timeline .msg .body", (b) => getComputedStyle(b).letterSpacing);
    assert.strictEqual(await spacing(), "3px");
    assert.ok(await page.$("#user-css"), "applied as a stylesheet of its own");

    await reload(page);
    assert.strictEqual(await spacing(), "3px");
    assert.deepStrictEqual(page.errors, []);
    await page.close();
});

test("custom CSS cannot hide or repaint the encryption badge itself", { skip }, async () => {
    const page = await openPage(browser);
    await signIn(page);
    await applyCss(page, `
        .badge, #room-tier, header.topbar #room-tier.badge.ok {
            display: none !important; background: #ff00ff !important;
            opacity: 0 !important; visibility: hidden !important; width: 0 !important;
        }
        .badge::after { content: " (not really)" !important; }
    `);
    for (const sel of ["#room-tier", "#rooms li:nth-child(1) .badge", "#transport"]) {
        const b = await badge(page, sel);
        assert.ok(b.visible, sel + " must stay visible");
        assert.notStrictEqual(b.display, "none", sel);
        assert.ok(b.width > 10, sel + " keeps its size");
    }
    assert.strictEqual((await badge(page, "#room-tier")).bg, E2EE_BG);
    const after = await page.$eval("#room-tier", (b) => getComputedStyle(b, "::after").content);
    assert.ok(after === "none" || after === "normal", "nothing can be appended to the badge: " + after);
    await page.close();
});

test("custom CSS that fades a badge's surroundings is switched off", { skip }, async () => {
    // The layer protects the badge element; it cannot stop CSS acting on an ancestor. The
    // tripwire in settings.js is what catches that, and this is the regression test for it.
    const page = await openPage(browser);
    await signIn(page);
    await applyCss(page, "header.topbar { opacity: 0.05; }");
    await page.waitForFunction(() => !document.getElementById("user-css"), null, { timeout: 5000 });
    const topbar = await page.$eval("header.topbar", (h) => getComputedStyle(h).opacity);
    assert.strictEqual(topbar, "1", "the CSS is gone, so the header is back");
    assert.match(await page.textContent("#set-css-status"), /switched off/);
    assert.match(await page.textContent("#look-toast"), /encryption badge/);

    // And it stays off: a reload must not bring the offending CSS back.
    await reload(page);
    assert.strictEqual(await page.$("#user-css"), null);
    await page.close();
});

test("custom CSS that covers a badge is switched off", { skip }, async () => {
    const page = await openPage(browser);
    await signIn(page);
    await applyCss(page, `
        header.topbar::after {
            content: ""; position: fixed; inset: 0 0 auto 0; height: 70px;
            background: #1a1d1f; z-index: 5;
        }
    `);
    // With the panel open the panel itself covers everything, legitimately; the check runs
    // again the moment it closes.
    await page.click("#settings-close");
    await page.waitForFunction(() => !document.getElementById("user-css"), null, { timeout: 5000 });
    assert.match(await page.textContent("#set-css-status"), /covered/);
    await page.close();
});

test("custom CSS may not declare or join a cascade layer", { skip }, async () => {
    // Joining the `security` layer is the one way to get level with the badge's own rules.
    // Refused by the browser's parser, so an escaped at-keyword is caught too.
    const page = await openPage(browser);
    await signIn(page);
    for (const css of [
        "@layer security { .badge { display: none !important; } }",
        "@\\6c ayer security { .badge { display: none !important; } }",
        "@media screen { @layer security { .badge { display: none !important; } } }",
    ]) {
        await applyCss(page, css);
        assert.strictEqual(await page.$("#user-css"), null, "not applied: " + css);
        assert.match(await page.textContent("#set-css-status"), /@layer/);
        assert.ok((await badge(page, "#room-tier")).visible);
        await page.click("#settings-close");
    }
    await page.close();
});

test("a theme exports and imports back exactly, and cannot carry CSS", { skip }, async () => {
    const page = await openPage(browser);
    await signIn(page);
    await page.click("#open-settings");
    await page.click('.theme-card[data-pick="campfire"]');
    await page.$eval("#set-accent", (i) => {
        i.value = "#22aa88";
        i.dispatchEvent(new Event("input", { bubbles: true }));
    });
    await page.click('label[for="set-layout-bubbles"]');
    await page.click("#theme-export");
    const json = await page.inputValue("#theme-json");
    const exported = JSON.parse(json);
    assert.strictEqual(exported["cairn-theme"], 1);
    assert.strictEqual(exported.tokens.accent, "#22aa88");
    const bg = await cssVar(page, "--bg");

    await page.click("#set-reset");
    assert.strictEqual(await page.getAttribute("html", "data-theme"), "slate");
    assert.notStrictEqual(await cssVar(page, "--bg"), bg);

    // A hostile copy of the same theme: CSS smuggled in at both levels, and a token that is
    // not a colour. None of it may land.
    const hostile = { ...exported, customCss: ".badge{display:none}", look: { ...exported.look, customCss: "x{}" } };
    hostile.tokens = { ...exported.tokens, text: "red; } .badge { display: none" };
    await page.fill("#theme-json", JSON.stringify(hostile));
    await page.click("#theme-import");
    assert.match(await page.textContent("#theme-status"), /Imported/);

    assert.strictEqual(await page.getAttribute("html", "data-theme"), "campfire");
    assert.strictEqual(await cssVar(page, "--bg"), bg);
    assert.strictEqual(await cssVar(page, "--accent"), "#22aa88");
    assert.strictEqual(await page.getAttribute("html", "data-layout"), "bubbles");
    assert.strictEqual(await page.$("#user-css"), null, "a theme carries no CSS");
    const kept = await page.evaluate(() => CairnLook.get());
    assert.strictEqual(kept.customCss, "");
    assert.ok(!String(await cssVar(page, "--text")).includes("badge"), "a non-colour token is dropped");

    await reload(page);
    assert.strictEqual(await cssVar(page, "--bg"), bg, "the imported theme persists");
    assert.deepStrictEqual(page.errors, []);
    await page.close();
});

test("timestamps follow the 12/24-hour choice", { skip }, async () => {
    const page = await openPage(browser);
    await signIn(page);
    const shown = () => page.textContent("#timeline .msg time.ts");
    const h24 = await shown();
    assert.match(h24, /^\d\d:\d\d$/);
    await page.click("#open-settings");
    await page.click('label[for="set-clock-12"]');
    assert.match(await shown(), /^\d{1,2}:\d\d (am|pm)$/);
    await page.click('label[for="set-clock-off"]');
    assert.ok(!(await page.isVisible("#timeline .msg time.ts")));
    await page.close();
});
