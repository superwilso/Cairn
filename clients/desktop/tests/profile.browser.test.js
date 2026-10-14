// Profiles in the real UI, in a real browser.
//
// Serves `ui/` unchanged, with the app's real CSP, and stubs only
// `window.__TAURI__.core.invoke`. Rust's side — the record, the rules, the lookalike check,
// and the attacks — is crates/cairn-server/tests/profiles_session.rs. This covers what a
// person looks at: that a member's chosen name is drawn as text and never as markup, that a
// name Rust flagged as ambiguous always carries the id, that the card shows the full account
// id and opens safety numbers *by id*, and that the editor sends what was typed and an image
// as raw bytes.
//
// Run: node --test clients/desktop/tests/profile.browser.test.js
// CAIRN_SCREENSHOT_DIR=<dir> also writes screenshots of the card and the editor.

const test = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");

const UI = path.join(__dirname, "../ui");
const CONF = JSON.parse(fs.readFileSync(path.join(__dirname, "../src-tauri/tauri.conf.json"), "utf8"));

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

const ME = "usr_0e0e0e0e0e0e4e0e8e0e0e0e0e0e0e0e";
const ALICE = "usr_a11ce000000040008000000000000001";
const MALLORY = "usr_3a11000000004000800000000000000f";
const HOSTILE = "usr_b0b0000000004000800000000000000b";
const HOSTILE_NAME = '<img src=x onerror="window.__pwned=1">';

function profile(user, extra) {
    const hex = user.replace(/^usr_/, "");
    return {
        user, short_id: hex.slice(0, 8), tag: hex.slice(0, 12), label: hex.slice(0, 8),
        ambiguous: false, display_name: null, nickname: null, pronouns: null, about: null,
        status: null, colors: null, avatar: null, banner: null, is_me: user === ME, ...extra,
    };
}

const PROFILES = [
    profile(ME, { label: "Sam", display_name: "Sam", colors: ["#2b6cb0", "#805ad5"] }),
    profile(ALICE, {
        label: "Alice", display_name: "Alice", ambiguous: true, pronouns: "she/her",
        about: "Curiouser and curiouser.\nTea at four.", colors: ["#f59e0b", "#7c3aed"],
        status: { emoji: "🫖", text: "at a tea party", expires_at_ms: null },
        avatar: { id: "blob_av", mime: "image/png" }, banner: { id: "blob_bn", mime: "image/png" },
    }),
    profile(MALLORY, { label: "AIice", display_name: "AIice", ambiguous: true }),
    profile(HOSTILE, { label: HOSTILE_NAME, display_name: HOSTILE_NAME, about: HOSTILE_NAME }),
];

class Fake {
    constructor() { this.calls = []; this.profiles = PROFILES.map((p) => ({ ...p })); }
    find(user) { return this.profiles.find((p) => p.user === user); }
    async invoke(cmd, args) {
        this.calls.push([cmd, args]);
        const msg = (sender, body, t) => ({
            sender, body, sent_at_ms: t, historic: true, attachment: null, id: null,
            reply_to: null, reactions: [], sender_label: this.find(sender).label,
            sender_ambiguous: this.find(sender).ambiguous,
        });
        switch (cmd) {
            case "sign_in": return { user: ME, tls: true };
            case "publish_key_packages": return 5;
            case "rooms": return [{ id: "rom_1", tier: "T2", e2ee: true, joined: true }];
            case "open_room": return [
                msg(ALICE, "hello from the real alice", 1),
                msg(MALLORY, "trust me, I am alice", 2),
                msg(HOSTILE, "hi", 3),
            ];
            case "open_room_tier": return "T2";
            case "room_timer": return null;
            case "poll": { const e = this.pending || []; this.pending = []; return e; }
            case "members": return this.profiles.map((p) => ({
                user: p.user, role: p.user === ME ? "owner" : "member", in_group: true,
                verified: p.user === ALICE, key_changed: false, profile: p,
            }));
            case "profiles": return this.profiles;
            case "my_profile": return this.find(ME);
            case "profile_limits": return {
                name_chars: 32, pronouns_chars: 40, about_chars: 190, about_lines: 8,
                status_chars: 128, image_bytes: 1048576,
                image_types: ["image/png", "image/jpeg", "image/webp", "image/gif"],
            };
            case "fetch_profile_image": return Array.from(await this.png(args.slot));
            case "safety_numbers": return [];
            case "call_config": return { ice_servers: [], has_relay: false, max_participants: 6 };
            case "attachment_limits": return { max_bytes: 1 << 20 };
            case "set_profile": {
                const e = args.edit;
                Object.assign(this.find(ME), {
                    display_name: e.display_name || null, label: e.display_name || "0e0e0e0e",
                    pronouns: e.pronouns || null, about: e.about || null, colors: e.colors,
                });
                return this.find(ME);
            }
            case "set_profile_image": return this.find(ME);
            case "clear_profile_image": return this.find(ME);
            case "set_nickname": return this.find(ME);
            default: return null;
        }
    }
    // Decoded in node, handed to the page as numbers — Tauri's postMessage shape.
    async png() { return Buffer.from(PNG_BYTES, "base64"); }
}

// An 8x8 orange PNG.
const PNG_BYTES =
    "iVBORw0KGgoAAAANSUhEUgAAAAgAAAAICAYAAADED76LAAAAE0lEQVR4nGP4Oo/7Pz7MMDIUAABRsqdBZYrLcQAAAABJRU5ErkJggg==";

async function openApp(browser, fake) {
    const page = await browser.newPage({ viewport: { width: 1180, height: 760 } });
    const errors = [];
    page.setDefaultTimeout(10000);
    page.on("pageerror", (e) => errors.push(e.message));
    page.on("console", (m) => { if (m.type() === "error") errors.push(m.text()); });
    await page.exposeFunction("__invoke", (cmd, args, opts) => {
        if (args && typeof args === "object" && args.__raw) {
            fake.calls.push(["raw:" + cmd, { length: args.length, header: opts && opts.headers && opts.headers["x-cairn-image"] }]);
            return fake.invoke(cmd, {});
        }
        return fake.invoke(cmd, args);
    });
    await page.addInitScript(`
        window.__TAURI__ = { core: { invoke: (cmd, args, opts) => {
            if (args instanceof Uint8Array) return window.__invoke(cmd, { __raw: true, length: args.length }, opts);
            return window.__invoke(cmd, args, opts);
        } } };
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
    await page.waitForSelector("#timeline li.msg .pf-name");
    await page.waitForSelector("#member-list .pf-avatar");
    return { page, errors };
}

const pw = playwright();
const REQUIRED = process.env.CAIRN_REQUIRE_BROWSER_TEST === "1";
if (!pw && REQUIRED) throw new Error("CAIRN_REQUIRE_BROWSER_TEST=1 but playwright is not installed");
const skip = pw ? false : "Playwright is not installed; skipping the profile UI test";
const SHOTS = process.env.CAIRN_SCREENSHOT_DIR;

test("profiles in the real UI", { skip }, async (t) => {
    let browser;
    try {
        browser = await launch(pw);
    } catch (e) {
        if (REQUIRED) throw e;
        return t.skip("no Chromium for Playwright: " + e.message);
    }
    try {
        await t.test("names come from Rust's labels, and an ambiguous one carries the id", async () => {
            const fake = new Fake();
            const { page, errors } = await openApp(browser, fake);
            const authors = await page.$$eval("#timeline li.msg .who", (l) => l.map((w) => ({
                name: w.querySelector(".pf-name").textContent,
                tag: w.querySelector(".pf-tag") && w.querySelector(".pf-tag").textContent,
                title: w.title,
            })));
            assert.deepStrictEqual(authors[0], { name: "Alice", tag: "#a11ce0000000", title: ALICE });
            assert.deepStrictEqual(authors[1], { name: "AIice", tag: "#3a1100000000", title: MALLORY });
            // Alice's avatar is the decrypted image, not initials.
            await page.waitForFunction(() => {
                const img = document.querySelector('#timeline .pf-avatar[data-pf-user^="usr_a11ce"] img');
                return img && img.complete && img.naturalWidth === 8;
            });
            if (SHOTS) await page.screenshot({ path: path.join(SHOTS, "profile-timeline.png") });
            assert.deepStrictEqual(errors, []);
            await page.close();
        });

        await t.test("a hostile name is text, isolated, and never markup", async () => {
            const { page } = await openApp(browser, new Fake());
            const names = await page.$$eval(".pf-name", (l) => l.map((n) => [n.tagName, n.textContent]));
            assert.ok(names.some(([tag, text]) => tag === "BDI" && text === HOSTILE_NAME), JSON.stringify(names));
            assert.strictEqual(await page.$$eval("#timeline img[src='x'], #member-list img[src='x']", (l) => l.length), 0);
            assert.strictEqual(await page.evaluate(() => window.__pwned), undefined);
            await page.close();
        });

        await t.test("the card shows the full id and opens safety numbers by id", async () => {
            const fake = new Fake();
            const { page } = await openApp(browser, fake);
            await page.click("#timeline li.msg .who >> nth=0");
            await page.waitForSelector("#pf-card:not([hidden])");
            assert.strictEqual(await page.$eval("#pf-card .pf-id", (n) => n.textContent), ALICE);
            assert.strictEqual(await page.$eval("#pf-card .pf-title .pf-name", (n) => n.textContent), "Alice");
            assert.strictEqual(await page.$eval("#pf-card .pf-pronouns", (n) => n.textContent), "she/her");
            assert.match(await page.$eval("#pf-card .pf-status", (n) => n.textContent), /tea party/);
            assert.match(await page.$eval("#pf-card .pf-keys", (n) => n.textContent), /Verified/);
            assert.ok(await page.$("#pf-card .pf-warn"), "an ambiguous name is explained on the card");
            await page.waitForFunction(() =>
                /blob:/.test(document.querySelector("#pf-card .pf-banner").style.backgroundImage));
            if (SHOTS) await page.screenshot({ path: path.join(SHOTS, "profile-card.png") });
            await page.click("#pf-card .pf-foot button");
            await page.waitForSelector("#safety:not([hidden])");
            assert.deepStrictEqual(fake.calls.filter(([c]) => c === "safety_numbers").pop()[1], { user: ALICE });
            await page.close();
        });

        await t.test("a member avatar opens the card; the row still opens safety numbers", async () => {
            const fake = new Fake();
            const { page } = await openApp(browser, fake);
            const row = page.locator("#member-list li").filter({ hasText: "AIice" });
            await row.locator(".pf-avatar").click();
            await page.waitForSelector("#pf-card:not([hidden])");
            assert.strictEqual(await page.$eval("#pf-card .pf-id", (n) => n.textContent), MALLORY);
            await page.keyboard.press("Escape");
            await row.locator(".who").click();
            await page.waitForSelector("#safety:not([hidden])");
            assert.deepStrictEqual(fake.calls.filter(([c]) => c === "safety_numbers").pop()[1], { user: MALLORY });
            await page.close();
        });

        await t.test("the editor previews live and sends what was typed, and the image as bytes", async () => {
            const fake = new Fake();
            const { page, errors } = await openApp(browser, fake);
            await page.click("#whoami");
            await page.waitForSelector("#pf-editor:not([hidden])");
            await page.fill("#pf-display-name", "Samwise");
            await page.fill("#pf-pronouns", "he/him");
            await page.fill("#pf-about", "Gardener.\nCarries things.");
            await page.check("#pf-use-colors");
            await page.fill("#pf-status-emoji", "🌱");
            await page.fill("#pf-status-text", "potatoes");
            assert.strictEqual(await page.$eval("#pf-preview .pf-name", (n) => n.textContent), "Samwise");
            assert.strictEqual(await page.$eval("#pf-preview .pf-pronouns", (n) => n.textContent), "he/him");
            await page.setInputFiles("#pf-avatar-input", {
                name: "me.png", mimeType: "image/png", buffer: Buffer.from(PNG_BYTES, "base64"),
            });
            await page.waitForSelector("#pf-preview .pf-avatar img");
            if (SHOTS) await page.screenshot({ path: path.join(SHOTS, "profile-editor.png") });
            await page.click("#pf-form button[type=submit]");
            await page.waitForSelector("#pf-editor", { state: "hidden" });
            const edit = fake.calls.find(([c]) => c === "set_profile")[1].edit;
            assert.strictEqual(edit.display_name, "Samwise");
            assert.strictEqual(edit.about, "Gardener.\nCarries things.");
            assert.strictEqual(edit.status_emoji, "🌱");
            assert.ok(Array.isArray(edit.colors) && /^#[0-9a-f]{6}$/.test(edit.colors[0]));
            const raw = fake.calls.find(([c]) => c === "raw:set_profile_image")[1];
            assert.ok(raw.length > 0, "the image goes as the raw IPC body");
            const meta = JSON.parse(raw.header);
            assert.strictEqual(meta.slot, "avatar");
            assert.match(meta.mime, /^image\/(webp|png)$/, "downscaled before sending");
            assert.match(raw.header, /^[\x20-\x7e]+$/);
            await page.waitForFunction(() => document.getElementById("whoami").textContent === "Samwise");
            assert.deepStrictEqual(errors, []);
            await page.close();
        });

        await t.test("a profiles event relabels what is already on screen", async () => {
            const fake = new Fake();
            const { page } = await openApp(browser, fake);
            const renamed = fake.profiles.map((p) => p.user === ALICE
                ? { ...p, label: "Alice L.", display_name: "Alice L.", ambiguous: false } : p);
            fake.pending = [{ kind: "profiles", profiles: renamed }];
            await page.waitForFunction(() =>
                document.querySelector("#timeline li.msg .who .pf-name").textContent === "Alice L.", null, { timeout: 5000 });
            assert.strictEqual(await page.$("#timeline li.msg:first-child .who .pf-tag"), null);
            await page.close();
        });
    } finally {
        await browser.close();
    }
});
