// Custom emoji, stickers, the picker and the Customise panel, in the real UI.
//
// Serves `ui/` unchanged with the app's real CSP and stubs only
// `window.__TAURI__.core.invoke`. Rust's side — who may change a set, that the instance sees
// no name or image, that drawing makes no request — is
// crates/cairn-server/tests/customisation_session.rs. This covers the UI's half of the same
// promise: it asks for an image **only by the id the set gave it, once per image, before or
// regardless of any message using it** — never per message, never by name — and it draws
// everything a member chose as text.
//
// Run: node --test clients/desktop/tests/emoji.browser.test.js
// CAIRN_SCREENSHOT_DIR=<dir> also writes screenshots, in every theme.

const test = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");

const UI = path.join(__dirname, "../ui");
const CONF = JSON.parse(fs.readFileSync(path.join(__dirname, "../src-tauri/tauri.conf.json"), "utf8"));
const THEMES = [...fs.readFileSync(path.join(UI, "settings.js"), "utf8").matchAll(/^\s*\["([a-z]+)", "[A-Z][a-z]+", "[^"]*\."\],$/gm)]
    .map((m) => m[1]);

function playwright() {
    for (const base of [null, "/opt/node22/lib/node_modules", "/usr/lib/node_modules"]) {
        try { return require(base ? path.join(base, "playwright") : "playwright"); } catch (_) { /* next */ }
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
    // Fake media so the soundboard can be tested in a real call.
    const args = ["--use-fake-device-for-media-stream", "--use-fake-ui-for-media-stream", "--autoplay-policy=no-user-gesture-required"];
    try { return await pw.chromium.launch({ args }); } catch (first) {
        const executablePath = findChromium();
        if (!executablePath) throw first;
        return await pw.chromium.launch({ args, executablePath });
    }
}

// Half a second of a 440 Hz tone, 16-bit mono WAV.
function wav() {
    const rate = 8000, n = rate / 2;
    const b = Buffer.alloc(44 + n * 2);
    b.write("RIFF", 0); b.writeUInt32LE(36 + n * 2, 4); b.write("WAVEfmt ", 8);
    b.writeUInt32LE(16, 16); b.writeUInt16LE(1, 20); b.writeUInt16LE(1, 22);
    b.writeUInt32LE(rate, 24); b.writeUInt32LE(rate * 2, 28); b.writeUInt16LE(2, 32); b.writeUInt16LE(16, 34);
    b.write("data", 36); b.writeUInt32LE(n * 2, 40);
    for (let i = 0; i < n; i++) b.writeInt16LE(Math.round(12000 * Math.sin((2 * Math.PI * 440 * i) / rate)), 44 + i * 2);
    return b;
}

const ME = "usr_0e0e0e0e0e0e4e0e8e0e0e0e0e0e0e0e";
const ALICE = "usr_a11ce000000040008000000000000001";
const ID = (n) => "c0ffee" + String(n).padStart(58, "0");

// Small PNGs in three colours, so a screenshot shows which is which.
function png(rgb) {
    const zlib = require("node:zlib");
    const size = 16;
    const raw = Buffer.alloc((size * 4 + 1) * size);
    for (let y = 0; y < size; y++) {
        raw[y * (size * 4 + 1)] = 0;
        for (let x = 0; x < size; x++) {
            const o = y * (size * 4 + 1) + 1 + x * 4;
            const inside = (x - 7.5) ** 2 + (y - 7.5) ** 2 < 56;
            raw[o] = rgb[0]; raw[o + 1] = rgb[1]; raw[o + 2] = rgb[2]; raw[o + 3] = inside ? 255 : 0;
        }
    }
    const crc = (buf) => {
        let c, crcTable = [];
        for (let n = 0; n < 256; n++) { c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; crcTable[n] = c >>> 0; }
        let x = 0xffffffff;
        for (const b of buf) x = crcTable[(x ^ b) & 0xff] ^ (x >>> 8);
        return (x ^ 0xffffffff) >>> 0;
    };
    const chunk = (type, data) => {
        const len = Buffer.alloc(4); len.writeUInt32BE(data.length);
        const td = Buffer.concat([Buffer.from(type), data]);
        const c = Buffer.alloc(4); c.writeUInt32BE(crc(td));
        return Buffer.concat([len, td, c]);
    };
    const ihdr = Buffer.alloc(13);
    ihdr.writeUInt32BE(size, 0); ihdr.writeUInt32BE(size, 4);
    ihdr[8] = 8; ihdr[9] = 6;
    return Buffer.concat([
        Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
        chunk("IHDR", ihdr), chunk("IDAT", zlib.deflateSync(raw)), chunk("IEND", Buffer.alloc(0)),
    ]);
}

const ART = { [ID(1)]: png([236, 72, 153]), [ID(2)]: png([59, 130, 246]), [ID(3)]: png([34, 197, 94]) };

class Fake {
    constructor({ canEdit = true, ready = true } = {}) {
        this.calls = [];
        this.pending = [];
        this.set = {
            can_edit: canEdit, author: ALICE, bytes: 4096,
            items: [
                { kind: "emoji", name: "party_parrot", id: ID(1), mime: "image/png", size: 900, ready },
                { kind: "emoji", name: "blobwave", id: ID(3), mime: "image/png", size: 900, ready },
                { kind: "sticker", name: "wave", id: ID(2), mime: "image/png", size: 1800, ready },
                { kind: "sound", name: "airhorn", id: ID(4), mime: "audio/wav", size: 8044, ready },
            ],
        };
    }
    msg(sender, body, n, extra) {
        return {
            sender, body, sent_at_ms: 1700000000000 + n * 60000, historic: true, attachment: null,
            id: "ab".repeat(31) + String(n).padStart(2, "0"), reply_to: null, reactions: [],
            sender_label: sender === ME ? "Sam" : "Alice", sender_ambiguous: false, card: null, sticker: null, ...extra,
        };
    }
    async invoke(cmd, args) {
        this.calls.push([cmd, args]);
        switch (cmd) {
            case "sign_in": return { user: ME, tls: true };
            case "publish_key_packages": return 5;
            case "rooms": return [{ id: "rom_1", tier: "T2", e2ee: true, joined: true }];
            case "open_room": return [
                this.msg(ALICE, "so festive :party_parrot: :party_parrot:", 1, {
                    reactions: [{ emoji: ":party_parrot:", by: [ME] }, { emoji: ":not_ours:", by: [ALICE] }, { emoji: "\u{1F44D}", by: [ALICE, ME] }],
                }),
                this.msg(ME, ":blobwave:", 2),
                this.msg(ALICE, "<img src=x onerror=\"window.__pwned=1\"> :unknown_one:", 3),
                this.msg(ALICE, ":wave:", 4, { sticker: "wave" }),
            ];
            case "open_room_tier": return "T2";
            case "room_timer": return null;
            case "poll": { const e = this.pending; this.pending = []; return e; }
            case "members": return [
                { user: ME, role: this.set.can_edit ? "owner" : "member", in_group: true, verified: false, key_changed: false, profile: null },
                { user: ALICE, role: "owner", in_group: true, verified: false, key_changed: false, profile: null },
            ];
            case "profiles": return [];
            case "my_profile": return null;
            case "call_config": return { ice_servers: [], has_relay: false, max_participants: 6 };
            case "attachment_limits": return { max_bytes: 1 << 20 };
            case "custom_set": return JSON.parse(JSON.stringify(this.set));
            case "custom_sync": { const n = this.set.items.filter((i) => !i.ready).length; for (const i of this.set.items) i.ready = true; return n; }
            case "custom_asset": {
                const it = this.set.items.find((i) => i.id === args.id);
                if (!it || !it.ready) throw new Error("not in this room's set on this device");
                return Array.from(ART[args.id] || wav());
            }
            case "custom_limits": return {
                emoji: 100, stickers: 40, sounds: 24, emoji_bytes: 262144, sticker_bytes: 524288,
                sound_bytes: 524288, sound_ms: 5000, set_bytes: 16777216,
                image_types: ["image/png", "image/gif", "image/webp"], sound_types: ["audio/ogg", "audio/mpeg", "audio/wav"],
            };
            case "custom_add": {
                this.set.items.push({ kind: "emoji", name: "new_one", id: ID(3), mime: "image/png", size: 70, ready: true });
                return JSON.parse(JSON.stringify(this.set));
            }
            case "custom_remove": {
                this.set.items = this.set.items.filter((i) => !(i.kind === args.kind && i.name === args.name));
                return JSON.parse(JSON.stringify(this.set));
            }
            case "send_sticker": return this.msg(ME, ":" + args.name + ":", 9, { sticker: args.name, historic: false });
            case "react": return [{ emoji: args.emoji, by: [ME] }];
            case "call_join": return "call-1";
            case "call_id": return "call-1";
            default: return null;
        }
    }
    count(cmd) { return this.calls.filter(([c]) => c === cmd).length; }
}

async function openApp(browser, fake, viewport = { width: 1180, height: 760 }) {
    const page = await browser.newPage({ viewport });
    const errors = [];
    page.setDefaultTimeout(10000);
    page.on("pageerror", (e) => errors.push(e.message));
    page.on("console", (m) => { if (m.type() === "error") errors.push(m.text()); });
    await page.exposeFunction("__invoke", (cmd, args, opts) => {
        if (args && typeof args === "object" && args.__raw) {
            fake.calls.push(["raw:" + cmd, { length: args.length, header: opts && opts.headers && opts.headers["x-cairn-custom"] }]);
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
    // Nothing but the app's own files may be requested: an image fetched by URL would be the
    // render-time fetch this design forbids.
    const requests = [];
    page.on("request", (r) => requests.push(r.url()));
    await page.route("http://localhost/**", (route) => {
        const rel = new URL(route.request().url()).pathname.replace(/^\/+/, "") || "index.html";
        const file = path.join(UI, rel);
        if (!file.startsWith(UI) || !fs.existsSync(file)) return route.fulfill({ status: 404 });
        const type = { ".html": "text/html", ".js": "text/javascript", ".css": "text/css" }[path.extname(file)] || "application/octet-stream";
        return route.fulfill({ contentType: type, headers: { "content-security-policy": CONF.app.security.csp }, body: fs.readFileSync(file) });
    });
    await page.goto("http://localhost/index.html");
    await page.click("#go");
    await page.waitForSelector("#rooms li");
    await page.click("#rooms li");
    await page.waitForSelector("#timeline li.msg");
    return { page, errors, requests };
}

const pw = playwright();
const REQUIRED = process.env.CAIRN_REQUIRE_BROWSER_TEST === "1";
if (!pw && REQUIRED) throw new Error("CAIRN_REQUIRE_BROWSER_TEST=1 but playwright is not installed");
const skip = pw ? false : "Playwright is not installed; skipping the emoji UI test";
const SHOTS = process.env.CAIRN_SCREENSHOT_DIR;

test("custom emoji, stickers and the picker in the real UI", { skip }, async (t) => {
    let browser;
    try { browser = await launch(pw); } catch (e) {
        if (REQUIRED) throw e;
        return t.skip("no Chromium for Playwright: " + e.message);
    }
    try {
        await t.test("a room emoji is drawn from the cache, once per image, never per use", async () => {
            const fake = new Fake();
            const { page, errors, requests } = await openApp(browser, fake);
            await page.waitForFunction(() => document.querySelectorAll("#timeline .ce img.ce-img").length >= 4);
            const imgs = await page.$$eval("#timeline li.msg:first-child .body .ce img", (l) => l.map((i) => [i.alt, i.src.slice(0, 5)]));
            assert.deepStrictEqual(imgs, [[":party_parrot:", "blob:"], [":party_parrot:", "blob:"]]);
            // One read per image in the set (three images; the sound is never decoded here),
            // whatever the timeline holds — and every one by id.
            const reads = fake.calls.filter(([c]) => c === "custom_asset").map(([, a]) => a.id);
            assert.deepStrictEqual([...new Set(reads)].sort(), [ID(1), ID(2), ID(3)].sort());
            assert.strictEqual(reads.length, 3, "an image is read once, not once per message: " + reads.length);
            // Only the app's own files went over the page's network.
            assert.ok(requests.every((u) => u.startsWith("http://localhost/") || u.startsWith("blob:") || u.startsWith("data:")), requests.join("\n"));
            // A body of nothing but emoji is drawn large.
            assert.ok(await page.$("#timeline li.msg:nth-child(2) .body.ce-jumbo .ce img"));
            // A name the set does not hold is its own text.
            const unknown = await page.$eval("#timeline li.msg:nth-child(3) .body .ce", (n) => [n.textContent, n.classList.contains("ce-missing")]);
            assert.deepStrictEqual(unknown, [":unknown_one:", true]);
            if (SHOTS) await page.screenshot({ path: path.join(SHOTS, "timeline.png") });
            assert.deepStrictEqual(errors, []);
            await page.close();
        });

        await t.test("a member's text stays text, around and inside emoji", async () => {
            const { page } = await openApp(browser, new Fake());
            assert.strictEqual(await page.$$eval("#timeline img[src='x']", (l) => l.length), 0);
            assert.match(await page.textContent("#timeline li.msg:nth-child(3) .body"), /<img src=x/);
            assert.strictEqual(await page.evaluate(() => window.__pwned), undefined);
            await page.close();
        });

        await t.test("a set not yet downloaded is synced whole before any image is read", async () => {
            const fake = new Fake({ ready: false });
            const { page } = await openApp(browser, fake);
            await page.waitForFunction(() => document.querySelectorAll("#timeline .ce img.ce-img").length >= 3);
            const order = fake.calls.map(([c]) => c).filter((c) => c === "custom_sync" || c === "custom_asset");
            assert.strictEqual(order[0], "custom_sync", order.join(","));
            await page.close();
        });

        await t.test("a reaction chip draws a room emoji, and a stranger's name as a placeholder", async () => {
            const { page } = await openApp(browser, new Fake());
            await page.waitForSelector("#timeline li.msg:first-child .reactions .chip .ce img");
            const chips = await page.$$eval("#timeline li.msg:first-child .reactions .chip", (l) => l.map((c) => c.textContent.trim()));
            assert.strictEqual(chips[1], "◌", "a :name: outside the set is not shown as words");
            assert.match(chips[2], /\u{1F44D}\s*2/u);
            await page.close();
        });

        await t.test("the composer picker inserts unicode and room emoji, and sends a sticker by name", async () => {
            const fake = new Fake();
            const { page, errors } = await openApp(browser, fake);
            await page.waitForFunction(() => document.querySelectorAll("#timeline .ce img").length >= 4);
            await page.click("#emoji");
            await page.waitForSelector("#emoji-picker:not([hidden])");
            assert.ok(await page.$("#emoji-picker #ep-sec-room + .ep-grid .ep-cell img"), "the room's own section is there, with its images");
            if (SHOTS) {
                await page.hover("#emoji-picker #ep-sec-room + .ep-grid .ep-cell");
                await page.screenshot({ path: path.join(SHOTS, "picker.png") });
            }
            await page.fill("#emoji-picker .ep-search", "pizza");
            await page.click("#emoji-picker .ep-body .ep-cell");
            assert.strictEqual(await page.inputValue("#text"), "\u{1F355}");
            await page.click("#emoji");
            await page.fill("#emoji-picker .ep-search", "parrot");
            await page.keyboard.press("Enter");
            assert.strictEqual(await page.inputValue("#text"), "\u{1F355} :party_parrot: ");
            await page.click("#emoji");
            await page.click('#emoji-picker .ep-tab[data-tab="stickers"]');
            assert.deepStrictEqual(await page.$$eval("#emoji-picker .ep-tab.on", (l) => l.map((b) => b.dataset.tab)), ["stickers"]);
            if (SHOTS) await page.screenshot({ path: path.join(SHOTS, "picker-stickers.png") });
            await page.click("#emoji-picker .ep-cell.ep-sticker");
            await page.waitForSelector("#timeline li.msg.mine.with-sticker:last-child .sticker img");
            assert.deepStrictEqual(fake.calls.find(([c]) => c === "send_sticker")[1], { name: "wave" });
            assert.deepStrictEqual(errors, []);
            await page.close();
        });

        await t.test("the reaction picker opens the full set and reacts with a room emoji", async () => {
            const fake = new Fake();
            const { page } = await openApp(browser, fake);
            await page.waitForFunction(() => document.querySelectorAll("#timeline .ce img").length >= 4);
            const li = page.locator("#timeline li.msg").nth(2);
            await li.hover();
            await li.locator(".act-react").click();
            await page.click("#react-picker .more");
            await page.waitForSelector("#emoji-picker:not([hidden])");
            assert.ok(await page.$eval('#emoji-picker .ep-tabs', (n) => n.hidden), "no sticker tab for a reaction");
            await page.click('#emoji-picker #ep-sec-room + .ep-grid .ep-cell[title=":blobwave:"]');
            const react = fake.calls.filter(([c]) => c === "react").pop()[1];
            assert.strictEqual(react.emoji, ":blobwave:");
            await page.waitForSelector("#timeline li.msg:nth-child(3) .reactions .chip .ce img");
            await page.close();
        });

        await t.test("an owner manages the set; a member sees it read-only", async () => {
            const fake = new Fake();
            const { page, errors } = await openApp(browser, fake);
            await page.click("#customise-btn");
            await page.waitForSelector("#customise:not([hidden])");
            assert.strictEqual(await page.$$eval("#cz-list .cz-item", (l) => l.length), 2);
            if (SHOTS) await page.screenshot({ path: path.join(SHOTS, "customise.png") });
            await page.setInputFiles("#cz-file", { name: "New One!.png", mimeType: "image/png", buffer: png([250, 200, 20]) });
            assert.strictEqual(await page.inputValue("#cz-name"), "new_one", "the name suggested is the sanitised one");
            await page.click("#cz-submit");
            await page.waitForFunction(() => document.querySelectorAll("#cz-list .cz-item").length === 3);
            const raw = fake.calls.find(([c]) => c === "raw:custom_add")[1];
            assert.ok(raw.length > 0, "the image goes as the raw IPC body");
            assert.deepStrictEqual(JSON.parse(raw.header), { kind: "emoji", name: "new_one" });
            await page.click('#cz-list .cz-remove[aria-label="Remove blobwave"]');
            await page.waitForFunction(() => document.querySelectorAll("#cz-list .cz-item").length === 2);
            assert.deepStrictEqual(fake.calls.find(([c]) => c === "custom_remove")[1], { kind: "emoji", name: "blobwave" });
            await page.click('.cz-tab[data-kind="sound"]');
            assert.ok(await page.$("#cz-list .cz-item.sound .cz-play"));
            if (SHOTS) await page.screenshot({ path: path.join(SHOTS, "customise-sounds.png") });
            assert.deepStrictEqual(errors, []);
            await page.close();

            const member = await openApp(browser, new Fake({ canEdit: false }));
            await member.page.click("#customise-btn");
            await member.page.waitForSelector("#customise:not([hidden])");
            assert.ok(await member.page.$eval("#cz-add", (n) => n.hidden));
            assert.ok(!(await member.page.$eval("#cz-readonly", (n) => n.hidden)));
            assert.strictEqual(await member.page.$$eval("#cz-list .cz-remove", (l) => l.length), 0);
            if (SHOTS) await member.page.screenshot({ path: path.join(SHOTS, "customise-member.png") });
            await member.page.close();
        });

        await t.test("in a call, the soundboard plays a clip into the mic and sends nothing", async () => {
            const fake = new Fake();
            const { page, errors } = await openApp(browser, fake);
            await page.click("#start-voice");
            await page.waitForSelector("#stage:not([hidden])");
            await page.waitForSelector("#soundboard-btn:not([hidden])");
            await page.click("#soundboard-btn");
            await page.waitForSelector("#soundboard:not([hidden]) .sb-clip");
            if (SHOTS) await page.screenshot({ path: path.join(SHOTS, "soundboard.png") });
            const before = fake.calls.length;
            await page.click("#soundboard .sb-clip");
            await page.waitForFunction(() => document.querySelector("#soundboard .sb-clip.playing"));
            await page.waitForTimeout(300);
            const after = fake.calls.slice(before).map(([c]) => c).filter((c) => c !== "poll");
            // The clip's bytes from the local cache; no signal, no message, nothing else.
            assert.deepStrictEqual([...new Set(after)], ["custom_asset"], after.join(","));
            assert.strictEqual(await page.textContent("#error"), "");
            // Off on this device: the button is refused, and says why.
            await page.check("#sb-off");
            assert.ok(await page.$eval("#soundboard .sb-clip", (b) => b.disabled));
            assert.deepStrictEqual(errors, []);
            await page.close();
        });

        await t.test("a custom event redraws what is already on screen", async () => {
            const fake = new Fake();
            const { page } = await openApp(browser, fake);
            await page.waitForSelector("#timeline li.msg:nth-child(3) .ce.ce-missing");
            const set = JSON.parse(JSON.stringify(fake.set));
            set.items.push({ kind: "emoji", name: "unknown_one", id: ID(2), mime: "image/png", size: 10, ready: true });
            fake.set = set;
            fake.pending = [{ kind: "custom", set }];
            await page.waitForSelector("#timeline li.msg:nth-child(3) .ce img", { timeout: 5000 });
            await page.close();
        });

        if (SHOTS) {
            await t.test("screenshots in every theme", async () => {
                assert.ok(THEMES.length >= 7, THEMES.join(","));
                for (const theme of THEMES) {
                    const { page } = await openApp(browser, new Fake());
                    await page.evaluate((th) => document.documentElement.setAttribute("data-theme", th), theme);
                    await page.waitForFunction(() => document.querySelectorAll("#timeline .ce img").length >= 4);
                    await page.click("#emoji");
                    await page.waitForSelector("#emoji-picker:not([hidden])");
                    await page.screenshot({ path: path.join(SHOTS, "theme-" + theme + ".png") });
                    await page.close();
                }
            });
        }
    } finally {
        await browser.close();
    }
});
