// Attachments, in the real UI, in a real browser.
//
// Serves `ui/` unchanged over http://localhost and stubs only `window.__TAURI__.core.invoke`,
// so what runs is the shipped index.html, app.js and attachments.js. Rust's side is covered
// by crates/cairn-server/tests/attachments_session.rs; this covers what `cargo test` cannot
// see — that a picked file leaves as raw bytes with a header the IPC layer will accept, that
// an image is decoded and shown, that a file is only ever offered as a save, and that a
// sender's filename is drawn as text.
//
// Run: node --test clients/desktop/tests/attachments.browser.test.js
//
// Skipped, with a message, when Playwright or its Chromium is not installed — as
// call.browser.test.js is.

const test = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const http = require("node:http");
const path = require("node:path");

const UI = path.join(__dirname, "../ui");
const TYPES = { ".html": "text/html", ".js": "text/javascript", ".css": "text/css" };

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

function serve() {
    const server = http.createServer((req, res) => {
        const rel = decodeURIComponent(new URL(req.url, "http://x").pathname).replace(/^\/+/, "") || "index.html";
        const file = path.join(UI, rel);
        if (!file.startsWith(UI) || !fs.existsSync(file)) {
            res.writeHead(404);
            return res.end();
        }
        res.writeHead(200, { "content-type": TYPES[path.extname(file)] || "application/octet-stream" });
        res.end(fs.readFileSync(file));
    });
    return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(server)));
}

// The stand-in for Rust. History holds one attachment of each kind; `fetch_attachment` answers
// the image as an ArrayBuffer (Tauri's ipc: protocol) and the audio as an array of numbers
// (its postMessage fallback), so both shapes are exercised.
function stub(opts) {
    window.__calls = [];
    const hostile = opts.hostileName;
    const history = [
        { sender: "usr_alice000", body: "sunset.png", sent_at_ms: 1, historic: true,
          attachment: { id: "blob_img", name: "sunset.png", size: 5120, mime: "image/png", kind: "image" } },
        { sender: "usr_alice000", body: "note.wav", sent_at_ms: 2, historic: true,
          attachment: { id: "blob_wav", name: "note.wav", size: 1644, mime: "audio/wav", kind: "audio" } },
        { sender: "usr_bob00000", body: hostile, sent_at_ms: 3, historic: false,
          attachment: { id: "blob_doc", name: hostile, size: 48213, mime: "application/pdf", kind: "file" } },
    ];
    // The scrolling case: a long history ending in a photo and one more message, with the
    // photo's bytes held back until the test releases them.
    if (opts.scroll) {
        history.length = 0;
        for (let i = 0; i < 40; i++) {
            history.push({ sender: "usr_bob00000", body: "filler line " + i, sent_at_ms: 100 + i, historic: true });
        }
        history.push({ sender: "usr_alice000", body: "late.png", sent_at_ms: 200, historic: true,
            attachment: { id: "blob_img", name: "late.png", size: 5120, mime: "image/png", kind: "image" } });
        history.push({ sender: "usr_bob00000", body: "the last word", sent_at_ms: 201, historic: true });
    }
    async function png() {
        const c = new OffscreenCanvas(240, 150);
        const g = c.getContext("2d");
        if (opts.scroll) { c.width = 300; c.height = 900; }
        const grad = g.createLinearGradient(0, 0, 240, 150);
        grad.addColorStop(0, "#f59e0b");
        grad.addColorStop(1, "#7c3aed");
        g.fillStyle = grad;
        g.fillRect(0, 0, 240, 150);
        return (await c.convertToBlob({ type: "image/png" })).arrayBuffer();
    }
    function wav() {
        const n = 1600;
        const b = new DataView(new ArrayBuffer(44 + n));
        const s = (o, t) => [...t].forEach((ch, i) => b.setUint8(o + i, ch.charCodeAt(0)));
        s(0, "RIFF"); b.setUint32(4, 36 + n, true); s(8, "WAVE"); s(12, "fmt ");
        b.setUint32(16, 16, true); b.setUint16(20, 1, true); b.setUint16(22, 1, true);
        b.setUint32(24, 8000, true); b.setUint32(28, 8000, true); b.setUint16(32, 1, true);
        b.setUint16(34, 8, true); s(36, "data"); b.setUint32(40, n, true);
        for (let i = 0; i < n; i++) b.setUint8(44 + i, 128);
        return Array.from(new Uint8Array(b.buffer));
    }
    const answers = {
        sign_in: () => ({ user: "usr_me000000", tls: false }),
        rooms: () => [{ id: "rom_room0000", e2ee: true, tier: "T1", joined: true }],
        open_room: () => history,
        open_room_tier: () => "T1",
        members: () => [],
        poll: () => [],
        call_config: () => ({ ice_servers: [], has_relay: false, max_participants: 8 }),
        attachment_limits: () => ({ max_bytes: opts.maxBytes }),
        fetch_attachment: ({ id }) => {
            if (id === "blob_img" && opts.scroll) return new Promise((done) => { window.__release = () => done(png()); });
            return id === "blob_img" ? png() : id === "blob_wav" ? wav() : Promise.reject("not inline");
        },
        save_attachment: () => "/home/me/Downloads/report.pdf",
        send_file: (body, o) => {
            const meta = JSON.parse(o.headers["x-cairn-file"]);
            return { sender: "usr_me000000", body: meta.name, sent_at_ms: 9, historic: false,
                     attachment: { id: "blob_new", name: meta.name, size: body.length, mime: meta.mime, kind: "file" } };
        },
    };
    window.__TAURI__ = { core: { invoke: async (cmd, args, o) => {
        const rec = { cmd };
        if (args instanceof Uint8Array) {
            rec.raw = true;
            rec.length = args.length;
            rec.sum = args.reduce((a, x) => a + x, 0);
            rec.header = o && o.headers && o.headers["x-cairn-file"];
        } else {
            rec.args = args;
        }
        window.__calls.push(rec);
        const answer = answers[cmd];
        return answer ? answer(args, o) : null;
    } } };
}

async function openApp(browser, base, opts) {
    const page = await browser.newPage({ viewport: { width: 1100, height: 750 } });
    const errors = [];
    // A page that fails to load should fail the test quickly rather than wait 30s per step.
    page.setDefaultTimeout(10000);
    page.on("pageerror", (e) => errors.push(String(e)));
    await page.addInitScript(stub, opts);
    await page.goto(base + "/index.html");
    await page.click("#go");
    await page.click("#rooms li");
    await page.waitForSelector("#timeline .attach-file");
    return { page, errors };
}

// Opens the long history, waits until the timeline is at its newest message, and returns
// the page with the photo's bytes still held back.
async function openScrolled(browser, base) {
    const page = await browser.newPage({ viewport: { width: 1100, height: 750 } });
    page.setDefaultTimeout(10000);
    await page.addInitScript(stub, { maxBytes: 1 << 20, hostileName: "x", scroll: true });
    await page.goto(base + "/index.html");
    await page.click("#go");
    await page.click("#rooms li");
    await page.waitForFunction(() => typeof window.__release === "function");
    await page.waitForFunction(() => {
        const t = document.getElementById("timeline");
        return t.scrollHeight > t.clientHeight * 2 && t.scrollHeight - t.scrollTop - t.clientHeight < 5;
    });
    return page;
}

async function photoLoaded(page) {
    await page.waitForFunction(() => {
        const img = document.querySelector(".attach-image img");
        return img && img.complete && img.naturalHeight === 900;
    });
    // Two frames: one for layout, one for the observer's callback to have run.
    await page.evaluate(() => new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r))));
}

const pw = playwright();
// As in call.browser.test.js: CI sets this so a missing browser fails the job rather than
// being reported as a pass.
const REQUIRED = process.env.CAIRN_REQUIRE_BROWSER_TEST === "1";
if (!pw && REQUIRED) {
    throw new Error("CAIRN_REQUIRE_BROWSER_TEST=1 but playwright is not installed");
}
const skip = pw ? false : "Playwright is not installed; skipping the attachment UI test";

test("attachments in the real UI", { skip }, async (t) => {
    const server = await serve();
    const base = "http://localhost:" + server.address().port;
    let browser;
    try {
        browser = await launch(pw);
    } catch (e) {
        server.close();
        if (REQUIRED) throw e;
        return t.skip("no Chromium for Playwright: " + e.message);
    }
    const hostileName = '<img src=x onerror="window.__pwned=1">report.pdf';

    try {
        await t.test("an image is decoded and shown inline, and audio gets a player", async () => {
            const { page, errors } = await openApp(browser, base, { maxBytes: 1 << 20, hostileName });
            await page.waitForFunction(() => {
                const img = document.querySelector(".attach-image img");
                return img && img.complete && img.naturalWidth > 0;
            });
            assert.strictEqual(await page.$eval(".attach-image img", (i) => i.naturalWidth), 240);
            await page.waitForFunction(() => {
                const a = document.querySelector(".attach-audio audio");
                return a && a.src.startsWith("blob:") && a.readyState >= 1;
            });
            if (process.env.CAIRN_SCREENSHOT) await page.screenshot({ path: process.env.CAIRN_SCREENSHOT });
            assert.deepStrictEqual(errors, []);
            await page.close();
        });

        await t.test("a file is offered as a save, never fetched into the page", async () => {
            const { page } = await openApp(browser, base, { maxBytes: 1 << 20, hostileName });
            const box = await page.$(".attach-file");
            assert.strictEqual(await box.$("img, audio, a, iframe, object, embed"), null);
            const fetched = await page.evaluate(() =>
                window.__calls.filter((c) => c.cmd === "fetch_attachment").map((c) => c.args.id));
            assert.ok(!fetched.includes("blob_doc"), "a file kind must not be fetched: " + fetched);
            await box.$eval(".attach-save", (b) => b.click());
            await page.waitForSelector("text=Saved");
            const saved = await page.evaluate(() => window.__calls.find((c) => c.cmd === "save_attachment").args);
            assert.deepStrictEqual(saved, { id: "blob_doc" });
            await page.close();
        });

        await t.test("a senders filename is drawn as text, not markup", async () => {
            const { page } = await openApp(browser, base, { maxBytes: 1 << 20, hostileName });
            assert.strictEqual(await page.$eval(".attach-file .attach-name", (n) => n.textContent), hostileName);
            assert.strictEqual(await page.$$eval(".attach-file img", (l) => l.length), 0);
            assert.strictEqual(await page.evaluate(() => window.__pwned), undefined);
            await page.close();
        });

        await t.test("a picked file leaves as raw bytes with its name in an ascii header", async () => {
            const { page } = await openApp(browser, base, { maxBytes: 1 << 20, hostileName });
            const name = "fotó ✓ 😀.png";
            const bytes = Buffer.alloc(3000, 7);
            await page.setInputFiles("#file-input", { name, mimeType: "image/png", buffer: bytes });
            await page.waitForFunction(() => window.__calls.some((c) => c.cmd === "send_file"));
            const call = await page.evaluate(() => window.__calls.find((c) => c.cmd === "send_file"));
            assert.strictEqual(call.raw, true, "the bytes must be the IPC body, not a JSON field");
            assert.strictEqual(call.length, 3000);
            assert.strictEqual(call.sum, 3000 * 7);
            assert.match(call.header, /^[\x20-\x7e]+$/, "a header value must be printable ascii");
            assert.deepStrictEqual(JSON.parse(call.header), { name, mime: "image/png" });
            // Our own message never comes back from a poll, so the UI must show it itself.
            await page.waitForFunction((n) =>
                [...document.querySelectorAll(".attach-name")].some((e) => e.textContent === n), name);
            assert.strictEqual(await page.$$eval(".notice", (l) => l.filter((e) => e.textContent.startsWith("Sending")).length), 0);
            await page.close();
        });

        await t.test("a photo that loads late keeps the newest message in view", async () => {
            // Found by looking: the timeline scrolled to the bottom before the photo's bytes
            // arrived, then the photo grew and pushed the last messages below the fold.
            const page = await openScrolled(browser, base);
            await page.evaluate(() => window.__release());
            await photoLoaded(page);
            const gap = await page.evaluate(() => {
                const t = document.getElementById("timeline");
                const last = [...t.querySelectorAll("li.msg")].pop();
                return {
                    text: last.textContent,
                    below: last.getBoundingClientRect().bottom - t.getBoundingClientRect().bottom,
                };
            });
            assert.match(gap.text, /the last word/);
            assert.ok(gap.below <= 1, "the last message must still be on screen, but is " + gap.below + "px below");
            await page.close();
        });

        await t.test("a reader who scrolled up is not moved when a photo loads", async () => {
            const page = await openScrolled(browser, base);
            await page.$eval("#timeline", (t) => { t.scrollTop = 120; });
            await page.waitForFunction(() => document.getElementById("timeline").scrollTop === 120);
            // Let the scroll event land before the photo does.
            await page.evaluate(() => new Promise((r) => requestAnimationFrame(r)));
            await page.evaluate(() => window.__release());
            await photoLoaded(page);
            assert.strictEqual(await page.$eval("#timeline", (t) => t.scrollTop), 120);
            await page.close();
        });

        await t.test("a message arriving while the reader is up in the history is counted, not scrolled to", async () => {
            const page = await openScrolled(browser, base);
            await page.evaluate(() => window.__release());
            await photoLoaded(page);
            await page.$eval("#timeline", (t) => { t.scrollTop = 120; });
            await page.waitForFunction(() => document.getElementById("timeline").scrollTop === 120);
            await page.evaluate(() => new Promise((r) => requestAnimationFrame(r)));
            await page.evaluate(() => addMessage({ sender: "usr_bob00000", body: "are you there?", sent_at_ms: 99, historic: false }));
            await page.evaluate(() => new Promise((r) => requestAnimationFrame(r)));
            assert.strictEqual(await page.$eval("#timeline", (t) => t.scrollTop), 120, "the reader was moved");
            assert.strictEqual(await page.isVisible("#jump-new"), true);
            assert.strictEqual(await page.innerText("#jump-new"), "1 new message \u2193");

            // The button takes them down and goes away.
            await page.click("#jump-new");
            await page.waitForFunction(() => {
                const t = document.getElementById("timeline");
                return t.scrollHeight - t.scrollTop - t.clientHeight <= 2;
            });
            assert.strictEqual(await page.isVisible("#jump-new"), false);

            // A message of one's own always brings the reader to it.
            await page.$eval("#timeline", (t) => { t.scrollTop = 120; });
            await page.evaluate(() => new Promise((r) => requestAnimationFrame(r)));
            await page.evaluate(() => addMessage({ sender: "usr_me000000", body: "here", sent_at_ms: 100, historic: false }));
            await page.waitForFunction(() => {
                const t = document.getElementById("timeline");
                return t.scrollHeight - t.scrollTop - t.clientHeight <= 2;
            });
            assert.strictEqual(await page.isVisible("#jump-new"), false);
            await page.close();
        });

        await t.test("an oversized file is refused before it is read or sent", async () => {
            const { page } = await openApp(browser, base, { maxBytes: 1000, hostileName });
            await page.setInputFiles("#file-input", { name: "big.bin", mimeType: "application/octet-stream", buffer: Buffer.alloc(2000) });
            await page.waitForFunction(() => /limited to/.test(document.getElementById("error").textContent));
            const sent = await page.evaluate(() => window.__calls.filter((c) => c.cmd === "send_file").length);
            assert.strictEqual(sent, 0);
            await page.close();
        });
    } finally {
        await browser.close();
        server.close();
    }
});
