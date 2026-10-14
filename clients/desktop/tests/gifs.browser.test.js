// The GIF picker, in the real UI, in a real browser.
//
// Serves `ui/` unchanged over http://localhost and stubs only `window.__TAURI__.core.invoke`.
// The relay, the advert filter and the re-hosting are Rust's and tested in cargo
// (crates/cairn-server/tests/gifs_http.rs); this covers what is drawn: that an instance with
// no provider says so, that two providers get tabs with each one's required placeholder and
// attribution, that previews arrive as bytes by id, that a provider's titles are text, that
// choosing one sends it by id — and that the page itself never contacts anything but its own
// origin.
//
// Run: node --test clients/desktop/tests/gifs.browser.test.js
// Set CAIRN_SCREENSHOT_DIR to keep screenshots of the picker.

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

// The stand-in for Rust. `opts.providers` is what the instance offers.
function stub(opts) {
    window.__calls = [];
    const PROVIDERS = {
        klipy: { id: "klipy", name: "KLIPY", placeholder: "Search KLIPY", attribution: null },
        giphy: { id: "giphy", name: "GIPHY", placeholder: "Search GIPHY", attribution: "Powered by GIPHY" },
    };
    const hues = [12, 48, 95, 160, 200, 240, 280, 320, 350];
    async function picture(i, w, h) {
        const c = new OffscreenCanvas(w, h);
        const g = c.getContext("2d");
        const grad = g.createLinearGradient(0, 0, w, h);
        grad.addColorStop(0, `hsl(${hues[i % hues.length]} 75% 60%)`);
        grad.addColorStop(1, `hsl(${(hues[i % hues.length] + 60) % 360} 70% 35%)`);
        g.fillStyle = grad;
        g.fillRect(0, 0, w, h);
        g.fillStyle = "rgba(255,255,255,.85)";
        g.font = `bold ${Math.round(h / 4)}px sans-serif`;
        g.fillText("GIF " + (i + 1), 10, h - 14);
        return (await c.convertToBlob({ type: "image/png" })).arrayBuffer();
    }
    const results = (provider, query) => Array.from({ length: 9 }, (_, i) => ({
        id: `gif-${provider}-${query || "trending"}-${i}`,
        title: i === 0 ? opts.hostileTitle : `${provider} ${query || "trending"} ${i + 1}`,
        width: 200,
        height: [120, 150, 110, 200, 130][i % 5],
    }));
    let sent = 0;
    const answers = {
        sign_in: () => ({ user: "usr_me000000", tls: true }),
        rooms: () => [{ id: "rom_room0000", e2ee: true, tier: "T1", joined: true }],
        open_room: () => [],
        open_room_tier: () => "T1",
        members: () => [],
        poll: () => [],
        call_config: () => ({ ice_servers: [], has_relay: false, max_participants: 8 }),
        room_timer: () => null,
        gif_providers: () => opts.providers.map((p) => PROVIDERS[p]),
        gif_search: ({ provider, query }) => results(provider, query),
        gif_preview: ({ id }) => {
            const i = Number(id.split("-").pop());
            return picture(i, 200, [120, 150, 110, 200, 130][i % 5]);
        },
        fetch_attachment: () => picture(4, 240, 160),
        send_gif: ({ id }) => ({
            sender: "usr_me000000", body: "Cat GIF.webp", sent_at_ms: 9, historic: false,
            attachment: { id: "blob_gif" + (sent++), name: "Cat GIF.webp", size: 4000, mime: "image/webp", kind: "image" },
            sentFrom: id,
        }),
    };
    window.__TAURI__ = { core: { invoke: async (cmd, args) => {
        window.__calls.push({ cmd, args });
        const answer = answers[cmd];
        return answer ? answer(args) : null;
    } } };
}

async function openApp(browser, base, opts) {
    const page = await browser.newPage({ viewport: { width: 1100, height: 750 } });
    const errors = [];
    const requests = [];
    page.setDefaultTimeout(10000);
    page.on("pageerror", (e) => errors.push(String(e)));
    page.on("request", (r) => requests.push(r.url()));
    await page.addInitScript(stub, opts);
    await page.goto(base + "/index.html");
    await page.click("#go");
    await page.click("#rooms li");
    await page.waitForSelector("#gif");
    return { page, errors, requests };
}

const calls = (page, cmd) => page.evaluate((c) => window.__calls.filter((x) => x.cmd === c).map((x) => x.args), cmd);
const shots = process.env.CAIRN_SCREENSHOT_DIR;
const hostileTitle = '<img src=x onerror="window.__pwned=1">wave';

const pw = playwright();
const REQUIRED = process.env.CAIRN_REQUIRE_BROWSER_TEST === "1";
if (!pw && REQUIRED) {
    throw new Error("CAIRN_REQUIRE_BROWSER_TEST=1 but playwright is not installed");
}
const skip = pw ? false : "Playwright is not installed; skipping the GIF picker UI test";

test("the GIF picker in the real UI", { skip }, async (t) => {
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

    try {
        await t.test("with no provider configured, the picker says so and searches nothing", async () => {
            const { page, errors } = await openApp(browser, base, { providers: [], hostileTitle });
            await page.click("#gif");
            await page.waitForSelector(".gif-picker.unconfigured");
            assert.match(await page.$eval(".gif-status", (e) => e.textContent), /GIF search isn't configured on this instance/);
            assert.strictEqual(await page.$eval(".gif-search", (e) => getComputedStyle(e).display), "none");
            assert.deepStrictEqual(await calls(page, "gif_search"), []);
            if (shots) await page.screenshot({ path: path.join(shots, "gifs-unconfigured.png") });
            assert.deepStrictEqual(errors, []);
            await page.close();
        });

        await t.test("two providers get tabs, each with its own placeholder and attribution", async () => {
            const { page, errors, requests } = await openApp(browser, base, { providers: ["klipy", "giphy"], hostileTitle });
            await page.click("#gif");
            await page.waitForSelector(".gif-tab.on");
            assert.deepStrictEqual(await page.$$eval(".gif-tab", (l) => l.map((e) => e.textContent)), ["KLIPY", "GIPHY"]);
            assert.strictEqual(await page.$eval(".gif-search", (e) => e.placeholder), "Search KLIPY");
            assert.strictEqual(await page.$eval(".gif-attribution", (e) => e.textContent), "");
            // Trending on open: a blank query.
            assert.deepStrictEqual((await calls(page, "gif_search"))[0], { provider: "klipy", query: "" });
            await page.waitForFunction(() => document.querySelectorAll(".gif-tile img").length === 9);

            await page.click(".gif-tab[data-provider=giphy]");
            await page.waitForFunction(() => document.querySelector(".gif-search").placeholder === "Search GIPHY");
            assert.strictEqual(await page.$eval(".gif-attribution", (e) => e.textContent), "Powered by GIPHY");
            await page.fill(".gif-search", "eye roll");
            await page.waitForFunction(() => window.__calls.some((c) => c.cmd === "gif_search" && c.args.query === "eye roll"));
            assert.deepStrictEqual((await calls(page, "gif_search")).pop(), { provider: "giphy", query: "eye roll" });
            await page.waitForFunction(() =>
                document.querySelectorAll(".gif-tile img").length === 9 &&
                document.querySelector(".gif-tile").dataset.id.startsWith("gif-giphy-eye roll"));
            if (shots) await page.screenshot({ path: path.join(shots, "gifs-picker.png") });

            // The page fetched nothing from anywhere but itself: previews arrived as bytes.
            const foreign = requests.filter((u) => !u.startsWith(base) && !u.startsWith("blob:") && !u.startsWith("data:"));
            assert.deepStrictEqual(foreign, []);
            assert.deepStrictEqual(errors, []);
            await page.close();
        });

        await t.test("a provider's title is drawn as text, never markup", async () => {
            const { page } = await openApp(browser, base, { providers: ["giphy"], hostileTitle });
            await page.click("#gif");
            await page.waitForFunction(() => document.querySelectorAll(".gif-tile img").length === 9);
            assert.strictEqual(await page.$eval(".gif-tile", (e) => e.title), hostileTitle);
            assert.strictEqual(await page.$$eval(".gif-tile img[src='x']", (l) => l.length), 0);
            assert.strictEqual(await page.evaluate(() => window.__pwned), undefined);
            // One provider: nothing to choose between, so no tabs.
            assert.strictEqual(await page.$eval(".gif-tabs", (e) => e.hidden), true);
            await page.close();
        });

        await t.test("choosing a GIF sends it by id and shows it as an image message", async () => {
            const { page, errors } = await openApp(browser, base, { providers: ["klipy"], hostileTitle });
            await page.click("#gif");
            await page.waitForFunction(() => document.querySelectorAll(".gif-tile img").length === 9);
            const id = await page.$eval(".gif-tile:nth-child(3)", (e) => e.dataset.id);
            await page.click(".gif-tile:nth-child(3)");
            await page.waitForSelector("#gif-picker", { state: "hidden" });
            assert.deepStrictEqual(await calls(page, "send_gif"), [{ id }]);
            await page.waitForFunction(() => {
                const img = document.querySelector("#timeline .attach-image img");
                return img && img.complete && img.naturalWidth > 0;
            });
            assert.deepStrictEqual(errors, []);
            await page.close();
        });

        await t.test("Escape and a click outside both close the picker", async () => {
            const { page } = await openApp(browser, base, { providers: ["klipy"], hostileTitle });
            await page.click("#gif");
            await page.waitForSelector("#gif-picker:not([hidden])");
            await page.keyboard.press("Escape");
            await page.waitForSelector("#gif-picker", { state: "hidden" });
            await page.click("#gif");
            await page.waitForSelector("#gif-picker:not([hidden])");
            await page.mouse.click(780, 100); // the timeline, above the panel
            await page.waitForSelector("#gif-picker", { state: "hidden" });
            await page.close();
        });
    } finally {
        await browser.close();
        server.close();
    }
});
