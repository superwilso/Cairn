// Link cards, rendered by the real UI in a real browser.
//
// Loads ui/index.html, style.css, call.js and app.js unchanged, with `window.__TAURI__`
// stubbed to answer the way the Rust side does, and checks the properties the card UI exists
// to keep (docs/05-embeds.md §3):
//
// - a sender's strings are text, never markup — a hostile title does not execute;
// - the host a link really goes to is on screen, and so is any warning or proxy caveat;
// - a reel lays out as a reel, and a reel with nothing fetched still says what it is;
// - clicking asks Rust to open the link, and nothing in the page loads a remote image.
//
// Run: node --test clients/desktop/tests/cards.browser.test.js
// Set CAIRN_SCREENSHOT=/path/to.png to keep a picture of the timeline.
//
// Skips, saying so, when Playwright or its Chromium is missing — same as call.browser.test.js.

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

async function launch(pw) {
    try {
        return await pw.chromium.launch();
    } catch (first) {
        const root = process.env.PLAYWRIGHT_BROWSERS_PATH || "/opt/pw-browsers";
        if (!fs.existsSync(root)) throw first;
        for (const dir of fs.readdirSync(root)) {
            const exe = path.join(root, dir, "chrome-linux", "chrome");
            if (fs.existsSync(exe)) return await pw.chromium.launch({ executablePath: exe });
        }
        throw first;
    }
}

const ME = "usr_1111111111111111";
const FRIEND = "usr_2222222222222222";
const ROOM = "rom_3333333333333333";

// What `CardView` serialises to. The thumbnail is filled in inside the page, where a
// canvas can make a real JPEG data: URI — the only kind Rust ever hands over.
const REEL = "https://www.instagram.com/reel/C5nYxQyOZ6V/?igsh=abc";
const BARE_REEL = "https://www.instagram.com/reel/DAbCdEfGhIj/";
const HOSTILE = "https://reuters.com@evil.test/world";
const history = [
    {
        sender: FRIEND, sent_at_ms: 1, historic: true,
        body: "this one 😂 " + REEL,
        card: {
            url: REEL, host: "www.instagram.com", host_warning: null,
            title: "Wii Gato (Lipe Sleep)", description: "A cat asleep on a games console.",
            claimed_site: "Instagram", author: "@diegoquinteiro",
            platform: "Instagram", kind: "Reel", portrait: true,
            thumbnail: "__THUMB__", caveat: "preview fetched via a third-party proxy",
        },
    },
    {
        sender: ME, sent_at_ms: 2, historic: true,
        body: BARE_REEL,
        card: {
            url: BARE_REEL, host: "www.instagram.com", host_warning: null,
            title: null, description: null, claimed_site: null, author: null,
            platform: "Instagram", kind: "Reel", portrait: true, thumbnail: null, caveat: null,
        },
    },
    {
        sender: FRIEND, sent_at_ms: 3, historic: false,
        body: "breaking " + HOSTILE,
        card: {
            url: HOSTILE, host: "evil.test",
            host_warning: "This link has text before an @ that is not where it goes.",
            title: "<img src=x onerror=\"window.__pwned=1\">Reuters: markets fall",
            description: "<script>window.__pwned=2</script>", claimed_site: "Reuters",
            author: null, platform: null, kind: null, portrait: false,
            thumbnail: null, caveat: null,
        },
    },
];

function stub(page, calls) {
    return page.exposeFunction("__invoke", async (cmd, args) => {
        calls.push([cmd, args]);
        switch (cmd) {
            case "sign_in": return { user: ME, tls: true };
            case "rooms": return [{ id: ROOM, tier: "T2", e2ee: true, joined: true }];
            case "open_room": return history;
            case "open_room_tier": return "T2";
            case "members": return [
                { user: ME, role: "owner", in_group: true, verified: false },
                { user: FRIEND, role: "member", in_group: true, verified: true },
            ];
            case "poll": return [];
            case "send": return { sender: ME, body: args.text, sent_at_ms: 9, historic: false, card: history[1].card };
            case "call_config": return { ice_servers: [], has_relay: false, max_participants: 6 };
            case "link_previews": return { enabled: true, instagram_proxy: false };
            case "instagram_proxy_disclosure":
                return "Instagram shows nothing to logged-out visitors, so a preview has to come " +
                    "from a third-party proxy. That proxy will see the link. The proxy used is zzinstagram.com.";
            default: return null;
        }
    });
}

const pw = playwright();
if (!pw && process.env.CAIRN_REQUIRE_BROWSER_TEST === "1") {
    throw new Error("CAIRN_REQUIRE_BROWSER_TEST=1 but playwright is not installed");
}

test(
    "link cards render as the sender's claim, show the real host, and never run markup",
    { skip: pw ? false : "playwright is not installed" },
    async () => {
        const browser = await launch(pw);
        try {
            const page = await browser.newPage({ viewport: { width: 1180, height: 1000 } });
            const calls = [];
            const remote = [];
            // Anything not served from ui/ is a request the page should never make.
            await page.route("**/*", (route) => {
                const url = new URL(route.request().url());
                if (url.hostname !== "localhost") {
                    remote.push(url.href);
                    return route.abort();
                }
                const file = path.join(UI, url.pathname === "/" ? "index.html" : url.pathname);
                if (!file.startsWith(UI) || !fs.existsSync(file)) return route.fulfill({ status: 404 });
                const type = file.endsWith(".css") ? "text/css"
                    : file.endsWith(".js") ? "text/javascript" : "text/html";
                return route.fulfill({ contentType: type, body: fs.readFileSync(file) });
            });
            await stub(page, calls);
            await page.addInitScript(() => {
                window.__TAURI__ = { core: { invoke: (cmd, args) => window.__invoke(cmd, args) } };
            });
            await page.goto("http://localhost/");

            // A real portrait JPEG, as Rust's thumbnail code would have produced.
            const thumb = await page.evaluate(() => {
                const c = document.createElement("canvas");
                c.width = 270; c.height = 480;
                const g = c.getContext("2d");
                const grad = g.createLinearGradient(0, 0, 270, 480);
                grad.addColorStop(0, "#f58529"); grad.addColorStop(0.5, "#dd2a7b"); grad.addColorStop(1, "#515bd4");
                g.fillStyle = grad; g.fillRect(0, 0, 270, 480);
                g.fillStyle = "rgba(255,255,255,0.85)";
                g.beginPath(); g.ellipse(135, 300, 80, 45, 0, 0, Math.PI * 2); g.fill();
                g.fillStyle = "#222"; g.beginPath(); g.arc(110, 290, 8, 0, Math.PI * 2); g.arc(160, 290, 8, 0, Math.PI * 2); g.fill();
                return c.toDataURL("image/jpeg", 0.8);
            });
            history[0].card.thumbnail = thumb;

            await page.click("#go");
            await page.waitForSelector("#rooms li");
            await page.click("#rooms li");
            await page.waitForSelector(".link-card");

            const cards = await page.$$eval(".link-card", (els) => els.map((e) => ({
                text: e.innerText,
                portrait: e.classList.contains("portrait"),
                img: e.querySelector("img")?.getAttribute("src")?.slice(0, 22) || null,
                play: !!e.querySelector(".play"),
                markup: e.querySelectorAll("script, iframe, .card-meta img").length,
            })));
            assert.strictEqual(cards.length, 3);

            // The reel: thumbnail from the data: URI, play glyph, kind, author, real host,
            // and the proxy caveat a proxied card must carry.
            assert.ok(cards[0].portrait && cards[0].play);
            assert.strictEqual(cards[0].img, "data:image/jpeg;base64");
            for (const s of ["INSTAGRAM · REEL", "@diegoquinteiro", "www.instagram.com", "third-party proxy", "supplied by the sender"]) {
                assert.ok(cards[0].text.includes(s), `reel card should show ${s}: ${cards[0].text}`);
            }

            // A reel with nothing fetched says what its URL says, and claims nothing else.
            assert.ok(cards[1].text.includes("Instagram reel"), cards[1].text);
            assert.ok(cards[1].text.includes("No preview available"), cards[1].text);
            assert.ok(cards[1].play && !cards[1].img);

            // The disguise: titled "Reuters", goes to evil.test. The host and the warning are
            // on screen, and the sender's markup is inert text.
            assert.ok(cards[2].text.includes("↗ evil.test"), cards[2].text);
            assert.ok(cards[2].text.includes("not where it goes"), cards[2].text);
            assert.ok(cards[2].text.includes("<img src=x"), "markup is shown as text");
            assert.strictEqual(cards[2].markup, 0);
            assert.strictEqual(await page.evaluate(() => window.__pwned), undefined);

            // The settings explain themselves; the proxy disclosure comes from Rust.
            assert.ok((await page.innerText(".prefs")).includes("site sees your IP"));
            assert.ok((await page.innerText("#ig-proxy-note")).includes("will see the link"));
            assert.strictEqual(await page.isChecked("#pref-ig-proxy"), false);

            if (process.env.CAIRN_SCREENSHOT) {
                await page.screenshot({ path: process.env.CAIRN_SCREENSHOT });
            }

            // Clicking opens through Rust, with the URL exactly as sent.
            await page.click(".link-card >> nth=0");
            assert.deepStrictEqual(calls.find(([c]) => c === "open_link"), ["open_link", { url: REEL }]);

            // Sending shows the sender's own message and card, which polling never would.
            calls.length = 0;
            await page.fill("#text", "look " + BARE_REEL);
            await page.press("#text", "Enter");
            await page.waitForFunction(() => document.querySelectorAll(".link-card").length === 4);
            assert.ok(calls.some(([c, a]) => c === "send" && a.text === "look " + BARE_REEL));

            assert.deepStrictEqual(remote, [], "the page must not fetch anything remote");
        } finally {
            await browser.close();
        }
    }
);
