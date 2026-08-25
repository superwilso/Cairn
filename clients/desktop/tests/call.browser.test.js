// A real call, in a real browser, between two real peer connections.
//
// ## Why this exists on top of mesh.test.js
//
// `mesh.test.js` stubs RTCPeerConnection, so it proves the *decisions* — who offers, whether
// an early candidate is buffered, whether a camera switch renegotiates — against a fake that
// agrees with the code by construction. It cannot prove that the SDP those decisions produce
// actually connects anything.
//
// This one runs `ui/call.js` unchanged in two Chromium pages with fake media devices, wires
// their signalling together through a relay that ports `Session::reconcile`, and asserts that
// both sides reach `connectionState === "connected"` and that media arrives. Loopback host
// candidates are enough; no STUN is involved.
//
// Run: node --test clients/desktop/tests/call.browser.test.js
//
// **Skipped when Playwright or its Chromium is not installed**, rather than failing — this
// is a development-machine check, not something to make a clean checkout red. When it skips,
// it says so.

const test = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");

const CALL_JS = fs.readFileSync(path.join(__dirname, "../ui/call.js"), "utf8");

// Where Playwright's own browser lives varies: `npx playwright install` puts it under
// ~/.cache/ms-playwright, while this development container ships one at /opt/pw-browsers with
// a layout Playwright's default resolution does not find. Try Playwright's own answer first
// and fall back to the container's.
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
    const args = [
        // A container has no camera. These give Chromium a synthetic one and stop it asking
        // for permission, so the code under test is the code that ships.
        "--use-fake-device-for-media-stream",
        "--use-fake-ui-for-media-stream",
    ];
    try {
        return await pw.chromium.launch({ args });
    } catch (first) {
        const executablePath = findChromium();
        if (!executablePath) throw first;
        return await pw.chromium.launch({ args, executablePath });
    }
}

function playwright() {
    for (const base of [null, "/opt/node22/lib/node_modules", "/usr/lib/node_modules"]) {
        try {
            return require(base ? path.join(base, "playwright") : "playwright");
        } catch (_) { /* try the next */ }
    }
    return null;
}

// `Session::reconcile`, ported. The browsers have no Rust, so the relay stands in for it —
// including the part that matters most, that each participant mints its own call id.
class Relay {
    constructor() {
        this.state = new Map();
        this.pages = new Map();
        // Delivery is queued rather than awaited inline. Handling a signal in one page sends
        // signals to the other, and awaiting that chain inside the first page's evaluate
        // nests browser calls arbitrarily deep. Queuing also models the real thing better:
        // signals arrive from a poll, not from inside the sender's call stack.
        this.queues = new Map();
        this.pumping = new Set();
    }

    peer(user) {
        if (!this.state.has(user)) this.state.set(user, { call: null, negotiated: false });
        return this.state.get(user);
    }

    async invoke(user, cmd, args) {
        const me = this.peer(user);
        if (cmd === "call_config") {
            return { ice_servers: [], has_relay: false, max_participants: 6 };
        }
        if (cmd === "call_join") {
            me.call = me.call || "call-from-" + user;
            this.fanout(user, { call: me.call, kind: "join", payload: "" });
            return me.call;
        }
        if (cmd === "call_leave") {
            if (me.call) this.fanout(user, { call: me.call, kind: "leave", payload: "" });
            me.call = null;
            me.negotiated = false;
            return null;
        }
        if (cmd === "signal") {
            const s = { ...args.signal, call: me.call || args.signal.call };
            if (s.kind === "offer" || s.kind === "answer") me.negotiated = true;
            this.fanout(user, s);
            return null;
        }
        throw new Error("unexpected command " + cmd);
    }

    fanout(from, signal) {
        for (const [user] of this.pages) {
            if (user === from) continue;
            if (signal.to && signal.to !== user) continue;
            if (!this.queues.has(user)) this.queues.set(user, []);
            this.queues.get(user).push({ from, signal });
            this.pump(user);
        }
    }

    // One at a time per recipient, so a page never has two handlers running at once — the
    // same guarantee the poll loop gives.
    async pump(user) {
        if (this.pumping.has(user)) return;
        this.pumping.add(user);
        try {
            const queue = this.queues.get(user);
            while (queue && queue.length) {
                const { from, signal } = queue.shift();
                // Reconciliation happens at delivery, exactly as `Session::poll` does it.
                const delivered = this.reconcile(user, signal);
                if (!delivered) continue;
                await this.pages
                    .get(user)
                    .evaluate(([f, s]) => window.CairnCall.handle(f, s), [from, delivered])
                    .catch((e) => console.error(user + " handle failed:", e.message));
            }
        } finally {
            this.pumping.delete(user);
        }
    }

    async idle() {
        for (let i = 0; i < 200; i++) {
            const busy = this.pumping.size > 0 ||
                [...this.queues.values()].some((q) => q.length > 0);
            if (!busy) return;
            await new Promise((r) => setTimeout(r, 25));
        }
        throw new Error("signalling never settled");
    }

    reconcile(user, signal) {
        const me = this.peer(user);
        if (!me.call) {
            if (signal.kind === "join" || signal.kind === "leave") return signal;
            return null;
        }
        if (signal.call !== me.call && signal.kind === "join" && !me.negotiated) {
            if (signal.to || signal.call < me.call) me.call = signal.call;
        }
        if (signal.call !== me.call && signal.kind !== "join") return null;
        if (signal.kind === "offer" || signal.kind === "answer") me.negotiated = true;
        return { ...signal, call: me.call };
    }
}

async function openClient(browser, relay, user) {
    const page = await browser.newPage();
    page.on("pageerror", (e) => console.error(user + " page error:", e.message));
    page.on("console", (m) => {
        if (m.type() === "error") console.error(user + " console:", m.text());
    });
    await page.exposeFunction("__relay", (cmd, args) => relay.invoke(user, cmd, args));
    await page.addInitScript(`
        window.__TAURI__ = { core: { invoke: (cmd, args) => window.__relay(cmd, args) } };
        window.__seen = { tracks: [], states: [] };
    `);
    // Not about:blank: `navigator.mediaDevices` only exists in a secure context, and
    // about:blank is not one. `http://localhost` is — the same reason Tauri serves the app
    // from `http://tauri.localhost` on Windows rather than a bare custom scheme.
    await page.route("http://localhost/cairn", (route) =>
        route.fulfill({ contentType: "text/html", body: "<!doctype html><title>cairn</title>" })
    );
    await page.goto("http://localhost/cairn");
    // `const CairnCall = ...` at the top level of a classic script goes into the global
    // *lexical* scope, not onto `window`. The app is unaffected — app.js shares that scope —
    // but page.evaluate runs in its own function, so the binding has to be published.
    await page.addScriptTag({ content: CALL_JS + "\n;window.CairnCall = CairnCall;" });
    await page.evaluate(() => {
        window.CairnCall.bind({
            onPeer: (u, s) => window.__seen.tracks.push([u, s ? s.getTracks().length : 0]),
            onState: (u, st) => window.__seen.states.push([u, st]),
            onNotice: (t) => window.__seen.states.push(["notice", t]),
        });
    });
    relay.pages.set(user, page);
    return page;
}

const pw = playwright();

// A test that quietly skips is a test that passes for the wrong reason. CI sets this so a
// missing browser fails the job instead of being reported as green.
const REQUIRED = process.env.CAIRN_REQUIRE_BROWSER_TEST === "1";
if (!pw && REQUIRED) {
    throw new Error("CAIRN_REQUIRE_BROWSER_TEST=1 but playwright is not installed");
}

test(
    "two clients actually connect, and media crosses",
    { skip: pw ? false : "playwright is not installed" },
    async () => {
        const browser = await launch(pw);
        try {
            const relay = new Relay();
            const a = await openClient(browser, relay, "usr_a");
            const b = await openClient(browser, relay, "usr_b");

            await a.evaluate(() => window.CairnCall.join({ video: true, myUser: "usr_a" }));
            await b.evaluate(() => window.CairnCall.join({ video: true, myUser: "usr_b" }));

            const connected = async (page) => {
                await page.waitForFunction(
                    () => window.__seen.states.some(([, s]) => s === "connected"),
                    null,
                    { timeout: 20000 }
                );
            };
            await Promise.all([connected(a), connected(b)]);

            // Connected is not the same as receiving anything: a peer connection reaches
            // "connected" on transport alone. The tracks arrive slightly after, so this
            // waits rather than sampling once — a single sample raced the video track and
            // reported a working call as broken.
            for (const [name, page] of [["alice", a], ["bob", b]]) {
                await page
                    .waitForFunction(
                        () => window.__seen.tracks.some(([, n]) => n >= 2),
                        null,
                        { timeout: 15000 }
                    )
                    .catch(async () => {
                        const seen = await page.evaluate(() => window.__seen.tracks);
                        assert.fail(
                            `${name} must receive audio and video from the peer, saw ` +
                                JSON.stringify(seen)
                        );
                    });
            }
        } finally {
            await browser.close();
        }
    }
);
