// Spaces in the real UI, in a real browser: the rail, a space's channels, and its people.
//
// ## Why this exists
//
// spaces.js draws who may do what in a space, which makes it the place a UI is most tempted
// to start deciding. It must not: every control is shown or withheld on a flag Rust handed
// over, and those flags are the instance's (crates/cairn-server/src/state.rs, tested there,
// attacked over HTTP in crates/cairn-server/tests/spaces_http.rs). So this checks the drawn
// half — that the controls follow the flags exactly, including when the flags would surprise
// a UI that thought it knew better, and that each action asks Rust and redraws from Rust's
// answer.
//
// The page is the shipped `ui/` directory, served from http://localhost with the CSP from
// tauri.conf.json, and `window.__TAURI__.core.invoke` answers from a stand-in that records
// every call.
//
// Run: node --test clients/desktop/tests/spaces.browser.test.js
// Skipped when Playwright or its Chromium is missing; CAIRN_REQUIRE_BROWSER_TEST=1 turns the
// skip into a failure, as for the other browser tests. CAIRN_SCREENSHOT_DIR saves a picture.

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

// The stand-in for Rust. Two spaces: one where this account runs things, one where it is a
// plain member. The flags in each are what Rust would hand over; the UI must follow them.
function stub() {
    const ME = "usr_me000000aaaa";
    const ALICE = "usr_alice000bbbb";
    const MALLORY = "usr_mallory0cccc";
    const OWNER = "usr_owner000dddd";
    const NOTE = "Your instance can see this space's name, its channels and roles, and who " +
        "is in it. In an end-to-end encrypted channel it cannot read the messages.";
    const roles = {
        mods: { id: "rol_mods", name: "mods", permissions: ["read", "send", "kick"], position: 3, manageable: true, assignable: true },
        // Below the viewer, so manageable — but it carries a permission the viewer lacks,
        // so Rust says it is not assignable. A UI that offered it on rank alone would be
        // working out a rule the instance already answered.
        admins: { id: "rol_admins", name: "admins", permissions: ["read", "manage_roles"], position: 2, manageable: true, assignable: false },
        elders: { id: "rol_elders", name: "elders", permissions: ["read"], position: 9, manageable: false, assignable: false },
    };
    const trail = {
        id: "spc_trail", name: "Trailhead", owner: ME, i_am_owner: true,
        my_permissions: ["read", "send", "invite", "kick", "manage_channels", "manage_roles"],
        everyone: ["read", "send"], everyone_manageable: true,
        roles: [roles.elders, roles.mods, roles.admins],
        members: [
            { user: ME, roles: [], owner: true, manageable: false, roles_editable: true },
            { user: ALICE, roles: ["rol_mods"], owner: false, manageable: true, roles_editable: true },
            // In the space, and ranked at or above the viewer: no Remove, no role changes,
            // even though the viewer holds `kick`.
            { user: MALLORY, roles: ["rol_elders"], owner: false, manageable: false, roles_editable: false },
        ],
        channels: [
            { id: "rom_general0", name: "general", tier: "T2", e2ee: true, can_send: true, joined: true, overrides: [] },
            { id: "rom_announce", name: "announcements", tier: "T2", e2ee: true, can_send: false, joined: true, overrides: [] },
            { id: "rom_lobby000", name: "lobby", tier: "T3", e2ee: false, can_send: true, joined: false, overrides: [] },
        ],
        visibility_note: NOTE,
    };
    const camp = {
        id: "spc_camp", name: "Base Camp", owner: OWNER, i_am_owner: false,
        my_permissions: ["read", "send"], everyone: ["read", "send"], everyone_manageable: false,
        roles: [{ ...roles.mods, manageable: false, assignable: false }],
        members: [
            { user: OWNER, roles: [], owner: true, manageable: false, roles_editable: false },
            { user: ME, roles: [], owner: false, manageable: false, roles_editable: false },
        ],
        channels: [{ id: "rom_camp0000", name: "fireside", tier: "T2", e2ee: true, can_send: true, joined: false, overrides: null }],
        visibility_note: NOTE,
    };
    const spaces = { spc_trail: trail, spc_camp: camp };
    let unlisted = false;
    window.__calls = [];
    window.__setUnlisted = (v) => { unlisted = v; };

    const answers = {
        sign_in: () => ({ user: ME, tls: true }),
        rooms: () => [{ id: "rom_dm000000", e2ee: true, tier: "T1", joined: true }],
        // An instance from before spaces answers nothing at all.
        spaces: () => window.__noSpaces ? null : Object.values(spaces).map((s) => ({ id: s.id, name: s.name })),
        link_previews: () => ({ instagram: false, youtube: false, tiktok: false, x: false, reddit: false, web: false, instagram_proxy: false }),
        space: ({ space }) => {
            if (!spaces[space]) throw "not a member of this space";
            return JSON.parse(JSON.stringify(spaces[space]));
        },
        create_space: ({ name }) => {
            const id = "spc_new" + Object.keys(spaces).length;
            spaces[id] = { ...camp, id, name, owner: ME, i_am_owner: true, channels: [],
                my_permissions: trail.my_permissions, members: [{ user: ME, roles: [], owner: true, manageable: false, roles_editable: true }] };
            return id;
        },
        kick: ({ space, user }) => {
            spaces[space].members = spaces[space].members.filter((m) => m.user !== user);
        },
        assign_role: ({ space, user, role }) => {
            spaces[space].members.find((m) => m.user === user).roles.push(role);
        },
        open_room: () => [],
        open_room_tier: () => "T2",
        room_timer: () => null,
        members: () => [
            { user: ME, role: "owner", in_group: true, verified: false, key_changed: false },
            ...(unlisted ? [{ user: MALLORY, role: "unlisted", in_group: true, verified: false, key_changed: false }] : []),
        ],
        remove_departed: () => { unlisted = false; return [MALLORY]; },
        poll: () => [],
        call_config: () => ({ ice_servers: [], has_relay: false, max_participants: 8 }),
        attachment_limits: () => ({ max_bytes: 1 << 20 }),
    };
    window.__TAURI__ = {
        core: {
            invoke: async (cmd, args) => {
                window.__calls.push({ cmd, args: args || null });
                return answers[cmd] ? answers[cmd](args || {}) : null;
            },
        },
    };
}

async function openPage(browser, { noSpaces = false } = {}) {
    const page = await browser.newPage({ viewport: { width: 1280, height: 800 } });
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
    if (noSpaces) await page.addInitScript(() => { window.__noSpaces = true; });
    await page.addInitScript(stub);
    await page.goto("http://localhost/index.html");
    page.errors = errors;
    await page.click("#go");
    await page.waitForSelector(noSpaces ? "#rooms li" : "#space-list .rail-btn");
    return page;
}

const calls = (page, cmd) =>
    page.evaluate((c) => window.__calls.filter((x) => x.cmd === c), cmd);

async function openSpace(page, id) {
    await page.click(`#space-list .rail-btn[data-space="${id}"]`);
    await page.waitForSelector("#space-pane:not([hidden]) #channels li");
}

async function shoot(page, name) {
    if (!SHOTS) return;
    fs.mkdirSync(SHOTS, { recursive: true });
    // Let the arrival animations finish, or the picture is of a half-faded page.
    await page.waitForTimeout(1200);
    await page.screenshot({ path: path.join(SHOTS, name + ".png") });
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

test("the rail lists spaces, and Home still holds the DMs and groups", { skip }, async () => {
    const page = await openPage(browser);
    const rail = await page.$$eval("#space-list .rail-btn", (bs) => bs.map((b) => [b.textContent, b.title]));
    assert.deepStrictEqual(rail, [["TR", "Trailhead"], ["BC", "Base Camp"]]);
    assert.ok(await page.$eval("#rail-home", (b) => b.classList.contains("active")));
    assert.ok(await page.isVisible("#rooms li"), "the room list is where it was");
    assert.ok(!(await page.isVisible("#space-pane")));
    assert.deepStrictEqual(page.errors, []);
    await page.close();
});

test("a space lists its channels with the tier Rust derived, and says what the instance sees", { skip }, async () => {
    const page = await openPage(browser);
    await openSpace(page, "spc_trail");
    assert.ok(!(await page.isVisible("#rooms")), "Home's list gives way to the channels");
    assert.strictEqual(await page.textContent("#space-name"), "Trailhead");
    assert.match(await page.textContent("#space-note"), /can see this space's name.*cannot read the messages/);

    const rows = await page.$$eval("#channels li", (ls) => ls.map((l) => ({
        name: l.querySelector(".channel-name").textContent,
        tier: l.querySelector(".badge").textContent,
        tone: l.querySelector(".badge").className,
        flags: [...l.querySelectorAll(".pending, .chan-flag")].map((f) => f.textContent),
    })));
    assert.deepStrictEqual(rows, [
        { name: "general", tier: "T2", tone: "badge ok", flags: [] },
        { name: "announcements", tier: "T2", tone: "badge ok", flags: ["read-only"] },
        { name: "lobby", tier: "T3", tone: "badge warn", flags: ["waiting"] },
    ]);
    // The badge is the security layer's, whatever this stylesheet does.
    const bg = await page.$eval("#channels li .badge.ok", (b) => getComputedStyle(b).backgroundColor);
    assert.strictEqual(bg, "rgb(29, 107, 67)");
    await shoot(page, "spaces");
    assert.deepStrictEqual(page.errors, []);
    await page.close();
});

test("the controls follow Rust's flags, not the UI's own idea of rank", { skip }, async () => {
    const page = await openPage(browser);
    await openSpace(page, "spc_trail");
    assert.ok(await page.isVisible("#new-channel"));
    assert.ok(await page.isVisible("#space-invite"));
    assert.ok(!(await page.isVisible("#space-leave")), "the owner cannot leave");

    const kickable = await page.$$eval("#space-members li", (ls) =>
        ls.filter((l) => l.querySelector(".kick")).map((l) => l.dataset.user));
    assert.deepStrictEqual(kickable, ["usr_alice000bbbb"], "Remove only where Rust said manageable");
    // Mallory's elders role ranks above the viewer: no × on it, no picker for her.
    assert.strictEqual(await page.$$eval('#space-members li[data-user="usr_mallory0cccc"] .chip-x, #space-members li[data-user="usr_mallory0cccc"] select', (x) => x.length), 0);
    // The picker offers only what Rust marked assignable — not `admins`, which is below the
    // viewer but carries a permission they lack.
    const offered = await page.$$eval('#space-members li[data-user="usr_alice000bbbb"] select option', (os) => os.map((o) => o.value));
    assert.deepStrictEqual(offered, [], "alice holds mods and admins is not assignable: no picker at all");
    const mine = await page.$$eval('#space-members li[data-user="usr_me000000aaaa"] select option', (os) => os.map((o) => o.value));
    assert.deepStrictEqual(mine, ["", "rol_mods"]);

    // The same UI, in a space where this account is nobody in particular.
    await openSpace(page, "spc_camp");
    for (const id of ["#new-channel", "#space-invite"]) {
        assert.ok(!(await page.isVisible(id)), id + " is withheld without the permission");
    }
    assert.ok(await page.isVisible("#space-leave"));
    assert.strictEqual(await page.$$eval("#space-members .kick, #space-members select, #space-members .chip-x", (x) => x.length), 0);
    assert.deepStrictEqual(page.errors, []);
    await page.close();
});

test("opening a channel opens its room and names it in the header", { skip }, async () => {
    const page = await openPage(browser);
    await openSpace(page, "spc_trail");
    await page.click('#channels li[data-channel="rom_general0"]');
    await page.waitForFunction(() => document.getElementById("room-id").textContent === "# general");
    const opened = await calls(page, "open_room");
    assert.deepStrictEqual(opened.map((c) => c.args.room), ["rom_general0"]);
    assert.ok(await page.$eval('#channels li[data-channel="rom_general0"]', (l) => l.classList.contains("active")));
    await shoot(page, "spaces-channel");
    assert.deepStrictEqual(page.errors, []);
    await page.close();
});

test("removing someone asks Rust, then redraws from Rust's answer", { skip }, async () => {
    const page = await openPage(browser);
    await openSpace(page, "spc_trail");
    await page.click('#space-members li[data-user="usr_alice000bbbb"] .kick');
    await page.waitForFunction(() => !document.querySelector('#space-members li[data-user="usr_alice000bbbb"]'));
    assert.deepStrictEqual((await calls(page, "kick")).map((c) => c.args), [{ space: "spc_trail", user: "usr_alice000bbbb" }]);
    // And the timeline says what a kick does not do.
    assert.match(await page.textContent("#timeline"), /still hold the group's keys until someone removes them/);

    await page.selectOption('#space-members li[data-user="usr_me000000aaaa"] select', "rol_mods");
    await page.waitForSelector('#space-members li[data-user="usr_me000000aaaa"] .role-chip:not(.owner)');
    assert.deepStrictEqual((await calls(page, "assign_role")).map((c) => c.args),
        [{ space: "spc_trail", user: "usr_me000000aaaa", role: "rol_mods" }]);
    assert.deepStrictEqual(page.errors, []);
    await page.close();
});

test("a removed member still in the encrypted group is shown, and removing them is a choice", { skip }, async () => {
    const page = await openPage(browser);
    await openSpace(page, "spc_trail");
    await page.evaluate(() => window.__setUnlisted(true));
    await page.click('#channels li[data-channel="rom_general0"]');
    await page.waitForSelector("#departed:not([hidden])");
    assert.match(await page.textContent("#departed-text"), /1 no longer in this room still hold its keys/);
    assert.strictEqual((await calls(page, "remove_departed")).length, 0, "never automatic");
    // Amber from the security layer, like the waiting banner.
    const bg = await page.$eval("#departed", (d) => getComputedStyle(d).backgroundColor);
    assert.strictEqual(bg, "rgb(247, 201, 72)");

    await page.click("#evict");
    await page.waitForSelector("#departed[hidden]", { state: "attached" });
    assert.strictEqual((await calls(page, "remove_departed")).length, 1);
    assert.deepStrictEqual(page.errors, []);
    await page.close();
});

test("creating a space puts it on the rail and opens it", { skip }, async () => {
    const page = await openPage(browser);
    await page.click("#new-space");
    await page.fill("#space-create-name", "Night Hike");
    await page.click("#space-create button[type=submit]");
    await page.waitForFunction(() => document.getElementById("space-name").textContent === "Night Hike");
    assert.deepStrictEqual((await calls(page, "create_space")).map((c) => c.args), [{ name: "Night Hike" }]);
    const rail = await page.$$eval("#space-list .rail-btn", (bs) => bs.map((b) => b.textContent));
    assert.ok(rail.includes("NH"));
    assert.match(await page.textContent("#channels"), /No channels yet/);
    assert.deepStrictEqual(page.errors, []);
    await page.close();
});

test("the rail fits a narrow window without pushing the timeline out", { skip }, async () => {
    const page = await openPage(browser);
    await page.setViewportSize({ width: 820, height: 700 });
    await openSpace(page, "spc_trail");
    const cols = await page.$eval("#app", (a) => getComputedStyle(a).gridTemplateColumns.split(" ").length);
    assert.strictEqual(cols, 3, "rail, sidebar, main — members fold away as before");
    const main = await page.$eval("main", (m) => m.getBoundingClientRect().width);
    assert.ok(main > 400, "the timeline keeps its room: " + main);
    assert.deepStrictEqual(page.errors, []);
    await page.close();
});

test("an instance without spaces does not stop the rest of sign-in", { skip }, async () => {
    // Regression. spaces.js once iterated whatever `spaces` returned, a null threw, and the
    // throw aborted sign-in before link-preview settings loaded — found by the link-card test,
    // whose stand-in knew nothing about spaces, going red.
    const page = await openPage(browser, { noSpaces: true });
    await page.waitForFunction(() => window.__calls.some((c) => c.cmd === "link_previews"));
    assert.strictEqual(await page.$$eval("#space-list .rail-btn", (b) => b.length), 0);
    assert.ok(await page.isVisible("#rooms li"));
    assert.deepStrictEqual(page.errors, []);
    await page.close();
});
