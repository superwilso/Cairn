// Cairn desktop UI.
//
// Every function here is presentation. Protocol decisions live in Rust — see
// ../src-tauri/src/main.rs and cairn_client_core::session. If something in this file starts
// deciding *whether* a room is encrypted, rather than displaying what Rust said, that is a
// bug of the kind ADR-006 exists to prevent.

const invoke = window.__TAURI__.core.invoke;
const $ = (id) => document.getElementById(id);

let openRoom = null;
let pollTimer = null;

const show = (el, on) => { el.hidden = !on; };
const fail = (el, e) => { el.textContent = e ? String(e) : ""; };

// ---- sign in ---------------------------------------------------------------

$("go").onclick = async () => {
    fail($("signin-error"), null);
    try {
        const me = await invoke("sign_in", {
            profile: $("profile").value.trim() || "me",
            server: $("server").value.trim(),
        });
        $("whoami").textContent = me.user;

        // The transport badge is not cosmetic. MLS protects message bodies either way, but
        // over http:// every id, every membership change and every request is in the clear
        // and modifiable. Saying "encrypted" here would be a claim the threat model does
        // not support.
        $("transport").textContent = me.tls ? "TLS" : "plaintext-transport";
        $("transport").className = "badge " + (me.tls ? "ok" : "warn");

        show($("signin"), false);
        show($("app"), true);
        // Without published key packages nobody can add this device to a group, and the
        // failure looks like "my friend cannot add me" much later.
        try { await invoke("publish_key_packages", { count: 5 }); } catch (_) {}
        await refreshRooms();
    } catch (e) {
        fail($("signin-error"), e);
    }
};

// ---- rooms -----------------------------------------------------------------

async function refreshRooms() {
    const rooms = await invoke("rooms");
    const list = $("rooms");
    list.textContent = "";
    for (const room of rooms) {
        const li = document.createElement("li");
        li.className = room.id === openRoom ? "active" : "";

        const tier = document.createElement("span");
        // The tier string is computed locally in Rust from the room's sealed shape, never
        // taken from the instance's word for it.
        tier.className = "badge " + (room.e2ee ? "ok" : "warn");
        tier.textContent = room.tier;

        const name = document.createElement("span");
        name.className = "mono room-name";
        name.textContent = room.id.replace(/^rom_/, "").slice(0, 8);

        li.append(tier, name);
        if (!room.joined) {
            const pending = document.createElement("span");
            pending.className = "pending";
            pending.textContent = "not admitted";
            li.append(pending);
        }
        li.onclick = () => selectRoom(room.id);
        list.append(li);
    }
}

$("new-group").onclick = async () => {
    try {
        // A group, not a DM: is_direct false and not discoverable, which seals as T2 —
        // still end-to-end encrypted. Only discoverability would drop it to T3.
        const room = await invoke("create_group", { ceiling: 50 });
        await refreshRooms();
        await selectRoom(room);
    } catch (e) { fail($("error"), e); }
};

$("new-direct").onclick = async () => {
    try {
        const room = await invoke("create_direct");
        await refreshRooms();
        await selectRoom(room);
    } catch (e) { fail($("error"), e); }
};

$("join").onclick = async () => {
    try {
        const room = await invoke("redeem_invite", { token: $("invite-token").value.trim() });
        $("invite-token").value = "";
        await refreshRooms();
        await selectRoom(room);
        // Redeeming joins the room; it does not hand over the group keys. Said plainly so
        // an empty room does not read as a bug.
        addNotice("Joined. A member must admit you before anything here is readable.");
    } catch (e) { fail($("error"), e); }
};

$("invite").onclick = async () => {
    try {
        const token = await invoke("create_invite", { uses: 1, hours: 24 });
        addNotice("Invite (1 use, 24h) — shown once: " + token);
    } catch (e) { fail($("error"), e); }
};

// ---- one room --------------------------------------------------------------

async function selectRoom(room) {
    fail($("error"), null);
    openRoom = room;
    $("room-id").textContent = room;
    $("timeline").textContent = "";
    try {
        const history = await invoke("open_room", { room });
        for (const m of history) addMessage(m);
    } catch (e) { fail($("error"), e); }
    await refreshRooms();
    await refreshMembers();
    startPolling();
}

async function refreshMembers() {
    if (!openRoom) return;
    let members = [];
    try { members = await invoke("members"); } catch (_) { return; }

    const list = $("member-list");
    list.textContent = "";
    const waiting = [];
    for (const m of members) {
        const li = document.createElement("li");
        li.className = "mono";
        li.textContent = m.user.replace(/^usr_/, "").slice(0, 8) + " " + m.role;
        if (!m.in_group) {
            li.classList.add("pending");
            li.title = "in the room, but not in the encrypted group — cannot read it";
            waiting.push(m.user);
        } else if (!m.verified) {
            // Unverified is the honest default: nobody is verified until safety numbers
            // have been compared out of band.
            li.title = "safety number not compared";
        }
        list.append(li);
    }

    show($("waiting"), waiting.length > 0);
    $("waiting-text").textContent =
        waiting.length + " joined by invite and cannot read this room yet";
}

$("admit").onclick = async () => {
    try {
        const admitted = await invoke("admit_waiting");
        addNotice("Admitted " + admitted.length + " to the encrypted group.");
        await refreshMembers();
    } catch (e) { fail($("error"), e); }
};

$("composer").onsubmit = async (ev) => {
    ev.preventDefault();
    const text = $("text").value;
    if (!text.trim()) return;
    try {
        await invoke("send", { text });
        $("text").value = "";
        fail($("error"), null);
    } catch (e) { fail($("error"), e); }
};

// ---- polling ---------------------------------------------------------------
//
// Polling rather than push: the server has no websocket yet. Deliberately modest, because
// every poll is a request the instance can time.

function startPolling() {
    if (pollTimer) clearInterval(pollTimer);
    pollTimer = setInterval(tick, 1500);
    tick();
}

async function tick() {
    if (!openRoom) return;
    let events = [];
    try { events = await invoke("poll"); } catch (_) { return; }
    let membershipChanged = false;

    for (const ev of events) {
        if (ev.kind === "message") {
            addMessage(ev);
        } else if (ev.kind === "membership") {
            membershipChanged = true;
            // A silently added member is a wiretap. Membership changes are shown in the
            // timeline, not folded away into a member list nobody is looking at.
            for (const who of ev.joined) addNotice("joined the group: " + short(who));
            for (const who of ev.left) addNotice("left the group: " + short(who));
        } else if (ev.kind === "removed") {
            addNotice("You were removed from this room.");
            clearInterval(pollTimer);
            openRoom = null;
            await refreshRooms();
        }
    }
    if (membershipChanged) await refreshMembers();
}

// ---- rendering -------------------------------------------------------------

const short = (id) => String(id).replace(/^usr_/, "").slice(0, 8);

function addMessage(m) {
    const li = document.createElement("li");
    li.className = m.historic ? "msg historic" : "msg";
    const who = document.createElement("span");
    who.className = "mono who";
    who.textContent = short(m.sender);
    const body = document.createElement("span");
    // textContent, never innerHTML: a message body is attacker-controlled text and this is
    // the one line standing between that and script execution in the client.
    body.textContent = m.body;
    li.append(who, body);
    $("timeline").append(li);
    li.scrollIntoView({ block: "end" });
}

function addNotice(text) {
    const li = document.createElement("li");
    li.className = "notice";
    li.textContent = text;
    $("timeline").append(li);
    li.scrollIntoView({ block: "end" });
}
