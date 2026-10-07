// Cairn desktop UI.
//
// Every function here is presentation. Protocol decisions live in Rust — see
// ../src-tauri/src/main.rs and cairn_client_core::session. If something in this file starts
// deciding *whether* a room is encrypted, rather than displaying what Rust said, that is a
// bug of the kind ADR-006 exists to prevent.
//
// Calls are in call.js. This file owns the DOM; that one owns RTCPeerConnection.

const invoke = window.__TAURI__.core.invoke;
const $ = (id) => document.getElementById(id);

let openRoom = null;
let pollTimer = null;
let myUser = null;
let inCall = false;
let sharing = false;
let muted = false;
let cameraOff = false;
let callStarted = 0;
let elapsedTimer = null;
let ringingFrom = null;
let callConfig = null;

const show = (el, on) => { el.hidden = !on; };
const fail = (el, e) => { el.textContent = e ? String(e) : ""; };
const short = (id) => String(id).replace(/^usr_|^rom_/, "").slice(0, 8);
const initials = (id) => short(id).slice(0, 2).toUpperCase();

// Polling is the only clock this client has, so the call handshake runs at its pace. An
// offer stuck behind a 1.5s tick makes a call take five seconds to connect for no reason;
// a call polls hard and idle rooms stay quiet.
const IDLE_POLL_MS = 1500;
const CALL_POLL_MS = 350;

// ---- sign in ---------------------------------------------------------------

$("go").onclick = async () => {
    fail($("signin-error"), null);
    try {
        const me = await invoke("sign_in", {
            profile: $("profile").value.trim() || "me",
            server: $("server").value.trim(),
            invite: $("reg-invite").value.trim() || null,
        });
        myUser = me.user;
        $("whoami").textContent = short(me.user);
        $("whoami").title = me.user;
        $("avatar").textContent = initials(me.user);

        // The transport badge is not cosmetic. MLS protects message bodies either way, but
        // over http:// every id, every membership change and every request is in the clear
        // and modifiable. Saying "encrypted" here would be a claim the threat model does
        // not support.
        $("transport").textContent = me.tls ? "TLS" : "plaintext";
        $("transport").className = "badge " + (me.tls ? "ok" : "warn");
        $("transport").title = me.tls
            ? "Transport is TLS."
            : "http:// — ids, membership changes and requests are in the clear on the wire.";

        show($("signin"), false);
        show($("app"), true);
        // Without published key packages nobody can add this device to a group, and the
        // failure looks like "my friend cannot add me" much later.
        try { await invoke("publish_key_packages", { count: 5 }); } catch (_) {}
        await refreshRooms();
        await describeRelay();
        await listDevices();
        await loadPreviewSettings();
    } catch (e) {
        fail($("signin-error"), e);
    }
};

for (const id of ["profile", "server", "reg-invite"]) {
    $(id).onkeydown = (ev) => { if (ev.key === "Enter") $("go").click(); };
}

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
        name.textContent = short(room.id);

        li.append(tier, name);
        if (!room.joined) {
            const pend = document.createElement("span");
            pend.className = "pending";
            pend.textContent = "waiting";
            li.append(pend);
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
    // Switching rooms during a call would leave the peer connections pointing at a room
    // this session is no longer polling, so the call ends first rather than half-surviving.
    if (inCall && room !== openRoom) await hangUp();

    fail($("error"), null);
    stopRinging();
    openRoom = room;
    $("room-id").textContent = short(room);
    $("room-id").title = room;
    $("timeline").textContent = "";
    try {
        const history = await invoke("open_room", { room });
        for (const m of history) addMessage(m);
    } catch (e) { fail($("error"), e); }

    // Derived in Rust from the room's sealed shape, never taken from the instance. An empty
    // badge is worse than none: it reads as "no protection stated" for a room that has one.
    try {
        const tier = await invoke("open_room_tier");
        const badge = $("room-tier");
        badge.textContent = tier || "";
        badge.className = "badge " + (tier === "T3" ? "warn" : "ok");
        badge.title = tier === "T3"
            ? "Transport-encrypted. The instance can read this room."
            : "End-to-end encrypted. The instance stores ciphertext it cannot read.";
    } catch (_) {}
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

        const av = document.createElement("span");
        av.className = "avatar";
        av.textContent = initials(m.user);

        const who = document.createElement("span");
        who.className = "mono who";
        who.textContent = short(m.user) + (m.role === "owner" ? " · owner" : "");

        li.append(av, who);
        li.title = m.user;

        if (!m.in_group) {
            li.classList.add("pending");
            li.title = "in the room, but not in the encrypted group — cannot read it";
            waiting.push(m.user);
        } else if (m.verified) {
            const tick = document.createElement("span");
            tick.className = "tick";
            tick.textContent = "✓";
            tick.title = "safety number compared";
            li.append(tick);
        } else {
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

// Sends are chained rather than run side by side. A message with a link waits for its
// preview (up to five seconds, in Rust, off the main thread), and a plain message typed
// after it must not overtake it.
let sendQueue = Promise.resolve();

$("composer").onsubmit = (ev) => {
    ev.preventDefault();
    const text = $("text").value;
    if (!text.trim()) return;
    $("text").value = "";
    sendQueue = sendQueue.then(async () => {
        try {
            // Rust returns the message as sent, card included: MLS never decrypts a
            // device's own message back to it, so this is the only way it appears.
            const sent = await invoke("send", { text });
            if (sent) addMessage(sent);
            fail($("error"), null);
        } catch (e) {
            fail($("error"), e);
            // Not sent; give the words back rather than losing them.
            if (!$("text").value) $("text").value = text;
        }
    });
};

// ---- calls -----------------------------------------------------------------

CairnCall.bind({
    onPeer: (user, stream) => {
        if (!stream) return removeTile(user);
        // The browser's own "stop sharing" control lives outside this UI, so call.js reports
        // the local stream back through the same channel as a peer's.
        const local = user === myUser;
        if (local) sharing = false;
        upsertTile(user, stream, { local });
        if (local) syncCallButtons();
    },
    onState: (user, state) => markTile(user, state),
    onNotice: (text) => addNotice(text),
    onEnd: () => teardownCallUi(),
});

$("start-voice").onclick = () => startCall(false);
$("start-video").onclick = () => startCall(true);
$("accept-voice").onclick = () => startCall(false);
$("accept-video").onclick = () => startCall(true);
$("hangup").onclick = () => hangUp();
// Dismissing hides the banner without leaving the call running for everyone else, and
// without pretending to the caller that anything happened.
$("decline").onclick = () => stopRinging();

// Somebody started a call in this room. `call_join` adopts the announced call id, so
// accepting joins *that* call rather than starting a rival one beside it.
function ring(from, signal) {
    if (signal.kind === "join") {
        ringingFrom = from;
        $("ringing-text").textContent = short(from) + " started a call";
        show($("ringing"), true);
    } else if (signal.kind === "leave" && from === ringingFrom) {
        stopRinging();
    }
}

function stopRinging() {
    ringingFrom = null;
    show($("ringing"), false);
}

async function startCall(video) {
    if (inCall || !openRoom) return;
    fail($("error"), null);
    stopRinging();
    try {
        const { local } = await CairnCall.join({ video, myUser });
        inCall = true;
        cameraOff = !video;
        muted = false;
        sharing = false;

        show($("stage"), true);
        $("tiles").textContent = "";
        upsertTile(myUser, local, { local: true });
        markTile(myUser, "connected");
        syncCallButtons();

        callStarted = Date.now();
        elapsedTimer = setInterval(tickElapsed, 1000);
        tickElapsed();
        startPolling();

        // The device labels only exist once permission has been granted, so this is the
        // first moment the pickers can say anything useful.
        await listDevices();
        addNotice(video ? "You started a video call." : "You joined the call.");
        if (callConfig && !callConfig.has_relay) {
            addNotice(
                "STUN only — no relay is configured, so this call may not connect across " +
                "some home networks."
            );
        }
    } catch (e) {
        fail($("error"), e);
        teardownCallUi();
    }
}

async function hangUp() {
    if (!inCall) return;
    try { await CairnCall.leave(); } catch (e) { fail($("error"), e); }
    teardownCallUi();
}

function teardownCallUi() {
    inCall = false;
    sharing = false;
    show($("stage"), false);
    $("tiles").textContent = "";
    if (elapsedTimer) clearInterval(elapsedTimer);
    elapsedTimer = null;
    startPolling();
}

function tickElapsed() {
    const s = Math.floor((Date.now() - callStarted) / 1000);
    const mm = String(Math.floor(s / 60)).padStart(2, "0");
    const ss = String(s % 60).padStart(2, "0");
    $("elapsed").textContent = mm + ":" + ss;
}

$("mute").onclick = () => {
    muted = !muted;
    CairnCall.setMuted(muted);
    syncCallButtons();
};

$("camera").onclick = async () => {
    try {
        cameraOff = !cameraOff;
        // Works even when the call started as voice-only: call.js negotiates an empty video
        // line up front precisely so a camera can be switched on without renegotiating.
        const stream = await CairnCall.setCameraOn(!cameraOff);
        if (stream && !sharing) upsertTile(myUser, stream, { local: true });
    } catch (e) {
        cameraOff = !cameraOff;
        fail($("error"), e);
    }
    syncCallButtons();
};

$("share").onclick = async () => {
    try {
        if (sharing) {
            const back = await CairnCall.stopScreenShare();
            sharing = false;
            if (back) upsertTile(myUser, back, { local: true });
        } else {
            const stream = await CairnCall.startScreenShare();
            sharing = true;
            upsertTile(myUser, stream, { local: true });
        }
    } catch (e) {
        // A cancelled picker throws NotAllowedError. That is a choice, not a fault.
        if (String(e).includes("NotAllowed")) sharing = false;
        else fail($("error"), e);
    }
    syncCallButtons();
};

function syncCallButtons() {
    $("mute").classList.toggle("on", muted);
    $("mute-text").textContent = muted ? "Unmuted" : "Mute";
    $("mute").querySelector("use").setAttribute("href", muted ? "#i-mic-off" : "#i-mic");

    $("camera").classList.toggle("on", !cameraOff);
    $("camera-text").textContent = cameraOff ? "Camera off" : "Camera on";
    $("camera").querySelector("use").setAttribute("href", cameraOff ? "#i-cam-off" : "#i-cam");

    $("share").classList.toggle("on", sharing);
    $("share-text").textContent = sharing ? "Stop sharing" : "Share screen";
}

// ---- video tiles -----------------------------------------------------------

const cssId = (user) => String(user).replace(/[^a-zA-Z0-9_-]/g, "");

function upsertTile(user, stream, opts = {}) {
    let tile = $("tile-" + cssId(user));
    if (!tile) {
        tile = document.createElement("div");
        tile.className = "tile";
        tile.id = "tile-" + cssId(user);

        const video = document.createElement("video");
        video.autoplay = true;
        video.playsInline = true;
        // Your own tile must be muted or the room howls: it is your microphone played back
        // into your speakers with a few hundred milliseconds of delay.
        video.muted = !!opts.local;

        const face = document.createElement("span");
        face.className = "initials";
        face.textContent = initials(user);

        const label = document.createElement("span");
        label.className = "label";
        const dot = document.createElement("span");
        dot.className = "dot";
        const name = document.createElement("span");
        name.textContent = opts.local ? short(user) + " (you)" : short(user);
        label.append(dot, name);

        tile.append(video, face, label);
        $("tiles").append(tile);
    }

    const video = tile.querySelector("video");
    if (video.srcObject !== stream) {
        video.srcObject = stream;
        video.play().catch(() => {});
    }
    if (!opts.local) CairnCall.applySpeaker(video);
    // A muted video track is a camera that is off, not one that is missing — treating them
    // the same is what leaves a frozen last frame on screen for the rest of the call.
    const live = stream.getVideoTracks().some((t) => !t.muted && t.readyState === "live");
    tile.classList.toggle("audio-only", !live);
    return tile;
}

function removeTile(user) {
    const tile = $("tile-" + cssId(user));
    if (tile) tile.remove();
}

function markTile(user, state) {
    const dot = document.querySelector("#tile-" + cssId(user) + " .dot");
    if (!dot) return;
    dot.className = "dot " +
        (state === "connected" ? "live"
            : state === "failed" || state === "disconnected" ? "bad"
            : "trying");
    dot.title = state;
}

// ---- device pickers --------------------------------------------------------

async function listDevices() {
    let found;
    try { found = await CairnCall.devices(); } catch (_) { return; }

    const named = fill($("dev-mic"), found.mic, "Default microphone") |
                  fill($("dev-cam"), found.camera, "Default camera") |
                  fill($("dev-out"), found.speaker, "Default output");

    $("device-note").textContent = named
        ? ""
        : "Device names appear once a call has been started and permission granted.";

    if (!CairnCall.canChooseSpeaker()) {
        $("dev-out").disabled = true;
        $("dev-out").title = "This webview does not support choosing an output device.";
    }
}

// Returns whether any device came back with a real label, which is the signal that
// permission has been granted at least once.
function fill(select, list, fallback) {
    const chosen = select.value;
    select.textContent = "";
    const def = document.createElement("option");
    def.value = "";
    def.textContent = fallback;
    select.append(def);

    let named = false;
    for (const d of list) {
        const opt = document.createElement("option");
        opt.value = d.deviceId;
        opt.textContent = d.label || "Device " + d.deviceId.slice(0, 6);
        if (d.label) named = true;
        select.append(opt);
    }
    if ([...select.options].some((o) => o.value === chosen)) select.value = chosen;
    return named ? 1 : 0;
}

$("dev-mic").onchange = (e) => CairnCall.useMicrophone(e.target.value).catch((x) => fail($("error"), x));
$("dev-cam").onchange = async (e) => {
    try {
        const stream = await CairnCall.useCamera(e.target.value);
        if (stream && !sharing) upsertTile(myUser, stream, { local: true });
    } catch (x) { fail($("error"), x); }
};
$("dev-out").onchange = (e) => {
    CairnCall.useSpeaker(e.target.value);
    for (const v of document.querySelectorAll("#tiles video")) {
        if (!v.muted) CairnCall.applySpeaker(v);
    }
};

// What the call configuration can and cannot do, said before someone hits a call that will
// not connect. Silence here would be the "claim a protection that is not there" failure in
// reverse: an unstated limitation people discover by being unreachable.
async function describeRelay() {
    let config;
    try { config = await CairnCall.loadConfig(); } catch (_) { return; }
    callConfig = config;
    const note = $("relay-note");
    if (config.has_relay) {
        note.className = "note";
        note.textContent = "Calls can fall back to a relay when a direct path fails.";
        note.title = "";
    } else {
        note.className = "note warn";
        note.textContent = "STUN only — some networks will not connect.";
        // The full statement lives in the tooltip and in the release notes. A four-line
        // warning permanently occupying the panel gets read once and then stops being read.
        note.title =
            "No TURN relay is configured, so a call may fail to connect across some home " +
            "networks. Calls carry media directly between participants, so each person in " +
            "a call learns the others' IP addresses.";
    }
}

// ---- polling ---------------------------------------------------------------
//
// Polling rather than push: the server has no websocket yet. Deliberately modest, because
// every poll is a request the instance can time.

function startPolling() {
    if (pollTimer) clearInterval(pollTimer);
    pollTimer = setInterval(tick, inCall ? CALL_POLL_MS : IDLE_POLL_MS);
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
        } else if (ev.kind === "signal") {
            // Already filtered in Rust: signals addressed to somebody else never arrive, and
            // a device that has not joined a call is only ever told that one started or
            // ended. Everything else is the mesh's business.
            if (!inCall) ring(ev.from, ev.signal);
            else await CairnCall.handle(ev.from, ev.signal);
        } else if (ev.kind === "membership") {
            membershipChanged = true;
            // A silently added member is a wiretap. Membership changes are shown in the
            // timeline, not folded away into a member list nobody is looking at.
            for (const who of ev.joined) addNotice("joined the group: " + short(who));
            for (const who of ev.left) addNotice("left the group: " + short(who));
        } else if (ev.kind === "removed") {
            addNotice("You were removed from this room.");
            if (inCall) await hangUp();
            clearInterval(pollTimer);
            openRoom = null;
            await refreshRooms();
        }
    }
    if (membershipChanged) await refreshMembers();
}

// ---- rendering -------------------------------------------------------------

function addMessage(m) {
    const li = document.createElement("li");
    li.className = m.historic ? "msg historic" : "msg";
    const who = document.createElement("span");
    who.className = "mono who";
    who.textContent = short(m.sender);
    who.title = m.sender;
    const body = document.createElement("span");
    // textContent, never innerHTML: a message body is attacker-controlled text and this is
    // the one line standing between that and script execution in the client.
    body.textContent = m.body;
    li.append(who, body);
    if (m.card) li.append(renderCard(m.card));
    $("timeline").append(li);
    li.scrollIntoView({ block: "end" });
}

// A link card. Everything here was decided in Rust (cairn_client_core::embed::CardView):
// whether to show it at all, where the link really goes, what kind of post it is, the
// caveat. This only lays it out.
//
// Rules this follows, from docs/05-embeds.md §3:
// - textContent only. Every string on a card is the sender's; none is ever parsed as HTML.
// - The real destination host is always visible, computed from the URL rather than taken
//   from the card, so a card titled "Reuters" cannot hide that its link goes elsewhere.
// - The card reads as the sender's, never as verified: no tick, no "official" styling.
// - No remote images. The CSP is img-src 'self' data:, and the thumbnail arrives as a data:
//   URI the *sender's* device made. Loading the image from its original URL would have the
//   recipient contact the platform — the leak the whole design exists to prevent.
function renderCard(c) {
    const card = document.createElement("div");
    card.className = "link-card" + (c.portrait ? " portrait" : "");
    card.tabIndex = 0;
    card.setAttribute("role", "link");
    card.title = c.url;
    const open = () => invoke("open_link", { url: c.url }).catch((e) => fail($("error"), e));
    card.onclick = open;
    card.onkeydown = (ev) => { if (ev.key === "Enter") open(); };

    const text = (cls, value) => {
        const el = document.createElement("div");
        el.className = cls;
        el.textContent = value;
        return el;
    };

    // The picture: the sender's thumbnail, or — for a recognised post with nothing fetched
    // — a plain tile naming what the URL itself says it is.
    if (c.thumbnail || c.platform) {
        const media = document.createElement("div");
        media.className = "card-media";
        if (c.thumbnail) {
            const img = document.createElement("img");
            img.alt = "";
            img.src = c.thumbnail;
            media.append(img);
        } else {
            media.classList.add("empty");
            media.append(text("card-media-label", c.platform));
        }
        if (c.portrait) {
            // Playback is not offered: the video is not in the message, and fetching it here
            // would contact the platform. The glyph says "this is a video; opening it plays
            // it", which is what clicking does.
            const play = document.createElement("span");
            play.className = "play";
            play.setAttribute("aria-hidden", "true");
            media.append(play);
        }
        card.append(media);
    }

    const meta = document.createElement("div");
    meta.className = "card-meta";
    // A platform and kind come from the URL, in Rust. A site name comes from the page, so it
    // is labelled as what the page says about itself rather than shown as an attribution.
    const eyebrow = [c.platform, c.kind].filter(Boolean).join(" · ")
        || (c.claimed_site ? "page says: " + c.claimed_site : "");
    if (eyebrow) meta.append(text("card-eyebrow", eyebrow));
    if (c.title) meta.append(text("card-title", c.title));
    else if (c.platform) meta.append(text("card-title", c.platform + " " + (c.kind || "link").toLowerCase()));
    if (c.author) meta.append(text("card-author", c.author));
    if (c.description) meta.append(text("card-desc", c.description));
    if (!c.title && !c.description) meta.append(text("card-desc", "No preview available · open link"));

    const dest = text("card-dest", "↗ " + c.host);
    dest.title = c.url;
    meta.append(dest);
    if (c.host_warning) meta.append(text("card-warn", c.host_warning));
    if (c.caveat) meta.append(text("card-warn", c.caveat));
    meta.append(text("card-claim", "Preview supplied by the sender, not checked by Cairn"));

    card.append(meta);
    return card;
}

// ---- link-preview settings -------------------------------------------------
//
// Stored per profile by Rust. Previews are on by default because the fetch is the sender's
// own; the Instagram proxy is off by default because a third party sees the link, and the
// disclosure text comes from Rust so every client shows the same words.

async function loadPreviewSettings() {
    try {
        const s = await invoke("link_previews");
        $("pref-previews").checked = s.enabled;
        $("pref-ig-proxy").checked = s.instagram_proxy;
        $("pref-ig-proxy").disabled = !s.enabled;
        $("ig-proxy-note").textContent = await invoke("instagram_proxy_disclosure");
    } catch (_) {}
}

async function savePreviewSettings() {
    const settings = {
        enabled: $("pref-previews").checked,
        instagram_proxy: $("pref-previews").checked && $("pref-ig-proxy").checked,
    };
    $("pref-ig-proxy").disabled = !settings.enabled;
    try { await invoke("set_link_previews", { settings }); } catch (e) { fail($("error"), e); }
}

$("pref-previews").onchange = savePreviewSettings;
$("pref-ig-proxy").onchange = savePreviewSettings;

function addNotice(text) {
    const li = document.createElement("li");
    li.className = "notice";
    li.textContent = text;
    $("timeline").append(li);
    li.scrollIntoView({ block: "end" });
}

// Devices change while the app is open — a headset gets plugged in mid-call.
if (navigator.mediaDevices) navigator.mediaDevices.ondevicechange = () => listDevices();
