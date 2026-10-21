// The voice channel in the sidebar — who is in it, its own badge, join and leave — and the
// voice bar that stays on screen while connected, whichever room is open.
//
// Presentation only. Who may join is the instance's rule (state.rs), whether the call is end
// to end is Rust's (Session::voice_state / voice_call), and the media is voicechannel.js's.
// This file draws those answers and says out loud when the protection changes — §5 of
// docs/12-realtime-media.md requires that everyone in the call is told, not only the person
// whose client caused it.
//
// Two things are drawn, and they are not the same call:
//
// - The **panel** is the open room's voice channel (`voice_state`). Its occupancy is shown
//   whether or not this device is in it.
// - The **bar** is the channel this device is connected to (`voice_call`), which stays
//   connected when another room is opened, Discord-style. Its badge is that call's badge,
//   so a transport-only call stays labelled as one from any room.

/* eslint-env browser */

const CairnVoicePanel = (() => {
    const IDLE_REFRESH_MS = 3000;
    const PREF_KEY = "cairn.voice.leaveOnFallback";
    const $ = (id) => document.getElementById(id);
    let hooks = {
        notice: () => {}, onError: () => {}, inCall: () => false, short: (s) => s,
        roomLabel: (id) => id, openRoom: async () => {}, openRoomId: () => null,
    };
    let timer = null;
    let roomOpen = false;
    let panelState = null;        // the open room's channel, as last drawn
    const muted = new Map();      // device -> { muted, deafened } from sealed frames

    // A top-level `const` is not a property of `window`, so this cannot be `window.CairnProfile`.
    const hasProfiles = () => typeof CairnProfile !== "undefined";

    function el(tag, cls, text) {
        const e = document.createElement(tag);
        if (cls) e.className = cls;
        if (text != null) e.textContent = text;
        return e;
    }

    function readPref() {
        try { return localStorage.getItem(PREF_KEY) === "1"; } catch (_) { return false; }
    }

    const BADGE_TEXT = {
        e2ee: "End-to-end",
        transport_only: "Transport only",
        transport_room: "Transport only",
    };
    const BADGE_TITLE = {
        e2ee: "Every participant seals their audio before it leaves their device. The " +
            "instance's voice server forwards it and cannot hear it. It does see who is " +
            "connected, from where, and when each person speaks.",
        transport_only: "Somebody here cannot encrypt call audio end to end, so nobody " +
            "does: the instance's voice server can hear this call. Messages in this room " +
            "are still end-to-end encrypted.",
        transport_room: "This room is transport-encrypted, so its voice channel is too. " +
            "The instance can hear it.",
    };

    // The call's own badge. Never the room's: an E2EE room can hold a transport-only call,
    // and the room badge beside it must not change.
    function paintBadge(b, protection) {
        b.textContent = BADGE_TEXT[protection] || "";
        b.className = "badge " + (protection === "e2ee" ? "ok" : "warn");
        b.title = BADGE_TITLE[protection] || "";
    }

    // Connected here: Rust's answer, by room id. Never "the page has a session", which is
    // true of a call in another room too.
    const joinedHere = (state) => !!state && !!CairnVoiceChannel.session && state.connected_room === state.room;

    function render(state) {
        panelState = state;
        const panel = $("voice-channel");
        if (!state || !state.available) { panel.hidden = true; return; }
        panel.hidden = false;
        paintBadge($("vc-badge"), state.protection);
        const list = $("vc-people");
        list.textContent = "";
        for (const p of state.participants) {
            const li = el("li", "vc-person");
            li.dataset.user = p.user;
            if (hasProfiles()) li.append(CairnProfile.avatar(p.user, 22));
            const name = el("span", "vc-name");
            if (hasProfiles()) CairnProfile.nameInto(name, CairnProfile.view(p.user), p.me ? " (you)" : "");
            else name.textContent = hooks.short(p.user) + (p.me ? " (you)" : "");
            li.append(name);
            const m = muted.get(p.device);
            if (p.me ? CairnVoiceChannel.muted || CairnVoiceChannel.deafened : m && m.muted) {
                li.append(el("span", "vc-flag", (p.me ? CairnVoiceChannel.deafened : m.deafened) ? "deafened" : "muted"));
            }
            if (p.media === "transport_only") {
                li.append(el("span", "vc-flag warn", "no E2EE media"));
            }
            // The instance listed a device the room's encrypted group does not contain. It
            // cannot hold a key, so it hears nothing sealed — but the list is the instance's
            // word, and a name that is not backed by the group must not look like one that is.
            if (!p.in_group) {
                const w = el("span", "vc-flag warn", "not in the encrypted group");
                w.title = "The instance lists this device, but the room's encrypted group does not contain it.";
                li.append(w);
            }
            // Their voice and their soundboard, for this device only: the same popover a
            // rung call's tiles open.
            if (!p.me && typeof CairnCallUi !== "undefined" && CairnCallUi.openVolume) {
                const menu = el("button", "vc-menu ghost");
                menu.type = "button";
                menu.title = "Volume and soundboard for this person";
                menu.setAttribute("aria-label", menu.title);
                menu.innerHTML = '<svg width="14" height="14" aria-hidden="true"><use href="#i-volume"/></svg>';
                menu.addEventListener("click", (e) => { e.stopPropagation(); CairnCallUi.openVolume(p.user, menu); });
                li.append(menu);
            }
            list.append(li);
        }
        if (!state.participants.length) list.append(el("li", "vc-empty", "Nobody is here."));
        const here = joinedHere(state);
        const elsewhere = !here && !!CairnVoiceChannel.session && !!state.connected_room;
        panel.classList.toggle("joined", here);
        $("vc-join").hidden = here;
        // Joining here leaves the other channel: one seat per device is the instance's rule.
        $("vc-join").textContent = elsewhere ? "Move here" : "Join voice";
        $("vc-join").title = elsewhere ? "Leave the voice channel you are in and join this one" : "";
        for (const id of ["vc-mute", "vc-deafen", "vc-leave"]) $(id).hidden = !here;
        syncMuteButtons();
    }

    function syncMuteButtons() {
        for (const [mute, deafen] of [["vc-mute", "vc-deafen"], ["vb-mute", "vb-deafen"]]) {
            if (!$(mute)) continue;
            $(mute).setAttribute("aria-pressed", String(CairnVoiceChannel.muted));
            $(mute).querySelector(".lbl").textContent = CairnVoiceChannel.muted ? "Unmute" : "Mute";
            $(deafen).setAttribute("aria-pressed", String(CairnVoiceChannel.deafened));
            $(deafen).querySelector(".lbl").textContent = CairnVoiceChannel.deafened ? "Undeafen" : "Deafen";
        }
    }

    // The bar: the connected call, from any room.
    function renderBar(state) {
        const bar = $("voice-bar");
        if (!bar) return;
        if (!state || !CairnVoiceChannel.session) { bar.hidden = true; return; }
        bar.hidden = false;
        paintBadge($("vb-badge"), state.protection);
        const name = $("vb-room");
        name.textContent = hooks.roomLabel(state.room);
        name.title = "Open " + hooks.roomLabel(state.room);
        bar.classList.toggle("here", state.room === hooks.openRoomId());
        const n = state.participants.length;
        $("vb-count").textContent = n === 1 ? "just you" : n + " here";
        syncMuteButtons();
    }

    function announce(before, after, by) {
        const who = by.map((u) => (hasProfiles() ? CairnProfile.view(u).label : hooks.short(u))).join(", ");
        const text = after === "transport_only"
            ? "This voice call is now transport-only: " + (who || "somebody") + " cannot encrypt " +
              "call audio end to end, so the instance's voice server can hear it. Messages are " +
              "still end-to-end encrypted."
            : after === "e2ee"
                ? "This voice call is end-to-end encrypted again."
                : "This voice call's protection changed.";
        $("vc-note").textContent = text;
        $("vb-note").textContent = text;
        hooks.notice(text);
    }

    async function idleRefresh() {
        if (!roomOpen) return;
        try { render(await window.__TAURI__.core.invoke("voice_state")); } catch (_) { $("voice-channel").hidden = true; }
    }

    async function join() {
        if (hooks.inCall()) { hooks.onError("Leave the call first: a ringing call and a voice channel cannot both hold the microphone."); return; }
        $("vc-join").disabled = true;
        $("vc-note").textContent = "";
        $("vb-note").textContent = "";
        try {
            const { path } = await CairnVoiceChannel.join();
            if (path === "none") {
                $("vc-note").textContent = "This app cannot encrypt call audio end to end, so the call is " +
                    "transport-only for everyone while you are in it. They have been told.";
            }
        } catch (e) { hooks.onError(e); }
        $("vc-join").disabled = false;
        await idleRefresh();
        renderBar(CairnVoiceChannel.state);
    }

    function toggleMute() { CairnVoiceChannel.setMuted(!CairnVoiceChannel.muted); redraw(); }
    function toggleDeafen() { CairnVoiceChannel.setDeafened(!CairnVoiceChannel.deafened); redraw(); }
    function redraw() { if (panelState) render(panelState); renderBar(CairnVoiceChannel.state); }

    function init(h) {
        hooks = { ...hooks, ...h };
        CairnVoiceChannel.setPrefs({ leaveOnFallback: readPref() });
        CairnVoiceChannel.bind({
            onState: (state) => {
                renderBar(state);
                // The connected call is also the panel's when its room is the open one.
                if (state && state.room === hooks.openRoomId()) render(state);
            },
            onProtection: announce,
            onNotice: (t) => { $("vc-note").textContent = t; $("vb-note").textContent = t; },
            onEnd: () => { muted.clear(); renderBar(null); idleRefresh(); },
            onHeard: (_slot, who) => { muted.set(who.device, who); },
        });
        $("vc-join").onclick = join;
        $("vc-leave").onclick = () => CairnVoiceChannel.leave();
        $("vc-mute").onclick = toggleMute;
        $("vc-deafen").onclick = toggleDeafen;
        $("vb-leave").onclick = () => CairnVoiceChannel.leave();
        $("vb-mute").onclick = toggleMute;
        $("vb-deafen").onclick = toggleDeafen;
        $("vb-room").onclick = () => {
            const s = CairnVoiceChannel.state;
            if (s && s.room !== hooks.openRoomId()) hooks.openRoom(s.room);
        };
        const pref = $("pref-vc-leave");
        if (pref) {
            pref.checked = readPref();
            pref.onchange = () => {
                try { localStorage.setItem(PREF_KEY, pref.checked ? "1" : "0"); } catch (_) {}
                CairnVoiceChannel.setPrefs({ leaveOnFallback: pref.checked });
            };
        }
    }

    // A new room is open. A voice channel this device is connected to elsewhere stays
    // connected — the bar carries it — and the panel starts showing this room's.
    async function roomChanged() {
        roomOpen = true;
        $("vc-note").textContent = "";
        clearInterval(timer);
        timer = setInterval(idleRefresh, IDLE_REFRESH_MS);
        await idleRefresh();
        renderBar(CairnVoiceChannel.state);
    }

    function roomClosed() {
        roomOpen = false;
        clearInterval(timer);
        $("voice-channel").hidden = true;
    }

    // From the poll loop: a device announced its media. Re-read now rather than at the next
    // tick, so the fallback is told the moment it is known.
    function handle(ev) {
        if (ev.kind !== "voice_media") return false;
        if (CairnVoiceChannel.session) CairnVoiceChannel.refresh();
        idleRefresh();
        return true;
    }

    return { init, roomChanged, roomClosed, handle, get active() { return !!CairnVoiceChannel.session; } };
})();
