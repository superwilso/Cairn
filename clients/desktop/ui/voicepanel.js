// The voice channel in the sidebar: who is in it, its own badge, join and leave.
//
// Presentation only. Who may join is the instance's rule (state.rs), whether the call is end
// to end is Rust's (Session::voice_state), and the media is voicechannel.js's. This file
// draws those answers and says out loud when the protection changes — §5 of
// docs/12-realtime-media.md requires that everyone in the call is told, not only the person
// whose client caused it.

/* eslint-env browser */

const CairnVoicePanel = (() => {
    const IDLE_REFRESH_MS = 3000;
    const PREF_KEY = "cairn.voice.leaveOnFallback";
    const $ = (id) => document.getElementById(id);
    let hooks = { notice: () => {}, onError: () => {}, inCall: () => false, short: (s) => s };
    let timer = null;
    let roomOpen = false;
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

    // The call's own badge. Never the room's: an E2EE room can hold a transport-only call,
    // and the room badge beside it must not change.
    function paintBadge(protection) {
        const b = $("vc-badge");
        const text = {
            e2ee: "End-to-end",
            transport_only: "Transport only",
            transport_room: "Transport only",
        }[protection] || "";
        b.textContent = text;
        b.className = "badge " + (protection === "e2ee" ? "ok" : "warn");
        b.title = {
            e2ee: "Every participant seals their audio before it leaves their device. The " +
                "instance's voice server forwards it and cannot hear it. It does see who is " +
                "connected, from where, and when each person speaks.",
            transport_only: "Somebody here cannot encrypt call audio end to end, so nobody " +
                "does: the instance's voice server can hear this call. Messages in this room " +
                "are still end-to-end encrypted.",
            transport_room: "This room is transport-encrypted, so its voice channel is too. " +
                "The instance can hear it.",
        }[protection] || "";
    }

    function render(state) {
        const panel = $("voice-channel");
        if (!state || !state.available) { panel.hidden = true; return; }
        panel.hidden = false;
        paintBadge(state.protection);
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
            list.append(li);
        }
        if (!state.participants.length) list.append(el("li", "vc-empty", "Nobody is here."));
        const joined = !!CairnVoiceChannel.session;
        $("vc-join").hidden = joined;
        for (const id of ["vc-mute", "vc-deafen", "vc-leave"]) $(id).hidden = !joined;
        $("vc-mute").setAttribute("aria-pressed", String(CairnVoiceChannel.muted));
        $("vc-mute").textContent = CairnVoiceChannel.muted ? "Unmute" : "Mute";
        $("vc-deafen").setAttribute("aria-pressed", String(CairnVoiceChannel.deafened));
        $("vc-deafen").textContent = CairnVoiceChannel.deafened ? "Undeafen" : "Deafen";
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
        hooks.notice(text);
    }

    async function idleRefresh() {
        if (!roomOpen || CairnVoiceChannel.session) return;
        try { render(await window.__TAURI__.core.invoke("voice_state")); } catch (_) { $("voice-channel").hidden = true; }
    }

    async function join() {
        if (hooks.inCall()) { hooks.onError("Leave the call first: a ringing call and a voice channel cannot both hold the microphone."); return; }
        $("vc-join").disabled = true;
        $("vc-note").textContent = "";
        try {
            const { path } = await CairnVoiceChannel.join();
            if (path === "none") {
                $("vc-note").textContent = "This app cannot encrypt call audio end to end, so the call is " +
                    "transport-only for everyone while you are in it. They have been told.";
            }
        } catch (e) { hooks.onError(e); }
        $("vc-join").disabled = false;
        render(CairnVoiceChannel.state);
    }

    function init(h) {
        hooks = { ...hooks, ...h };
        CairnVoiceChannel.setPrefs({ leaveOnFallback: readPref() });
        CairnVoiceChannel.bind({
            onState: render,
            onProtection: announce,
            onNotice: (t) => { $("vc-note").textContent = t; },
            onEnd: () => { muted.clear(); idleRefresh(); },
            onHeard: (_slot, who) => { muted.set(who.device, who); },
        });
        $("vc-join").onclick = join;
        $("vc-leave").onclick = () => CairnVoiceChannel.leave();
        $("vc-mute").onclick = () => { CairnVoiceChannel.setMuted(!CairnVoiceChannel.muted); render(CairnVoiceChannel.state); };
        $("vc-deafen").onclick = () => { CairnVoiceChannel.setDeafened(!CairnVoiceChannel.deafened); render(CairnVoiceChannel.state); };
        const pref = $("pref-vc-leave");
        if (pref) {
            pref.checked = readPref();
            pref.onchange = () => {
                try { localStorage.setItem(PREF_KEY, pref.checked ? "1" : "0"); } catch (_) {}
                CairnVoiceChannel.setPrefs({ leaveOnFallback: pref.checked });
            };
        }
    }

    // A new room: leave the old one's channel (Rust does too) and start watching this one's.
    async function roomChanged() {
        if (CairnVoiceChannel.session) await CairnVoiceChannel.leave();
        roomOpen = true;
        muted.clear();
        $("vc-note").textContent = "";
        clearInterval(timer);
        timer = setInterval(idleRefresh, IDLE_REFRESH_MS);
        await idleRefresh();
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
        if (CairnVoiceChannel.session) CairnVoiceChannel.refresh(); else idleRefresh();
        return true;
    }

    return { init, roomChanged, roomClosed, handle, get active() { return !!CairnVoiceChannel.session; } };
})();
