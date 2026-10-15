// Cairn calls — the parts a person touches: being rung, answering or declining, mute and
// deafen, push-to-talk, the speaking ring, and turning one person up or down.
//
// Presentation only, like the rest of the UI. Who is calling arrives as a signal Rust has
// already filtered (`Session::reconcile`); declining is `call_decline`, which Rust addresses
// and sends; what someone is called comes from profile.js. app.js owns starting and ending
// the call; call.js owns the peer connections; callaudio.js owns what is heard. This file
// joins them to buttons.
//
// Every preference here — the input mode, the push-to-talk key, the ring, the processing
// switches, the relay — is stored on this device and nowhere else.

/* eslint-env browser */

const CairnCallUi = (() => {
    const KEY = "cairn.voice.v1";
    const $ = (id) => document.getElementById(id);
    // How long an unanswered ring lasts, on both ends, before it becomes a missed call.
    const RING_MS = 45000;

    let hooks = {
        invoke: null, me: () => null, short: (id) => id, addNotice: () => null,
        inCall: () => false, startCall: async () => {}, hangUp: async () => {},
    };

    const DEFAULTS = {
        mode: "vad", pttCode: "Backquote", pttLabel: "`", ring: true,
        noiseSuppression: true, echoCancellation: true, autoGainControl: true, relayOnly: false,
    };
    let prefs = load();

    // Call state this file draws.
    let ringing = null;       // { call, from, timer }
    // Calls already declined or missed here. In a group, every newcomer announces itself to
    // the room, and without this each arrival would ring again someone who already said no.
    const quiet = new Set();
    let muted = false;
    let deafened = false;
    let config = null;        // CallConfig for the call in progress
    let unanswered = null;    // timer: a DM call nobody picked up
    let connected = new Set();
    const peerStates = new Map();  // user -> { muted, deafened }
    let capturing = false;    // the settings panel is waiting for a push-to-talk key
    let answering = false;    // this call was joined from a ring, not started here

    // ---- preferences -------------------------------------------------------------

    function load() {
        try {
            const raw = JSON.parse(localStorage.getItem(KEY) || "null");
            if (!raw || typeof raw !== "object") return { ...DEFAULTS };
            const out = { ...DEFAULTS };
            if (raw.mode === "vad" || raw.mode === "ptt") out.mode = raw.mode;
            if (typeof raw.pttCode === "string" && /^[A-Za-z0-9]{1,24}$/.test(raw.pttCode)) out.pttCode = raw.pttCode;
            if (typeof raw.pttLabel === "string") out.pttLabel = raw.pttLabel.slice(0, 16);
            for (const k of ["ring", "noiseSuppression", "echoCancellation", "autoGainControl", "relayOnly"]) {
                if (typeof raw[k] === "boolean") out[k] = raw[k];
            }
            return out;
        } catch (_) { return { ...DEFAULTS }; }
    }
    function save() {
        try { localStorage.setItem(KEY, JSON.stringify(prefs)); } catch (_) { /* not persisted */ }
    }

    async function setPref(key, value) {
        prefs = { ...prefs, [key]: value };
        save();
        const r = await CairnCall.setPrefs(prefs).catch(() => ({}));
        if (key === "mode") CairnCall.setPushToTalk(prefs.mode === "ptt");
        syncPrefs();
        syncCallbar();
        if (r && r.relayChangedMidCall) {
            hooks.addNotice("The relay setting applies from your next call; this one keeps its current route.");
        }
    }

    // Friendly names for the keys someone is likely to pick. `code` is what is stored —
    // it is the physical key, so it does not change with the keyboard layout.
    function keyLabel(ev) {
        if (ev.code.startsWith("Key")) return ev.code.slice(3);
        if (ev.code.startsWith("Digit")) return ev.code.slice(5);
        const named = {
            Backquote: "`", Space: "Space", CapsLock: "Caps Lock", Tab: "Tab",
            ShiftLeft: "Left Shift", ShiftRight: "Right Shift", ControlLeft: "Left Ctrl",
            ControlRight: "Right Ctrl", AltLeft: "Left Alt", AltRight: "Right Alt",
        };
        return named[ev.code] || (ev.key && ev.key.length === 1 ? ev.key.toUpperCase() : ev.code);
    }

    // ---- the settings section ------------------------------------------------------
    //
    // The nodes live in index.html (#prefs-voice) and settings.js moves them into the panel,
    // the same way it moves the link-preview settings. Bound here, once, on load.

    function bindPrefs() {
        const box = $("prefs-voice");
        if (!box) return;
        for (const r of box.querySelectorAll('input[name="pref-mode"]')) {
            r.addEventListener("change", () => { if (r.checked) setPref("mode", r.value); });
        }
        const pairs = [
            ["pref-ring", "ring"], ["pref-ns", "noiseSuppression"], ["pref-ec", "echoCancellation"],
            ["pref-agc", "autoGainControl"], ["pref-relay-only", "relayOnly"],
        ];
        for (const [id, key] of pairs) {
            const input = $(id);
            if (input) input.addEventListener("change", () => setPref(key, input.checked));
        }
        const keyBtn = $("pref-ptt-key");
        if (keyBtn) keyBtn.addEventListener("click", () => {
            capturing = true;
            keyBtn.textContent = "Press a key…";
            keyBtn.classList.add("on");
        });
        // Capture phase, so the key that is being chosen does not also type somewhere.
        document.addEventListener("keydown", (ev) => {
            if (!capturing) return;
            ev.preventDefault();
            ev.stopPropagation();
            capturing = false;
            if (keyBtn) keyBtn.classList.remove("on");
            if (ev.code === "Escape") { syncPrefs(); return; }
            prefs = { ...prefs, pttCode: ev.code, pttLabel: keyLabel(ev) };
            save();
            syncPrefs();
            syncCallbar();
        }, true);
        syncPrefs();
    }

    function syncPrefs() {
        const box = $("prefs-voice");
        if (!box) return;
        for (const r of box.querySelectorAll('input[name="pref-mode"]')) r.checked = r.value === prefs.mode;
        const set = (id, v) => { const e = $(id); if (e) e.checked = v; };
        set("pref-ring", prefs.ring);
        set("pref-ns", prefs.noiseSuppression);
        set("pref-ec", prefs.echoCancellation);
        set("pref-agc", prefs.autoGainControl);
        set("pref-relay-only", prefs.relayOnly);
        const keyBtn = $("pref-ptt-key");
        if (keyBtn && !capturing) keyBtn.textContent = prefs.pttLabel || prefs.pttCode;
        const ptt = $("pref-ptt-row");
        if (ptt) ptt.classList.toggle("off", prefs.mode !== "ptt");
        relayNote();
    }

    // What the relay switch does on *this* instance, said beside the switch.
    function relayNote() {
        const note = $("relay-only-note");
        if (!note) return;
        const known = config || CairnCall.config;
        const noRelay = known && !known.has_relay;
        note.classList.toggle("warn", !!(prefs.relayOnly && noRelay));
        note.textContent = prefs.relayOnly && noRelay
            ? "This instance runs no relay, so with this on, calls cannot connect."
            : "Your media goes through the instance's relay instead of straight to the other " +
              "people in the call, so they no longer see your IP address. The relay's operator " +
              "does, instead, and calls may have slightly more delay. Needs the instance to run " +
              "a relay; applies from the next call.";
    }

    // ---- being rung ------------------------------------------------------------------

    const label = (user) => {
        const v = CairnProfile && CairnProfile.view ? CairnProfile.view(user) : null;
        return v ? v.label : hooks.short(user);
    };

    // Somebody started a call in the open room. `call_join` adopts the announced call id,
    // so accepting joins *that* call rather than starting a rival one beside it.
    function ring(from, signal) {
        if (signal.kind === "join") {
            if (ringing && ringing.call === signal.call) return;
            if (quiet.has(signal.call)) return;
            stopRinging();
            const direct = !!(CairnCall.config && CairnCall.config.direct);
            ringing = { call: signal.call, from, timer: setTimeout(() => missed(from), RING_MS) };

            const face = $("ringing-avatar");
            face.textContent = "";
            if (CairnProfile && CairnProfile.avatar) face.append(CairnProfile.avatar(from, 88));
            const name = $("ringing-name");
            if (CairnProfile && CairnProfile.nameInto) {
                CairnProfile.nameInto(name, CairnProfile.view(from));
            } else {
                name.textContent = hooks.short(from);
            }
            $("ringing-text").textContent = direct ? "is calling you" : "started a call in this group";
            const sound = prefs.ring ? CairnCallAudio.startRing() : false;
            // The ring is generated in the page, and a webview may not let a page make sound
            // before it has been clicked. Say so rather than letting a silent ring look like
            // a broken speaker.
            $("ringing-note").textContent = !prefs.ring
                ? "Ring sound is off (Settings → Voice & video)."
                : sound ? "" : "Click anywhere in Cairn once to let it ring out loud.";
            $("ringing").hidden = false;
            $("accept-voice").focus();
        } else if (signal.kind === "leave" && ringing && from === ringing.from) {
            missed(from);
        }
    }

    function stopRinging() {
        if (ringing) clearTimeout(ringing.timer);
        ringing = null;
        CairnCallAudio.stopRing();
        const box = $("ringing");
        if (box) box.hidden = true;
    }

    // Not answered: the caller gave up, or the ring ran out. Left in the timeline with a way
    // to call back, which is the reason a missed call is worth showing at all.
    function missed(from) {
        if (ringing) quiet.add(ringing.call);
        stopRinging();
        const li = hooks.addNotice("Missed call from " + label(from));
        if (li) {
            li.classList.add("call-notice", "missed");
            const back = document.createElement("button");
            back.type = "button";
            back.className = "ghost call-back";
            back.textContent = "Call back";
            back.addEventListener("click", () => hooks.startCall(false));
            li.append(" ", back);
        }
    }

    async function accept(video) {
        answering = true;
        stopRinging();
        CairnCallAudio.resume();
        await hooks.startCall(video);
    }

    async function decline() {
        const from = ringing && ringing.from;
        if (ringing) quiet.add(ringing.call);
        stopRinging();
        try { await hooks.invoke("call_decline"); } catch (e) { hooks.addNotice("Could not decline: " + e); return; }
        if (from) hooks.addNotice("You declined a call from " + label(from) + ".");
    }

    // ---- in a call -------------------------------------------------------------------

    function started(cfg) {
        config = cfg;
        muted = false;
        deafened = false;
        connected = new Set();
        peerStates.clear();
        CairnCall.setPushToTalk(prefs.mode === "ptt");
        CairnCallAudio.setDeafened(false);
        const me = hooks.me();
        if (CairnCall.local) CairnCallAudio.attachLocal(me, CairnCall.local);
        // A DM call nobody answers ends, as a phone call does. A group call stays open for
        // whoever joins later, so it only says that nobody has yet.
        clearTimeout(unanswered);
        const joined = answering;
        answering = false;
        status(joined ? "Connecting…" : cfg && cfg.direct ? "Ringing…" : "Waiting for others to join…");
        if (cfg && cfg.direct && !joined) {
            unanswered = setTimeout(async () => {
                if (connected.size || !hooks.inCall()) return;
                hooks.addNotice("No answer.");
                await hooks.hangUp();
            }, RING_MS);
        }
        syncCallbar();
        relayNote();
    }

    function ended() {
        clearTimeout(unanswered);
        unanswered = null;
        connected = new Set();
        peerStates.clear();
        muted = false;
        deafened = false;
        CairnCall.resetMic();
        CairnCallAudio.reset();
        status("");
        syncCallbar();
    }

    function peerConnection(user, state) {
        if (state === "connected") connected.add(user);
        else if (state === "closed" || state === "failed") connected.delete(user);
        if (connected.size) {
            clearTimeout(unanswered);
            status(connected.size === 1 ? "Connected" : connected.size + " people connected");
        }
    }

    function declined(from) {
        hooks.addNotice(label(from) + " declined the call.");
        if (config && config.direct && !connected.size) {
            status("Declined");
            clearTimeout(unanswered);
            // Long enough to read the word, short enough not to feel like a hang.
            setTimeout(() => { if (!connected.size) hooks.hangUp(); }, 1500);
        }
    }

    function status(text) {
        const el = $("call-status");
        if (el) el.textContent = text;
    }

    function toggleMute() {
        // Unmuting while deafened undeafens too, as people expect: the alternative is a
        // button that appears to do nothing.
        if (deafened && muted) { deafened = false; CairnCallAudio.setDeafened(false); CairnCall.setDeafened(false); }
        muted = !muted;
        CairnCall.setMuted(muted);
        syncCallbar();
    }

    function toggleDeafen() {
        deafened = !deafened;
        CairnCall.setDeafened(deafened);
        CairnCallAudio.setDeafened(deafened);
        syncCallbar();
    }

    function syncCallbar() {
        const m = $("mute");
        if (!m) return;
        const shownMuted = muted || deafened;
        m.classList.toggle("on", shownMuted);
        m.setAttribute("aria-pressed", String(shownMuted));
        $("mute-text").textContent = shownMuted ? "Unmute" : "Mute";
        m.querySelector("use").setAttribute("href", shownMuted ? "#i-mic-off" : "#i-mic");

        const d = $("deafen");
        d.classList.toggle("on", deafened);
        d.setAttribute("aria-pressed", String(deafened));
        $("deafen-text").textContent = deafened ? "Undeafen" : "Deafen";
        d.querySelector("use").setAttribute("href", deafened ? "#i-deaf" : "#i-headphones");

        const hint = $("ptt-hint");
        if (hint) {
            const on = prefs.mode === "ptt" && hooks.inCall();
            hint.hidden = !on;
            hint.textContent = "Hold " + (prefs.pttLabel || prefs.pttCode) + " to talk";
            hint.title = "Push-to-talk works only while the Cairn window is focused. " +
                "In another app, your microphone stays closed.";
        }
        const me = hooks.me();
        if (me) badge(me, { muted: shownMuted, deafened });
    }

    // ---- push-to-talk ----------------------------------------------------------------
    //
    // A key held in *this window*. A webview cannot see keys pressed in other applications,
    // and a global hotkey would mean a system-wide keyboard hook — so the honest version is
    // focused-only, and the settings and the call bar both say so. Losing focus releases it,
    // or alt-tabbing away mid-sentence would leave the microphone open.

    const editable = (t) => t && (t.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName));

    function talking(held) {
        CairnCall.setTalking(held);
        const hint = $("ptt-hint");
        if (hint) hint.classList.toggle("live", held);
    }

    function bindKeys() {
        document.addEventListener("keydown", (ev) => {
            if (!hooks.inCall() || capturing) return;
            if (prefs.mode === "ptt" && ev.code === prefs.pttCode && !editable(ev.target)) {
                ev.preventDefault();
                if (!ev.repeat) talking(true);
                return;
            }
            if (ev.ctrlKey && ev.shiftKey && !ev.altKey && ev.code === "KeyM") { ev.preventDefault(); toggleMute(); }
            if (ev.ctrlKey && ev.shiftKey && !ev.altKey && ev.code === "KeyD") { ev.preventDefault(); toggleDeafen(); }
        });
        document.addEventListener("keyup", (ev) => {
            if (prefs.mode === "ptt" && ev.code === prefs.pttCode) talking(false);
        });
        window.addEventListener("blur", () => { if (prefs.mode === "ptt") talking(false); });
        document.addEventListener("visibilitychange", () => { if (document.hidden && prefs.mode === "ptt") talking(false); });
    }

    // ---- tiles -----------------------------------------------------------------------

    const cssId = (user) => String(user).replace(/[^a-zA-Z0-9_-]/g, "");
    const tileOf = (user) => document.getElementById("tile-" + cssId(user));

    function icon(name, size = 13) {
        const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
        svg.setAttribute("width", size);
        svg.setAttribute("height", size);
        svg.setAttribute("aria-hidden", "true");
        const use = document.createElementNS("http://www.w3.org/2000/svg", "use");
        use.setAttribute("href", "#" + name);
        svg.append(use);
        return svg;
    }

    // Called by app.js whenever a tile is drawn or its stream changes.
    function tile(el, user, stream, local) {
        el.dataset.user = user;
        if (!el.dataset.decorated) {
            el.dataset.decorated = "1";
            const face = el.querySelector(".initials");
            if (face && CairnProfile && CairnProfile.avatar) {
                face.textContent = "";
                face.append(CairnProfile.avatar(user, 76));
            }
            const name = el.querySelector(".label span:not(.dot)");
            if (name && CairnProfile && CairnProfile.nameInto) {
                name.classList.add("pf-name-host");
                CairnProfile.nameInto(name, CairnProfile.view(user), local ? " (you)" : "");
            }
            const badges = document.createElement("span");
            badges.className = "tile-badges";
            el.append(badges);
            if (!local) {
                const menu = document.createElement("button");
                menu.type = "button";
                menu.className = "tile-menu ghost";
                menu.title = "Volume for " + label(user);
                menu.setAttribute("aria-label", "Volume for " + label(user));
                menu.append(icon("i-volume", 15));
                menu.addEventListener("click", (e) => { e.stopPropagation(); openVolume(user, menu); });
                el.append(menu);
                el.addEventListener("contextmenu", (e) => { e.preventDefault(); openVolume(user, menu); });
            }
        }
        if (local) {
            CairnCallAudio.attachLocal(user, CairnCall.local || stream);
            badge(user, { muted: muted || deafened, deafened });
        } else {
            CairnCallAudio.attach(user, stream, el.querySelector("video"));
            badge(user, peerStates.get(user) || { muted: false, deafened: false });
        }
    }

    function untile(user) {
        CairnCallAudio.detach(user);
        peerStates.delete(user);
        connected.delete(user);
        closeVolume();
    }

    function peerState(user, state) {
        peerStates.set(user, state);
        badge(user, state);
    }

    // What everyone can see about a participant, plus what only you chose about them.
    function badge(user, state) {
        const el = tileOf(user);
        if (!el) return;
        const box = el.querySelector(".tile-badges");
        if (!box) return;
        box.textContent = "";
        const add = (name, text, cls) => {
            const b = document.createElement("span");
            b.className = "tile-badge " + (cls || "");
            b.title = text;
            b.setAttribute("aria-label", text);
            b.append(icon(name));
            box.append(b);
        };
        if (state.deafened) add("i-deaf", "Deafened", "deafened");
        else if (state.muted) add("i-mic-off", "Muted", "muted");
        const mine = el.dataset.user !== hooks.me() ? CairnCallAudio.prefsFor(user) : null;
        if (mine && mine.muted) add("i-volume-off", "Muted for you", "local");
        else if (mine && mine.volume !== 100) {
            const b = document.createElement("span");
            b.className = "tile-badge local mono";
            b.textContent = mine.volume + "%";
            b.title = "Your volume for " + label(user);
            box.append(b);
        }
        el.classList.toggle("is-muted", !!(state.muted || state.deafened));
    }

    function speaking(user, on) {
        const el = tileOf(user);
        if (el) el.classList.toggle("speaking", on);
    }

    // ---- per-person volume -----------------------------------------------------------

    let popFor = null;

    function openVolume(user, anchor) {
        const pop = $("volume-pop");
        if (!pop) return;
        if (popFor === user && !pop.hidden) { closeVolume(); return; }
        popFor = user;
        const p = CairnCallAudio.prefsFor(user);
        $("volume-who").textContent = label(user);
        $("volume-range").value = p.volume;
        $("volume-out").textContent = p.volume + "%";
        $("volume-mute").checked = p.muted;
        pop.hidden = false;
        const r = anchor.getBoundingClientRect();
        const w = pop.offsetWidth || 240;
        pop.style.left = Math.max(8, Math.min(window.innerWidth - w - 8, r.right - w)) + "px";
        pop.style.top = (r.bottom + 6) + "px";
        $("volume-range").focus();
    }

    function closeVolume() {
        const pop = $("volume-pop");
        if (pop) pop.hidden = true;
        popFor = null;
    }

    function bindVolume() {
        const range = $("volume-range");
        if (!range) return;
        range.addEventListener("input", () => {
            if (!popFor) return;
            CairnCallAudio.setVolume(popFor, range.value);
            $("volume-out").textContent = range.value + "%";
            badge(popFor, peerStates.get(popFor) || {});
        });
        $("volume-mute").addEventListener("change", () => {
            if (!popFor) return;
            CairnCallAudio.setLocalMute(popFor, $("volume-mute").checked);
            badge(popFor, peerStates.get(popFor) || {});
        });
        $("volume-reset").addEventListener("click", () => {
            if (!popFor) return;
            CairnCallAudio.setVolume(popFor, 100);
            CairnCallAudio.setLocalMute(popFor, false);
            range.value = 100;
            $("volume-out").textContent = "100%";
            $("volume-mute").checked = false;
            badge(popFor, peerStates.get(popFor) || {});
        });
        document.addEventListener("click", (ev) => {
            if (popFor && !ev.target.closest("#volume-pop, .tile-menu")) closeVolume();
        });
        document.addEventListener("keydown", (ev) => { if (ev.key === "Escape") closeVolume(); });
    }

    // ---- wiring ------------------------------------------------------------------

    function init(h) {
        hooks = { ...hooks, ...h };
        CairnCall.bind({
            onPeerState: (user, state) => peerState(user, state),
            onDecline: (from) => declined(from),
        });
        CairnCallAudio.bind({ onSpeaking: (user, on) => speaking(user, on) });
        CairnCall.setPrefs(prefs);
        $("accept-voice").addEventListener("click", () => accept(false));
        $("accept-video").addEventListener("click", () => accept(true));
        $("decline").addEventListener("click", () => decline());
        $("mute").addEventListener("click", () => toggleMute());
        $("deafen").addEventListener("click", () => toggleDeafen());
        $("call-settings").addEventListener("click", () => {
            CairnLook.open();
            const box = $("prefs-voice");
            if (box) box.closest(".set-section").scrollIntoView({ block: "start" });
        });
        bindPrefs();
        bindKeys();
        bindVolume();
        syncCallbar();
    }

    return {
        init, ring, stopRinging, started, ended, peerConnection, tile, untile, syncPrefs,
        get prefs() { return { ...prefs }; },
        get ringingFor() { return ringing ? ringing.from : null; },
    };
})();
