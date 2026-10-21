// Cairn calls — what this device plays and hears: per-person volume, deafen, speaking
// detection, and the ring.
//
// Presentation only. Nothing here decides who is in a call or touches a key; it takes the
// MediaStreams call.js already has and routes their sound. Every setting here stays on this
// device — another participant never learns that you turned them down.
//
// ## Two paths for a voice, and why the plain one is the default
//
// Up to 100%, a voice plays through its tile's own media element, with `volume` and `muted`
// — the path every webview has played WebRTC audio through for years. A media element's
// volume stops at 100%, though, and a quiet microphone on the other end needs more. Above
// 100% a voice is switched to WebAudio: source → gain → a MediaStream destination → its own
// hidden <audio> element, which is still a media element, so the output-device choice
// (`setSinkId`) keeps working.
//
// The boost is the exception rather than the rule on purpose. An AudioContext can start
// suspended — a webview's autoplay policy keeps it so until the user has clicked something —
// and a suspended graph is silence; and the three webviews Tauri runs on do not all treat a
// remote WebRTC stream in WebAudio alike. Whatever goes wrong with the graph, the worst case
// is "the boost does not work", never "I cannot hear anyone". The analysers for the speaking
// ring tap the same source and never sit in the path of what is heard.

/* eslint-env browser */

const CairnCallAudio = (() => {
    const KEY = "cairn.callvol.v1";
    let ctx = null;
    let deafened = false;
    const voices = new Map();   // user -> { stream, source, gain, analyser, out, el }
    let localVoice = null;      // { stream, source, analyser } for the speaking ring on your own tile
    let onSpeaking = () => {};
    const speaking = new Map(); // user -> { on, until }
    let loop = null;
    let saved = load();

    // ---- per-person settings, this device only ---------------------------------

    function load() {
        try {
            const raw = JSON.parse(localStorage.getItem(KEY) || "{}");
            const out = {};
            for (const [user, v] of Object.entries(raw || {})) {
                if (!/^usr_[0-9a-zA-Z-]{1,64}$/.test(user) || !v || typeof v !== "object") continue;
                out[user] = {
                    volume: clampVolume(v.volume),
                    muted: v.muted === true,
                    board: clampBoard(v.board),
                    boardMuted: v.boardMuted === true,
                };
            }
            return out;
        } catch (_) { return {}; }
    }
    function save() {
        try { localStorage.setItem(KEY, JSON.stringify(saved)); } catch (_) { /* not persisted */ }
    }
    function clampVolume(v) {
        const n = Number(v);
        return Number.isFinite(n) ? Math.min(200, Math.max(0, Math.round(n))) : 100;
    }
    // A soundboard's level stops at 100%: it is there to turn clips down, not up.
    function clampBoard(v) {
        const n = Number(v);
        return Number.isFinite(n) ? Math.min(100, Math.max(0, Math.round(n))) : 100;
    }
    const prefsFor = (user) =>
        ({ volume: 100, muted: false, board: 100, boardMuted: false, ...(saved[user] || {}) });

    function setVolume(user, pct) {
        saved[user] = { ...prefsFor(user), volume: clampVolume(pct) };
        save();
        apply(user);
    }
    function setLocalMute(user, muted) {
        saved[user] = { ...prefsFor(user), muted: !!muted };
        save();
        apply(user);
    }

    // ---- soundboards, per listener ---------------------------------------------
    //
    // A participant's clips arrive on their own track (call.js, voicechannel.js), so each
    // listener can turn one person's soundboard down, or off, or everyone's, without touching
    // anyone's voice. Like the voice settings above, nothing here leaves this device. The cost
    // of the separate track is stated in docs/13-customisation.md: whoever carries the media
    // can see when a clip is playing.
    const ALL_BOARDS_KEY = "cairn.soundboards.muted";
    let allBoardsMuted = (() => {
        try { return localStorage.getItem(ALL_BOARDS_KEY) === "1"; } catch (_) { return false; }
    })();
    const boards = new Map();   // user -> { stream, el, source, gain, out }
    const boardListeners = [];

    function boardsChanged(user) {
        if (user) applyBoard(user); else for (const u of boards.keys()) applyBoard(u);
        for (const fn of boardListeners) { try { fn(user || null); } catch (_) {} }
    }
    function setBoardVolume(user, pct) {
        saved[user] = { ...prefsFor(user), board: clampBoard(pct) };
        save();
        boardsChanged(user);
    }
    function setBoardMuted(user, muted) {
        saved[user] = { ...prefsFor(user), boardMuted: !!muted };
        save();
        boardsChanged(user);
    }
    function setAllBoardsMuted(on) {
        allBoardsMuted = !!on;
        try { localStorage.setItem(ALL_BOARDS_KEY, allBoardsMuted ? "1" : "0"); } catch (_) {}
        boardsChanged(null);
    }

    // What this device plays, 0..1, for one person's voice and for their soundboard. Used
    // here for the mesh, and by voicechannel.js for the SFU's receive slots.
    function voiceLevel(user) {
        const p = prefsFor(user);
        return deafened || p.muted ? 0 : p.volume / 100;
    }
    function boardLevel(user) {
        const p = prefsFor(user);
        return deafened || allBoardsMuted || p.boardMuted ? 0 : p.board / 100;
    }

    // A participant's soundboard track. Played through the graph when it runs — source →
    // gain → its own <audio> — so a mute is a gain of zero on exactly this track; otherwise
    // through a plain element whose volume is set instead. The element is kept either way:
    // Chromium only feeds a remote WebRTC track to WebAudio while an element consumes it.
    function attachBoard(user, stream) {
        let b = boards.get(user);
        if (b && b.stream === stream) { applyBoard(user); return; }
        if (b) detachBoard(user);
        b = { stream, el: new Audio(), source: null, gain: null, out: null, dest: null };
        b.el.autoplay = true;
        b.el.srcObject = stream;
        b.el.dataset.callBoard = user;
        if (typeof CairnCall !== "undefined") CairnCall.applySpeaker(b.el);
        b.el.play().catch(() => {});
        boards.set(user, b);
        const c = context();
        if (c && stream.getAudioTracks().length) {
            try {
                b.source = c.createMediaStreamSource(stream);
                b.gain = c.createGain();
                b.dest = c.createMediaStreamDestination();
                b.source.connect(b.gain);
                b.gain.connect(b.dest);
                b.out = new Audio();
                b.out.autoplay = true;
                b.out.srcObject = b.dest.stream;
                if (typeof CairnCall !== "undefined") CairnCall.applySpeaker(b.out);
                b.out.play().catch(() => {});
            } catch (_) {
                b.source = b.gain = b.out = b.dest = null;
            }
        }
        applyBoard(user);
    }

    function detachBoard(user) {
        const b = boards.get(user);
        if (!b) return;
        for (const n of [b.source, b.gain]) { try { n && n.disconnect(); } catch (_) {} }
        for (const el of [b.el, b.out]) if (el) { el.srcObject = null; el.remove(); }
        boards.delete(user);
    }

    function applyBoard(user) {
        const b = boards.get(user);
        if (!b) return;
        const level = boardLevel(user);
        if (running() && b.gain && b.out) {
            b.gain.gain.value = level;
            b.out.muted = false;
            b.el.muted = true;
        } else {
            if (b.out) b.out.muted = true;
            b.el.muted = level === 0;
            b.el.volume = Math.min(1, level);
        }
    }

    // What this device is playing for one person's soundboard, when it plays through the
    // graph: the browser test measures it, so "muted" means silence and not a flag.
    function boardOutput(user) {
        const b = boards.get(user);
        return b && running() && b.dest ? b.dest.stream : null;
    }

    // ---- the graph -------------------------------------------------------------

    function context() {
        if (ctx) return ctx;
        const AC = window.AudioContext || window.webkitAudioContext;
        if (!AC) return null;
        try { ctx = new AC(); } catch (_) { return null; }
        // Nothing is connected to ctx.destination except the ring: voices leave through
        // their own <audio> elements, so each can be sent to the chosen output device.
        ctx.onstatechange = () => {
            for (const user of voices.keys()) apply(user);
            for (const user of boards.keys()) applyBoard(user);
        };
        return ctx;
    }

    // Autoplay policy: a context made before the user has interacted stays suspended. Any
    // click or key resumes it; calling this from a click handler resumes it at once.
    function resume() {
        const c = context();
        if (c && c.state === "suspended") c.resume().catch(() => {});
    }
    document.addEventListener("pointerdown", resume, { capture: true });
    document.addEventListener("keydown", resume, { capture: true });

    const running = () => !!ctx && ctx.state === "running";

    // Route a participant's sound. `el` is their tile's media element, which carries the
    // video and is the fallback output when the graph cannot run.
    function attach(user, stream, el) {
        let v = voices.get(user);
        if (v && v.stream === stream && v.el === el) { apply(user); return; }
        if (v) detach(user);
        v = { stream, el, source: null, gain: null, analyser: null, out: null };
        voices.set(user, v);

        const c = context();
        if (c && stream.getAudioTracks().length) {
            try {
                v.source = c.createMediaStreamSource(stream);
                v.gain = c.createGain();
                v.analyser = speakingAnalyser(c);
                const dest = c.createMediaStreamDestination();
                v.source.connect(v.analyser);
                v.source.connect(v.gain);
                v.gain.connect(dest);
                v.out = new Audio();
                v.out.autoplay = true;
                v.out.srcObject = dest.stream;
                v.out.dataset.callAudio = user;
                if (typeof CairnCall !== "undefined") CairnCall.applySpeaker(v.out);
                v.out.play().catch(() => {});
            } catch (_) {
                v.source = v.gain = v.analyser = v.out = null;
            }
        }
        apply(user);
        startLoop();
    }

    function detach(user) {
        const v = voices.get(user);
        if (!v) return;
        for (const n of [v.source, v.gain, v.analyser]) { try { n && n.disconnect(); } catch (_) {} }
        if (v.out) { v.out.srcObject = null; v.out.remove(); }
        voices.delete(user);
        speaking.delete(user);
    }

    // Put one participant's chosen volume into effect, on whichever path is live.
    function apply(user) {
        const v = voices.get(user);
        if (!v) return;
        const p = prefsFor(user);
        const level = deafened || p.muted ? 0 : p.volume / 100;
        const boost = level > 1 && running() && v.gain && v.out;
        if (boost) {
            v.gain.gain.value = level;
            v.out.muted = false;
            if (v.el) v.el.muted = true;
        } else {
            if (v.out) v.out.muted = true;
            if (v.el) {
                v.el.muted = level === 0;
                v.el.volume = Math.min(1, level);
            }
        }
    }

    function setDeafened(on) {
        deafened = !!on;
        for (const user of voices.keys()) apply(user);
        boardsChanged(null);
    }

    function applySpeakerAll() {
        if (typeof CairnCall === "undefined") return;
        for (const v of voices.values()) if (v.out) CairnCall.applySpeaker(v.out);
    }

    // ---- speaking --------------------------------------------------------------

    function attachLocal(user, stream) {
        detachLocal();
        const c = context();
        if (!c || !stream || !stream.getAudioTracks().length) return;
        try {
            const source = c.createMediaStreamSource(stream);
            const analyser = speakingAnalyser(c);
            source.connect(analyser);
            localVoice = { user, stream, source, analyser };
        } catch (_) { localVoice = null; }
        startLoop();
    }

    function detachLocal() {
        if (!localVoice) return;
        try { localVoice.source.disconnect(); } catch (_) {}
        localVoice = null;
    }

    // How often the speaking loop reads the analysers, and how much each read must see.
    //
    // An analyser holds only its last `fftSize` samples. At 512 — the size this used to be —
    // that is 10.7 ms of each 90 ms tick, so nearly nine tenths of what someone said was
    // never measured, and any sound shorter than a tick was seen or missed by where it fell
    // against the loop's phase. Found by tracing the browser test: the fake microphone beeps
    // for a few tens of milliseconds every 500 ms, and the ring caught at most every other
    // beep, in a pattern that drifted with the aliasing between the two periods — dark for
    // seconds at a time while sound was arriving. The window now spans a whole tick (the
    // next power of two up, so reads overlap slightly), and every sample is looked at.
    const TICK_MS = 90;
    function speakingAnalyser(c) {
        const analyser = c.createAnalyser();
        const want = Math.ceil((c.sampleRate * TICK_MS) / 1000);
        let size = 32;
        while (size < want && size < 32768) size *= 2;
        analyser.fftSize = size;
        return analyser;
    }

    function level(analyser) {
        const buf = new Float32Array(analyser.fftSize);
        analyser.getFloatTimeDomainData(buf);
        let sum = 0;
        for (let i = 0; i < buf.length; i++) sum += buf[i] * buf[i];
        return Math.sqrt(sum / buf.length);
    }

    // A ring that flickers on every syllable is noise, so a voice stays "speaking" for a
    // moment after it drops below the threshold.
    const THRESHOLD = 0.012;
    const HANG_MS = 350;

    function mark(user, loud, now) {
        const s = speaking.get(user) || { on: false, until: 0 };
        if (loud) s.until = now + HANG_MS;
        const on = now < s.until;
        if (on !== s.on) { s.on = on; onSpeaking(user, on); }
        speaking.set(user, s);
    }

    function startLoop() {
        if (loop) return;
        loop = setInterval(() => {
            const now = Date.now();
            for (const [user, v] of voices) {
                if (!v.analyser || !running()) continue;
                // Measured before the gain, so turning someone down locally does not hide
                // that they are talking.
                mark(user, level(v.analyser) > THRESHOLD, now);
            }
            if (localVoice && running()) {
                const open = localVoice.stream.getAudioTracks().some((t) => t.enabled);
                mark(localVoice.user, open && level(localVoice.analyser) > THRESHOLD, now);
            }
            if (!voices.size && !localVoice) { clearInterval(loop); loop = null; }
        }, TICK_MS);
    }

    function reset() {
        for (const user of [...voices.keys()]) detach(user);
        for (const user of [...boards.keys()]) detachBoard(user);
        detachLocal();
        speaking.clear();
        deafened = false;
    }

    // ---- the ring --------------------------------------------------------------
    //
    // Generated, not bundled: two soft notes and a pause, every two seconds. No file to ship,
    // nothing fetched, and it follows the output device like everything else here when the
    // webview allows choosing one for a context.

    let ring = null;

    function startRing() {
        stopRing();
        const c = context();
        if (!c) return false;
        resume();
        const out = c.createGain();
        out.gain.value = 0.18;
        out.connect(c.destination);
        const chime = () => {
            const t = c.currentTime + 0.02;
            [[659.25, 0], [880, 0.22], [659.25, 0.7], [880, 0.92]].forEach(([freq, at]) => {
                const osc = c.createOscillator();
                const env = c.createGain();
                osc.type = "sine";
                osc.frequency.value = freq;
                env.gain.setValueAtTime(0, t + at);
                env.gain.linearRampToValueAtTime(1, t + at + 0.02);
                env.gain.exponentialRampToValueAtTime(0.001, t + at + 0.45);
                osc.connect(env);
                env.connect(out);
                osc.start(t + at);
                osc.stop(t + at + 0.5);
            });
        };
        chime();
        ring = { out, timer: setInterval(chime, 2600) };
        return c.state === "running";
    }

    function stopRing() {
        if (!ring) return;
        clearInterval(ring.timer);
        try { ring.out.disconnect(); } catch (_) {}
        ring = null;
    }

    return {
        attach, detach, attachLocal, setDeafened, setVolume, setLocalMute,
        prefsFor, applySpeakerAll, startRing, stopRing, resume, reset,
        attachBoard, detachBoard, setBoardVolume, setBoardMuted, setAllBoardsMuted,
        voiceLevel, boardLevel, boardOutput,
        onBoardChange(fn) { boardListeners.push(fn); },
        get allBoardsMuted() { return allBoardsMuted; },
        get deafened() { return deafened; },
        bind(h) { if (h.onSpeaking) onSpeaking = h.onSpeaking; },
        get ringing() { return !!ring; },
        get running() { return running(); },
    };
})();
