// Cairn calls — what this device plays and hears: per-person volume, deafen, speaking
// detection, and the ring.
//
// Presentation only. Nothing here decides who is in a call or touches a key; it takes the
// MediaStreams call.js already has and routes their sound. Every setting here stays on this
// device — another participant never learns that you turned them down.
//
// ## Why remote audio goes through WebAudio
//
// A media element's `volume` stops at 100%, and a quiet microphone on the other end needs
// more than that. So each remote voice runs source → gain → a MediaStream destination → its
// own hidden <audio> element: the gain gives 0–200%, and the element is still a media element,
// so the output-device choice (`setSinkId`) keeps working. The tile's <video> stays muted.
//
// **The fallback matters more than the feature.** An AudioContext can start suspended — the
// webview's autoplay policy keeps it so until the user has clicked something — and a
// suspended graph is silence. Whenever the context is not running, a voice plays through its
// tile's own element instead, capped at 100%, so the worst case is "the boost does not work
// yet", never "I cannot hear anyone".

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
                out[user] = { volume: clampVolume(v.volume), muted: v.muted === true };
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
    const prefsFor = (user) => saved[user] || { volume: 100, muted: false };

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

    // ---- the graph -------------------------------------------------------------

    function context() {
        if (ctx) return ctx;
        const AC = window.AudioContext || window.webkitAudioContext;
        if (!AC) return null;
        try { ctx = new AC(); } catch (_) { return null; }
        // Nothing is connected to ctx.destination except the ring: voices leave through
        // their own <audio> elements, so each can be sent to the chosen output device.
        ctx.onstatechange = () => { for (const user of voices.keys()) apply(user); };
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
                v.analyser = c.createAnalyser();
                v.analyser.fftSize = 512;
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
        const graph = running() && v.gain && v.out;
        if (graph) {
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
            const analyser = c.createAnalyser();
            analyser.fftSize = 512;
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
        }, 90);
    }

    function reset() {
        for (const user of [...voices.keys()]) detach(user);
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
        bind(h) { if (h.onSpeaking) onSpeaking = h.onSpeaking; },
        get ringing() { return !!ring; },
        get running() { return running(); },
    };
})();
