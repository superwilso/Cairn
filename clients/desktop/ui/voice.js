// Voice notes: recording one, and playing one back. Presentation only.
//
// A recording is just a file. It leaves through the same `CairnAttach.sendBytes` path as a
// photo — sealed in Rust under a fresh key, uploaded as ciphertext, its key carried inside
// the encrypted message — and Rust decides from the type whether a recipient is shown a
// player (`kind: "audio"`). Nothing here touches a key or decides what is believed.
//
// Recording: press and hold the mic to record, release to send; release off the button to
// throw it away. A quick click instead locks recording on, with Send and Cancel in the bar.
// Escape cancels either way. Recording stops itself, and sends, at MAX_MS.

const CairnVoice = (() => {
    // Two minutes of 32 kbit/s Opus is under half a megabyte: a voice note, not a podcast,
    // and comfortably inside the attachment ceiling Rust enforces.
    const MAX_MS = 2 * 60 * 1000;
    // Shorter than this is a slipped finger, not a message.
    const MIN_MS = 600;
    // A press held longer than this is "hold to talk"; shorter is a click that locks.
    const HOLD_MS = 300;
    // In order of preference. Opus in either container is what Chromium and WebView2
    // produce, and what Rust's normalisation treats as playable audio; WebKit records AAC
    // in MP4. Whatever the recorder actually reports is what is sent.
    const TYPES = ["audio/ogg;codecs=opus", "audio/webm;codecs=opus", "audio/webm", "audio/mp4"];

    let opts = { send: null, onSent: () => {}, onError: () => {}, onNotice: () => {} };
    let button = null;
    let composer = null;
    let bar = null;
    let rec = null;          // the recording in progress, if any
    let playing = null;      // the one <audio> playing, so starting another pauses it

    function fmt(ms) {
        const s = Math.max(0, Math.floor(ms / 1000));
        return Math.floor(s / 60) + ":" + String(s % 60).padStart(2, "0");
    }

    function pickType() {
        if (!window.MediaRecorder || !MediaRecorder.isTypeSupported) return "";
        return TYPES.find((t) => MediaRecorder.isTypeSupported(t)) || "";
    }

    function extension(mime) {
        if (mime.startsWith("audio/ogg")) return "ogg";
        if (mime.startsWith("audio/mp4")) return "m4a";
        return "webm";
    }

    function buildBar() {
        bar = document.createElement("div");
        bar.className = "voice-bar";
        bar.hidden = true;
        bar.setAttribute("role", "status");
        bar.innerHTML =
            '<span class="voice-dot" aria-hidden="true"></span>' +
            '<span class="voice-label">Recording</span>' +
            '<span class="voice-timer mono">0:00</span>' +
            '<span class="voice-hint"></span>' +
            '<span class="voice-grow"></span>' +
            '<button type="button" class="ghost voice-cancel">Cancel</button>' +
            '<button type="button" class="primary voice-send">Send</button>';
        bar.querySelector(".voice-cancel").onclick = () => finish(false);
        bar.querySelector(".voice-send").onclick = () => finish(true);
        composer.prepend(bar);
    }

    function showBar(locked) {
        bar.hidden = false;
        // Cover the composer up to the mic, which stays visible as the thing being held.
        const c = composer.getBoundingClientRect();
        const b = button.getBoundingClientRect();
        if (c.width && b.width) bar.style.right = Math.max(8, c.right - b.left + 8) + "px";
        bar.classList.toggle("locked", locked);
        bar.querySelector(".voice-hint").textContent = locked
            ? ""
            : "Release to send · release elsewhere to cancel";
        composer.classList.add("voice-recording");
    }

    function hideBar() {
        bar.hidden = true;
        composer.classList.remove("voice-recording");
    }

    function tick() {
        if (!rec) return;
        const ms = Date.now() - rec.started;
        bar.querySelector(".voice-timer").textContent = fmt(ms) + " / " + fmt(MAX_MS);
        if (ms >= MAX_MS) {
            opts.onNotice("Voice notes stop at " + fmt(MAX_MS) + "; sending what was recorded.");
            finish(true);
        }
    }

    async function start(locked) {
        if (rec) return;
        if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia || !window.MediaRecorder) {
            opts.onError("This device cannot record audio here.");
            return;
        }
        // Claimed before the await, so a second press while the permission prompt is up
        // does not start a second recorder.
        rec = { pending: true, locked, started: Date.now(), chunks: [], cancelled: false };
        let stream;
        try {
            stream = await navigator.mediaDevices.getUserMedia({
                audio: { echoCancellation: true, noiseSuppression: true, autoGainControl: true },
            });
        } catch (e) {
            rec = null;
            opts.onError("The microphone is not available: " + (e && e.message ? e.message : e));
            return;
        }
        // Released (and cancelled) while the prompt was still up.
        if (!rec || rec.cancelled) {
            stream.getTracks().forEach((t) => t.stop());
            rec = null;
            return;
        }
        const type = pickType();
        let recorder;
        try {
            recorder = new MediaRecorder(stream, type ? { mimeType: type, audioBitsPerSecond: 32000 } : undefined);
        } catch (e) {
            stream.getTracks().forEach((t) => t.stop());
            rec = null;
            opts.onError("Could not start recording: " + e);
            return;
        }
        Object.assign(rec, { pending: false, stream, recorder, type, started: Date.now() });
        // Into this recording's own list, not whatever `rec` is by then: the last chunk is
        // delivered after stop(), when `finish` has already cleared `rec`, and reading the
        // global here silently dropped the final quarter-second of every note.
        const chunks = rec.chunks;
        recorder.ondataavailable = (ev) => { if (ev.data && ev.data.size) chunks.push(ev.data); };
        recorder.start(250);
        rec.timer = setInterval(tick, 200);
        button.classList.add("on");
        button.setAttribute("aria-pressed", "true");
        showBar(rec.locked);
        tick();
        // The hold was released while getUserMedia was still resolving.
        if (rec.releaseAfterStart) {
            const how = rec.releaseAfterStart;
            rec.releaseAfterStart = null;
            if (how === "send") finish(true);
            else if (how === "cancel") finish(false);
        }
    }

    /// Stop recording; send what was recorded if `sendIt`.
    async function finish(sendIt) {
        const r = rec;
        if (!r) return;
        if (r.pending) {
            // Still waiting on the microphone; settle once it arrives.
            r.cancelled = !sendIt;
            r.releaseAfterStart = sendIt ? "send" : "cancel";
            if (!sendIt) rec = null;
            return;
        }
        rec = null;
        clearInterval(r.timer);
        button.classList.remove("on");
        button.setAttribute("aria-pressed", "false");
        hideBar();
        const stopped = new Promise((resolve) => { r.recorder.onstop = resolve; });
        try { r.recorder.stop(); } catch (_) { /* already stopped */ }
        await stopped;
        r.stream.getTracks().forEach((t) => t.stop());
        if (!sendIt) return;

        const elapsed = Date.now() - r.started;
        if (elapsed < MIN_MS || !r.chunks.length) {
            opts.onError("That was too short to send — hold the mic while you talk.");
            return;
        }
        // The recorder's own report of what it produced beats what was asked for.
        const mime = r.recorder.mimeType || r.type || "audio/webm";
        const blob = new Blob(r.chunks, { type: mime });
        const bytes = new Uint8Array(await blob.arrayBuffer());
        const stamp = new Date().toISOString().slice(0, 16).replace("T", " ").replace(":", "-");
        const name = "Voice note " + stamp + "." + extension(mime);
        const pending = opts.onNotice("Sending voice note…");
        try {
            opts.onSent(await opts.send(bytes, name, mime));
        } catch (e) {
            opts.onError(e);
        } finally {
            if (pending && pending.remove) pending.remove();
        }
    }

    function bind(o) {
        opts = Object.assign(opts, o);
        button = o.button;
        composer = o.composer;
        buildBar();

        let pressedAt = 0;
        button.addEventListener("pointerdown", (ev) => {
            if (ev.button !== 0) return;
            ev.preventDefault();
            if (rec && rec.locked) return finish(true); // second click on a locked recording sends it
            if (!o.canRecord()) return;
            pressedAt = Date.now();
            try { button.setPointerCapture(ev.pointerId); } catch (_) { /* not supported */ }
            start(false);
        });
        button.addEventListener("pointerup", (ev) => {
            if (!rec || rec.locked || !pressedAt) return;
            const held = Date.now() - pressedAt;
            pressedAt = 0;
            if (held < HOLD_MS) {
                // A click: keep recording, with Send and Cancel in the bar.
                rec.locked = true;
                if (!rec.pending) showBar(true);
                return;
            }
            const r = button.getBoundingClientRect();
            const inside = ev.clientX >= r.left && ev.clientX <= r.right && ev.clientY >= r.top && ev.clientY <= r.bottom;
            finish(inside);
        });
        button.addEventListener("pointercancel", () => { if (rec && !rec.locked) finish(false); });
        // Keyboard: Enter or Space on the button toggles a locked recording.
        button.addEventListener("keydown", (ev) => {
            if (ev.key !== "Enter" && ev.key !== " ") return;
            ev.preventDefault();
            if (rec) finish(true);
            else if (o.canRecord()) start(true);
        });
        document.addEventListener("keydown", (ev) => {
            if (ev.key === "Escape" && rec) finish(false);
        });
    }

    // ---- playback ---------------------------------------------------------------

    const BARS = 44;

    /// Peaks for a waveform, from the decoded audio. Decoding is local: the bytes are
    /// already in the page, opened by Rust.
    async function peaks(bytes) {
        const Ctx = window.AudioContext || window.webkitAudioContext;
        if (!Ctx) return null;
        const ctx = new Ctx();
        try {
            const audio = await ctx.decodeAudioData(bytes.slice().buffer);
            const data = audio.getChannelData(0);
            const step = Math.max(1, Math.floor(data.length / BARS));
            const out = [];
            for (let b = 0; b < BARS; b++) {
                let sum = 0;
                const from = b * step;
                const to = Math.min(data.length, from + step);
                for (let i = from; i < to; i++) sum += data[i] * data[i];
                out.push(Math.sqrt(sum / Math.max(1, to - from)));
            }
            const max = Math.max(...out, 1e-4);
            return { bars: out.map((v) => v / max), duration: audio.duration };
        } catch (_) {
            return null;
        } finally {
            if (ctx.close) ctx.close().catch(() => {});
        }
    }

    /// A player for an audio attachment. `load()` resolves to `{ bytes, url }`.
    function player(att, load) {
        const box = document.createElement("div");
        box.className = "voice-player";
        const play = document.createElement("button");
        play.type = "button";
        play.className = "voice-play";
        play.setAttribute("aria-label", "Play");
        play.disabled = true;
        play.innerHTML = '<svg viewBox="0 0 24 24" width="16" height="16" aria-hidden="true"><path class="voice-icon-play" fill="currentColor" d="M8 5.5v13l10.5-6.5z"/><path class="voice-icon-pause" fill="currentColor" d="M7 5h3.5v14H7zM13.5 5H17v14h-3.5z"/></svg>';
        const wave = document.createElement("div");
        wave.className = "voice-wave";
        wave.setAttribute("role", "slider");
        wave.setAttribute("aria-label", "Position");
        wave.setAttribute("aria-valuemin", "0");
        wave.setAttribute("aria-valuemax", "100");
        wave.setAttribute("aria-valuenow", "0");
        wave.tabIndex = 0;
        const bars = [];
        for (let i = 0; i < BARS; i++) {
            const s = document.createElement("span");
            // A gentle placeholder shape until the real one is decoded.
            s.style.height = (22 + 18 * Math.abs(Math.sin(i * 0.7))) + "%";
            bars.push(s);
            wave.append(s);
        }
        const time = document.createElement("span");
        time.className = "voice-time mono";
        time.textContent = "–:––";
        const audio = document.createElement("audio");
        audio.preload = "metadata";
        box.append(play, wave, time, audio);

        let duration = NaN;
        const known = () => (Number.isFinite(duration) && duration > 0 ? duration
            : Number.isFinite(audio.duration) ? audio.duration : NaN);
        function draw() {
            const d = known();
            const frac = d ? Math.min(1, audio.currentTime / d) : 0;
            const upto = Math.round(frac * BARS);
            bars.forEach((b, i) => b.classList.toggle("played", i < upto));
            wave.setAttribute("aria-valuenow", String(Math.round(frac * 100)));
            time.textContent = d
                ? (audio.currentTime > 0 ? fmt(audio.currentTime * 1000) + " / " : "") + fmt(d * 1000)
                : "–:––";
            box.classList.toggle("is-playing", !audio.paused);
            play.setAttribute("aria-label", audio.paused ? "Play" : "Pause");
        }
        let raf = 0;
        const loop = () => { draw(); if (!audio.paused) raf = requestAnimationFrame(loop); };
        audio.addEventListener("play", () => {
            if (playing && playing !== audio) playing.pause();
            playing = audio;
            cancelAnimationFrame(raf);
            loop();
        });
        audio.addEventListener("pause", draw);
        audio.addEventListener("ended", () => { audio.currentTime = 0; draw(); });
        audio.addEventListener("loadedmetadata", draw);
        audio.addEventListener("durationchange", draw);

        play.onclick = () => (audio.paused ? audio.play().catch((e) => opts.onError(e)) : audio.pause());
        function seekTo(frac) {
            const d = known();
            if (!d) return;
            audio.currentTime = Math.max(0, Math.min(d, frac * d));
            draw();
        }
        wave.addEventListener("click", (ev) => {
            const r = wave.getBoundingClientRect();
            seekTo((ev.clientX - r.left) / r.width);
        });
        wave.addEventListener("keydown", (ev) => {
            const d = known();
            if (!d) return;
            if (ev.key === "ArrowRight") { ev.preventDefault(); seekTo((audio.currentTime + 5) / d); }
            if (ev.key === "ArrowLeft") { ev.preventDefault(); seekTo((audio.currentTime - 5) / d); }
            if (ev.key === " " || ev.key === "Enter") { ev.preventDefault(); play.click(); }
        });

        load().then(async ({ bytes, url }) => {
            audio.src = url;
            play.disabled = false;
            const p = await peaks(bytes);
            if (p) {
                // A recorder's WebM carries no duration in its header, so the element reports
                // Infinity until played through; the decoded length is the real one.
                duration = p.duration;
                p.bars.forEach((v, i) => { bars[i].style.height = Math.max(8, Math.round(v * 100)) + "%"; });
                box.classList.add("decoded");
            }
            draw();
        }, (e) => {
            box.classList.add("failed");
            time.textContent = "Could not open: " + e;
        });
        return box;
    }

    return { bind, player, MAX_MS };
})();
