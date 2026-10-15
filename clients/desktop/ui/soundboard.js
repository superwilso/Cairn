// The soundboard: a room's short clips, played into a call.
//
// ## How a clip reaches everyone
//
// Mixed into this device's outgoing microphone track (`CairnCall.mixIntoMic`), and played
// locally at the same level so the person pressing the button hears what they sent. There is
// no "play X" message: one would cross the instance — encrypted, but timed — whereas the mix
// is just more audio on a peer-to-peer track the instance never carries. The clip's bytes come
// from this device's cache of the room's set; pressing a button fetches nothing.
//
// ## What that costs, said where the controls are
//
// A listener receives a clip as part of the sender's voice. So **the volume here is the
// sender's**: it sets how loud your clips are for everyone, you included. A listener cannot
// turn one person's clips down without turning that person down, and "soundboard off" on
// this device stops you playing clips and previews — it cannot silence clips other people
// mix into their own microphones. Doing that would need each clip on a separate track,
// which costs a renegotiation per call in the mesh; recorded in docs/13-customisation.md.

const CairnSoundboard = (() => {
    const $ = (id) => document.getElementById(id);
    const VOLUME_KEY = "cairn.soundboard.volume";
    const OFF_KEY = "cairn.soundboard.off";
    let hooks = { onError: () => {}, inCall: () => false, onPlayed: () => {} };
    let panel = null;
    let button = null;
    let ctx = null;
    const decoded = new Map();   // asset id -> AudioBuffer
    let limitMs = 5000;

    function stored(key, fallback) {
        try { const v = localStorage.getItem(key); return v === null ? fallback : JSON.parse(v); }
        catch (_) { return fallback; }
    }
    function store(key, value) {
        try { localStorage.setItem(key, JSON.stringify(value)); } catch (_) { /* a convenience */ }
    }
    const volume = () => Math.max(0, Math.min(1, Number(stored(VOLUME_KEY, 0.7))));
    const off = () => !!stored(OFF_KEY, false);

    function context() {
        if (!ctx) ctx = new AudioContext();
        if (ctx.state === "suspended") ctx.resume().catch(() => {});
        return ctx;
    }

    async function buffer(it) {
        if (decoded.has(it.id)) return decoded.get(it.id);
        const bytes = await CairnEmoji.bytes(it);
        const buf = await context().decodeAudioData(bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength));
        decoded.set(it.id, buf);
        return buf;
    }

    function playLocally(buf) {
        const c = context();
        const src = c.createBufferSource();
        src.buffer = buf;
        const g = c.createGain();
        g.gain.value = volume();
        src.connect(g).connect(c.destination);
        src.start();
        src.stop(c.currentTime + Math.min(buf.duration, limitMs / 1000));
    }

    // Play into the call: everyone hears it in this device's microphone track.
    async function play(it) {
        if (off()) throw new Error("The soundboard is off on this device.");
        if (!hooks.inCall()) throw new Error("Join a call to play a sound.");
        const buf = await buffer(it);
        await CairnCall.mixIntoMic(buf, { gain: volume(), maxSeconds: limitMs / 1000 });
        playLocally(buf);
        hooks.onPlayed(it);
    }

    // Hear a clip on this device only, from the Customise panel.
    async function preview(it) {
        if (off()) throw new Error("The soundboard is off on this device.");
        playLocally(await buffer(it));
    }

    function build() {
        panel = document.createElement("div");
        panel.id = "soundboard";
        panel.className = "sb";
        panel.hidden = true;
        panel.setAttribute("role", "dialog");
        panel.setAttribute("aria-label", "Soundboard");
        panel.innerHTML = `
          <div class="sb-head"><span class="sb-title">Soundboard</span></div>
          <div class="sb-grid" id="sb-grid"></div>
          <div class="sb-settings">
            <label class="sb-volume">Your clips' volume
              <input type="range" id="sb-volume" min="0" max="100" step="1"></label>
            <label class="toggle"><input type="checkbox" id="sb-off"> Soundboard off on this device</label>
            <p class="note">Clips are mixed into your microphone, so everyone in the call hears
              them at this volume. Listeners cannot turn your clips down apart from your voice,
              and turning the soundboard off here does not silence other people's.</p>
          </div>`;
        document.body.append(panel);
        const slider = $("sb-volume");
        slider.value = String(Math.round(volume() * 100));
        slider.addEventListener("input", () => store(VOLUME_KEY, Number(slider.value) / 100));
        const toggle = $("sb-off");
        toggle.checked = off();
        toggle.addEventListener("change", () => { store(OFF_KEY, toggle.checked); draw(); });
        document.addEventListener("pointerdown", (e) => {
            if (!panel.hidden && !panel.contains(e.target) && !button.contains(e.target)) close();
        });
        document.addEventListener("keydown", (e) => { if (e.key === "Escape") close(); });
        CairnEmoji.onChange(() => {
            decoded.clear();
            if (!panel.hidden) draw();
            sync();
        });
    }

    function draw() {
        const grid = $("sb-grid");
        grid.textContent = "";
        const sounds = CairnEmoji.items("sound");
        for (const it of sounds) {
            const b = document.createElement("button");
            b.type = "button";
            b.className = "sb-clip";
            b.textContent = it.name.replace(/_/g, " ");
            b.title = ":" + it.name + ":";
            b.disabled = !it.ready || off();
            b.addEventListener("click", async () => {
                b.classList.add("playing");
                try { await play(it); } catch (e) { hooks.onError(e); }
                setTimeout(() => b.classList.remove("playing"), 600);
            });
            grid.append(b);
        }
        if (!sounds.length) {
            const p = document.createElement("p");
            p.className = "sb-empty";
            p.textContent = "This room has no sounds yet.";
            grid.append(p);
        }
    }

    function place() {
        const a = button.getBoundingClientRect();
        const w = Math.min(320, window.innerWidth - 16);
        panel.style.width = w + "px";
        panel.style.left = Math.max(8, Math.min(window.innerWidth - w - 8, a.left)) + "px";
        // Above the call bar when it fits, below it when it does not: the stage can sit near
        // the top of a short window.
        const h = panel.offsetHeight;
        const above = a.top - h - 6;
        panel.style.top = (above >= 8 ? above : Math.min(window.innerHeight - h - 8, a.bottom + 6)) + "px";
    }

    function open() {
        if (!panel) build();
        draw();
        panel.hidden = false;
        place();
        button.classList.add("on");
    }

    function close() {
        if (panel) panel.hidden = true;
        if (button) button.classList.remove("on");
    }

    // The button only exists in a call's control bar, and only when the room has sounds.
    function sync() {
        if (button) button.hidden = CairnEmoji.items("sound").length === 0;
    }

    // `bar` is the call's control bar; the button goes in before its spacer, kept apart from
    // whatever else call work puts there.
    function bind(h) {
        hooks = { ...hooks, ...h };
        if (h.limitMs) limitMs = h.limitMs;
        if (!h.bar) return;
        button = document.createElement("button");
        button.type = "button";
        button.id = "soundboard-btn";
        button.className = "icon";
        button.title = "Soundboard";
        button.setAttribute("aria-label", "Soundboard");
        button.innerHTML = '<svg width="15" height="15" aria-hidden="true"><use href="#i-sound"/></svg> <span>Sounds</span>';
        button.addEventListener("click", () => (panel && !panel.hidden ? close() : open()));
        const spacer = h.bar.querySelector(".grow");
        h.bar.insertBefore(button, spacer || null);
        if (!panel) build();
        sync();
    }

    return { bind, play, preview, open, close, volume, off };
})();
