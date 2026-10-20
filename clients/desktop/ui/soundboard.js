// The soundboard: a room's short clips, played into a call.
//
// ## How a clip reaches everyone
//
// On this device's **soundboard track** — a second audio track beside the microphone, in a
// rung call (`CairnCall.playClip`) or a voice channel (`CairnVoiceChannel.playClip`) — and
// played locally at the same level so the person pressing the button hears what they sent.
// There is no "play X" message. The clip's bytes come from this device's cache of the room's
// set; pressing a button fetches nothing.
//
// ## What listeners control, and what it costs
//
// Because clips are their own track, every listener can turn one person's soundboard down or
// off, or mute everyone's, on their own device (callaudio.js; the per-person popover and
// Settings → Voice & video). The volume here is the sender's: how loud your clips go out.
//
// The cost, said in docs/13-customisation.md and in the panel below: whoever carries the
// media can tell when a clip is playing, from the soundboard track's activity and timing —
// the instance's SFU in a voice channel, a TURN relay in a rung call. Not which clip: in an
// end-to-end call the audio is sealed like the voice.

const CairnSoundboard = (() => {
    const $ = (id) => document.getElementById(id);
    const VOLUME_KEY = "cairn.soundboard.volume";
    const OFF_KEY = "cairn.soundboard.off";
    let hooks = { onError: () => {}, inCall: () => false, onPlayed: () => {} };
    let panel = null;
    let button = null;          // the call bar's button
    let anchor = null;          // whichever button opened the panel
    const extra = [];           // further buttons, e.g. in the voice-channel panel
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

    // Play into the call this device is in, on its soundboard track.
    async function play(it) {
        if (off()) throw new Error("The soundboard is off on this device.");
        if (!hooks.inCall()) throw new Error("Join a call to play a sound.");
        const buf = await buffer(it);
        const call = typeof CairnVoiceChannel !== "undefined" && CairnVoiceChannel.session
            ? CairnVoiceChannel : CairnCall;
        await call.playClip(buf, { gain: volume(), maxSeconds: limitMs / 1000 });
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
            <p class="note">How loud your clips go out. Each listener can also turn your clips
              down or off for themselves. Clips travel as their own stream, so the server
              carrying the call can tell when one is playing, though not what it is.</p>
          </div>`;
        document.body.append(panel);
        const slider = $("sb-volume");
        slider.value = String(Math.round(volume() * 100));
        slider.addEventListener("input", () => store(VOLUME_KEY, Number(slider.value) / 100));
        const toggle = $("sb-off");
        toggle.checked = off();
        toggle.addEventListener("change", () => { store(OFF_KEY, toggle.checked); draw(); });
        document.addEventListener("pointerdown", (e) => {
            const onButton = [button, ...extra].some((b) => b && b.contains(e.target));
            if (!panel.hidden && !panel.contains(e.target) && !onButton) close();
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
        const a = (anchor || button).getBoundingClientRect();
        const w = Math.min(320, window.innerWidth - 16);
        panel.style.width = w + "px";
        panel.style.left = Math.max(8, Math.min(window.innerWidth - w - 8, a.left)) + "px";
        // Above the call bar when it fits, below it when it does not: the stage can sit near
        // the top of a short window.
        const h = panel.offsetHeight;
        const above = a.top - h - 6;
        panel.style.top = (above >= 8 ? above : Math.min(window.innerHeight - h - 8, a.bottom + 6)) + "px";
    }

    function open(from) {
        if (!panel) build();
        anchor = from || button;
        draw();
        panel.hidden = false;
        place();
        if (anchor) anchor.classList.add("on");
    }

    function close() {
        if (panel) panel.hidden = true;
        for (const b of [button, ...extra]) if (b) b.classList.remove("on");
    }

    // The button only exists in a call's control bar, and only when the room has sounds.
    function sync() {
        const none = CairnEmoji.items("sound").length === 0;
        for (const b of [button, ...extra]) if (b) b.hidden = none;
    }

    function makeButton(id) {
        const b = document.createElement("button");
        b.type = "button";
        b.id = id;
        b.className = "icon";
        b.title = "Soundboard";
        b.setAttribute("aria-label", "Soundboard");
        b.innerHTML = '<svg width="15" height="15" aria-hidden="true"><use href="#i-sound"/></svg> <span>Sounds</span>';
        b.addEventListener("click", () => (panel && !panel.hidden && anchor === b ? close() : open(b)));
        return b;
    }

    // A second way in, for the voice channel's controls: the same panel, opened beside it.
    function addButton(container) {
        if (!container) return;
        const b = makeButton("soundboard-btn-" + (extra.length + 1));
        extra.push(b);
        container.append(b);
        if (!panel) build();
        sync();
    }

    // `bar` is the call's control bar; the button goes in before its spacer, kept apart from
    // whatever else call work puts there.
    function bind(h) {
        hooks = { ...hooks, ...h };
        if (h.limitMs) limitMs = h.limitMs;
        if (!h.bar) return;
        button = makeButton("soundboard-btn");
        const spacer = h.bar.querySelector(".grow");
        h.bar.insertBefore(button, spacer || null);
        if (!panel) build();
        sync();
    }

    return { bind, addButton, play, preview, open, close, volume, off };
})();
