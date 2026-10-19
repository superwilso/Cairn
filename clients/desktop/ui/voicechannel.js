// Cairn voice channels — one WebRTC connection to the instance's SFU.
//
// ## How this differs from call.js
//
// call.js is a mesh: peers connect to each other, signalling rides the encrypted body, and
// media never touches the instance. Here there is one peer connection, to the SFU, and the
// SFU is the far end of DTLS-SRTP — it holds every RTP payload. In an end-to-end encrypted
// room those payloads are frames this file seals with keys from Rust before they leave, so
// what the SFU holds is ciphertext. docs/adr/012-sfu-voice-channels.md is the design.
//
// ## What this file decides: nothing protocol-shaped
//
// Whether the call is end to end, and with which keys, comes from `voice_state` and
// `voice_keys`. This applies them. The only judgement made here is the honest one only the
// webview can make — "can I transform frames at all?" — and it is reported to Rust, which
// announces it to the room.
//
// ## No renegotiation
//
// The first offer carries one sendonly audio track and SLOTS recvonly ones. The SFU fills a
// slot when somebody first speaks. Nothing is ever added later, so there is no glare and no
// second offer — the same reasoning as call.js's empty video line.

/* eslint-env browser */

const CairnVoiceChannel = (() => {
    const SLOTS = 15;                 // MAX_VOICE_PARTICIPANTS - 1, see state.rs
    const KEEP_OLD_EPOCH_MS = 10_000; // senders cross an epoch at slightly different moments
    const REFRESH_MS = 1000;

    const invoke = (cmd, args) => window.__TAURI__.core.invoke(cmd, args);

    let pc = null;
    let local = null;
    let worker = null;
    let path = "none";                // "script" | "legacy" | "none"
    let session = null;
    let timer = null;
    let state = null;                 // last voice_state
    let epoch = null;
    let keyTable = new Map();         // "epoch:leaf" -> CryptoKey
    let leafInfo = new Map();         // leaf -> { user, device }
    let sealing = null;
    const old = [];                   // [{ until, keys: Map }]
    const mic = { muted: false, deafened: false };
    const heard = new Map();          // slot index -> { leaf, flags, at }
    const audio = new Map();          // slot index -> HTMLAudioElement
    const stats = { sealed: 0, opened: 0, passed: 0, dropped: 0 };
    const slotMid = [];               // slot index -> mid, once negotiated
    let prefs = { leaveOnFallback: false };

    let ui = {
        onState: () => {},            // (voice_state) on every refresh
        onProtection: () => {},       // (before, after, fallbackBy) when it changes
        onNotice: () => {},           // (text)
        onEnd: () => {},
        onHeard: () => {},            // (slotIndex, {user, device, muted, deafened})
    };

    // The webview's honest capability. Chromium (WebView2) has both; WebKit has the
    // standard one. A webview with neither cannot seal, and says so.
    function capability() {
        if (typeof RTCRtpScriptTransform === "function") return "script";
        if (typeof RTCRtpSender !== "undefined" &&
            typeof RTCRtpSender.prototype.createEncodedStreams === "function") return "legacy";
        return "none";
    }

    const mode = () => (state && state.protection === "e2ee" ? "e2ee" : "transport");
    const flags = () => (mic.muted || mic.deafened ? 1 : 0) | (mic.deafened ? 2 : 0);

    function keyFor(e, leaf) {
        const k = keyTable.get(e + ":" + leaf);
        if (k) return k;
        for (const o of old) { const ok = o.keys.get(e + ":" + leaf); if (ok) return ok; }
        return null;
    }

    function allKeys() {
        const m = new Map();
        for (const o of old) for (const [k, v] of o.keys) m.set(k, v);
        for (const [k, v] of keyTable) m.set(k, v);
        return m;
    }

    function pushToWorker() {
        if (!worker) return;
        worker.postMessage({ type: "state", mode: mode(), sealing, keys: allKeys(), flags: flags() });
    }

    // New keys only when the epoch moved. The raw bytes from Rust are imported as
    // non-extractable and go out of scope here; nothing else in the page holds them.
    async function loadKeys() {
        let view;
        try { view = await invoke("voice_keys"); } catch (_) { return; }
        if (view.epoch === epoch && sealing) return;
        if (keyTable.size) old.push({ until: Date.now() + KEEP_OLD_EPOCH_MS, keys: keyTable });
        const fresh = new Map();
        leafInfo = new Map();
        for (const k of view.keys) {
            const raw = Uint8Array.from(atob(k.key), (c) => c.charCodeAt(0));
            fresh.set(view.epoch + ":" + k.leaf, await CairnFrame.importKey(raw));
            raw.fill(0);
            leafInfo.set(k.leaf, { user: k.user, device: k.device });
        }
        keyTable = fresh;
        epoch = view.epoch;
        const mine = fresh.get(view.epoch + ":" + view.me_leaf);
        sealing = mine ? { key: mine, epoch: view.epoch, leaf: view.me_leaf } : null;
    }

    async function refresh() {
        if (!session) return;
        let next;
        try { next = await invoke("voice_state"); } catch (e) { ui.onNotice("Voice channel: " + e); return; }
        const before = state && state.protection;
        state = next;
        while (old.length && old[0].until < Date.now()) old.shift();
        if (next.protection !== "transport_room") await loadKeys();
        pushToWorker();
        if (before && before !== next.protection) {
            ui.onProtection(before, next.protection, next.fallback_by || []);
            if (prefs.leaveOnFallback && next.protection === "transport_only") {
                ui.onNotice("Left the voice channel: it stopped being end-to-end encrypted.");
                await leave();
                return;
            }
        }
        if (!next.joined) {           // evicted — removed from the room, or the seat lapsed
            ui.onNotice("You are no longer in the voice channel.");
            await leave();
            return;
        }
        ui.onState(next);
    }

    function attachTransform(target, side, index) {
        if (path === "script") {
            target.transform = new RTCRtpScriptTransform(worker, { side, index });
            return;
        }
        if (path !== "legacy") return;
        const { readable, writable } = target.createEncodedStreams();
        const run = CairnFrame.transformer(side, {
            mode, sealing: () => sealing, keyFor, flags,
            count: (w) => { stats[w]++; },
            opened: (leaf, f) => noteHeard(index, leaf, f),
        });
        readable.pipeThrough(new TransformStream({ transform: run })).pipeTo(writable).catch(() => {});
    }

    function noteHeard(index, leaf, f) {
        const who = leafInfo.get(leaf);
        heard.set(index, { leaf, flags: f, at: Date.now() });
        if (who) ui.onHeard(index, { ...who, muted: !!(f & 1), deafened: !!(f & 2) });
    }

    function waitForIce(peer) {
        if (peer.iceGatheringState === "complete") return Promise.resolve();
        return new Promise((resolve) => {
            const done = () => { if (peer.iceGatheringState === "complete") resolve(); };
            peer.addEventListener("icegatheringstatechange", done);
            setTimeout(resolve, 3000);
        });
    }

    // `simulateNoTransforms` behaves exactly as a webview without encoded transforms does;
    // the browser test uses it to exercise the §5 fallback with a real Chromium.
    async function join({ deviceId, simulateNoTransforms = false } = {}) {
        if (pc) await leave();
        path = simulateNoTransforms ? "none" : capability();
        local = await navigator.mediaDevices.getUserMedia({
            audio: deviceId ? { deviceId: { exact: deviceId } } : true, video: false,
        });
        pc = new RTCPeerConnection(path === "legacy" ? { encodedInsertableStreams: true } : {});
        if (path === "script") {
            worker = new Worker("mediaframe-worker.js");
            worker.onmessage = (ev) => {
                const m = ev.data || {};
                if (m.type === "heard") noteHeard(m.index, m.leaf, m.flags);
                if (m.type === "stats") Object.assign(stats, m.stats);
            };
        }
        const send = pc.addTransceiver(local.getAudioTracks()[0], { direction: "sendonly", streams: [local] });
        attachTransform(send.sender, "send", -1);
        const recv = [];
        for (let i = 0; i < SLOTS; i++) {
            const t = pc.addTransceiver("audio", { direction: "recvonly" });
            attachTransform(t.receiver, "receive", i);
            recv.push(t);
        }
        pc.ontrack = (ev) => {
            const index = recv.findIndex((t) => t.receiver === ev.receiver);
            if (index < 0) return;
            const el = audio.get(index) || new Audio();
            el.autoplay = true;
            el.srcObject = new MediaStream([ev.track]);
            el.muted = mic.deafened;
            audio.set(index, el);
            if (typeof CairnCall !== "undefined" && CairnCall.applySpeaker) CairnCall.applySpeaker(el);
            el.play().catch(() => {});
        };
        pc.onconnectionstatechange = () => {
            if (pc && pc.connectionState === "failed") {
                ui.onNotice("Could not reach the voice server. Its UDP port may be blocked on this network.");
            }
        };

        await pc.setLocalDescription(await pc.createOffer());
        await waitForIce(pc);
        let joined;
        try {
            joined = await invoke("voice_join", { offer: pc.localDescription.sdp, e2ee: path !== "none" });
        } catch (e) {
            await teardown();
            throw e;
        }
        session = joined.session;
        await pc.setRemoteDescription({ type: "answer", sdp: joined.answer });
        recv.forEach((t, i) => { slotMid[i] = t.mid; });
        // Before the first refresh nothing is decided, and the default is the safe one: the
        // worker starts in "e2ee" with no sealing key, so nothing leaves unsealed.
        await refresh();
        timer = setInterval(refresh, REFRESH_MS);
        return { session, path };
    }

    async function teardown() {
        clearInterval(timer);
        timer = null;
        if (pc) { try { pc.close(); } catch (_) {} }
        if (local) local.getTracks().forEach((t) => t.stop());
        if (worker) worker.terminate();
        for (const el of audio.values()) { el.srcObject = null; }
        audio.clear();
        heard.clear();
        pc = null; local = null; worker = null; session = null; state = null;
        keyTable = new Map(); old.length = 0; sealing = null; epoch = null;
    }

    async function leave() {
        if (!pc && !session) return;
        try { await invoke("voice_leave"); } catch (_) {}
        await teardown();
        ui.onEnd();
    }

    function setMuted(m) {
        mic.muted = !!m;
        if (local) local.getAudioTracks().forEach((t) => { t.enabled = !mic.muted && !mic.deafened; });
        pushToWorker();
    }

    function setDeafened(d) {
        mic.deafened = !!d;
        for (const el of audio.values()) el.muted = mic.deafened;
        setMuted(mic.muted);
    }

    async function readStats() {
        if (worker) {
            await new Promise((resolve) => {
                const prev = worker.onmessage;
                worker.onmessage = (ev) => { prev(ev); if (ev.data && ev.data.type === "stats") { worker.onmessage = prev; resolve(); } };
                worker.postMessage({ type: "stats" });
                setTimeout(resolve, 500);
            });
        }
        return { ...stats };
    }

    // Who is on a slot: by the key their frames open under in an E2EE call; by the SFU's
    // claim (state.slots) only when the call is transport-only.
    function slotOwner(index) {
        const h = heard.get(index);
        if (h && leafInfo.has(h.leaf)) return { ...leafInfo.get(h.leaf), attested: true };
        if (state && mode() === "transport") {
            const s = (state.slots || []).find((x) => x.mid === slotMid[index]);
            if (s) return { user: s.user, device: s.device, attested: false };
        }
        return null;
    }

    return {
        join, leave, refresh, setMuted, setDeafened, readStats, slotOwner, capability,
        setPrefs(p) { prefs = { ...prefs, ...p }; },
        get session() { return session; },
        get state() { return state; },
        get path() { return path; },
        get muted() { return mic.muted; },
        get deafened() { return mic.deafened; },
        get audio() { return audio; },
        get pc() { return pc; },
        bind(handlers) { ui = { ...ui, ...handlers }; },
    };
})();
