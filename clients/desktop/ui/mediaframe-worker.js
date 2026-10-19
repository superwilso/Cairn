// The encoded-transform worker for voice channels (RTCRtpScriptTransform).
//
// It holds the CryptoKeys the page imported — structured-cloned, still non-extractable —
// and the mode Rust decided, and runs CairnFrame's transformer on every frame. It decides
// nothing itself: the page posts it new state whenever `voice_state`/`voice_keys` change.

/* eslint-env worker */
importScripts("mediaframe.js");

const state = {
    mode: "e2ee",
    sealing: null,          // { key, epoch, leaf }
    keys: new Map(),        // "epoch:leaf" -> CryptoKey, current and previous epoch
    flags: 0,
    stats: { sealed: 0, opened: 0, passed: 0, dropped: 0 },
};
const lastReport = new Map();

onmessage = (ev) => {
    const m = ev.data || {};
    if (m.type === "state") {
        state.mode = m.mode;
        state.sealing = m.sealing;
        state.keys = m.keys;
        state.flags = m.flags;
    } else if (m.type === "stats") {
        postMessage({ type: "stats", stats: { ...state.stats } });
    }
};

onrtctransform = (ev) => {
    const t = ev.transformer;
    const { side, index, board } = t.options;
    const run = CairnFrame.transformer(side, {
        mode: () => state.mode,
        sealing: () => state.sealing,
        keyFor: (epoch, leaf) => state.keys.get(epoch + ":" + leaf) || null,
        // The soundboard sender marks its frames as such, inside the seal; the microphone
        // sender carries the mute bits.
        flags: () => (board ? CairnFrame.FLAG_SOUNDBOARD : state.flags),
        count: (what) => { state.stats[what]++; },
        // Who is on this receive slot, by the key their frame opened under — not by the
        // SFU's word. Reported a few times a second, not per frame.
        opened: (leaf, flags) => {
            const now = Date.now();
            if ((lastReport.get(index) || 0) + 250 > now) return;
            lastReport.set(index, now);
            postMessage({ type: "heard", index, leaf, flags });
        },
    });
    t.readable.pipeThrough(new TransformStream({ transform: run })).pipeTo(t.writable).catch(() => {});
};
