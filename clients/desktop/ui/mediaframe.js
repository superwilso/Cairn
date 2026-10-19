// Sealing and opening voice frames — the JavaScript half of `cairn_crypto::media`.
//
// ## What this file may and may not do
//
// It applies a decision; it never makes one. Which key seals this device's frames, which
// keys open everyone else's, and whether the call is end to end at all are decided in
// `cairn-client-core` (`Session::voice_keys`, `Session::voice_state`) and handed in. The keys
// arrive once per MLS epoch as raw bytes, are imported here as **non-extractable** CryptoKeys,
// and the bytes are dropped. See docs/adr/012-sfu-voice-channels.md for why that, and not "the
// webview never sees a key", is the honest statement of the line.
//
// ## Format (must match crates/cairn-crypto/src/media.rs byte for byte)
//
//   AES-128-GCM(key, iv, aad = trailer, flags ‖ codec frame) ‖ iv(12) ‖ epoch(u32 BE) ‖ leaf(u32 BE) ‖ 0xC1
//
// `clients/desktop/tests/mediaframe.test.js` checks this file against the Rust vector.
//
// Loaded three ways: as a classic script in the page, by importScripts in the transform
// worker, and by require() in Node for the vector test. Hence the plain global.

/* eslint-env browser, worker */

const CairnFrame = (() => {
    const VERSION = 0xC1;
    const TRAILER = 12 + 4 + 4 + 1;
    const TAG = 16;
    const subtle = () => globalThis.crypto.subtle;

    async function importKey(raw) {
        return subtle().importKey("raw", raw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
    }

    function peek(buf) {
        const b = new Uint8Array(buf);
        if (b.length < TAG + TRAILER + 1 || b[b.length - 1] !== VERSION) return null;
        const v = new DataView(b.buffer, b.byteOffset + b.length - TRAILER, TRAILER);
        return { epoch: v.getUint32(12), leaf: v.getUint32(16) };
    }

    async function seal(key, epoch, leaf, flags, frame, iv) {
        const trailer = new Uint8Array(TRAILER);
        trailer.set(iv || globalThis.crypto.getRandomValues(new Uint8Array(12)), 0);
        const v = new DataView(trailer.buffer);
        v.setUint32(12, epoch >>> 0);
        v.setUint32(16, leaf >>> 0);
        trailer[20] = VERSION;
        const plain = new Uint8Array(1 + frame.byteLength);
        plain[0] = flags & 0xff;
        plain.set(new Uint8Array(frame), 1);
        const ct = new Uint8Array(await subtle().encrypt(
            { name: "AES-GCM", iv: trailer.subarray(0, 12), additionalData: trailer, tagLength: 128 },
            key, plain));
        const out = new Uint8Array(ct.length + TRAILER);
        out.set(ct, 0);
        out.set(trailer, ct.length);
        return out.buffer;
    }

    // { flags, data } or null. Null covers every failure alike: wrong key, altered bytes,
    // not a frame at all.
    async function open(key, buf) {
        const b = new Uint8Array(buf);
        if (!peek(b)) return null;
        const trailer = b.subarray(b.length - TRAILER);
        try {
            const plain = new Uint8Array(await subtle().decrypt(
                { name: "AES-GCM", iv: trailer.subarray(0, 12), additionalData: trailer, tagLength: 128 },
                key, b.subarray(0, b.length - TRAILER)));
            if (!plain.length) return null;
            return { flags: plain[0], data: plain.slice(1).buffer };
        } catch (_) {
            return null;
        }
    }

    // The transform for one sender or receiver. `ctx` is supplied by whoever runs it (the
    // page, or the worker) and answers from the state Rust last handed over:
    //
    //   ctx.mode()            "e2ee" | "transport"
    //   ctx.sealing()         { key, epoch, leaf } for this device, or null
    //   ctx.keyFor(e, leaf)   CryptoKey or null
    //   ctx.flags()           mute/deafen bits for outgoing frames
    //   ctx.opened(leaf, f)   a frame from `leaf` opened, carrying flags `f`
    //   ctx.count(what)       statistics: sealed, opened, passed, dropped
    //
    // **In an end-to-end call nothing unsealed goes out and nothing that fails to open is
    // played.** A sender without a key drops the frame rather than sending it in the clear;
    // a receiver drops plaintext, which is what a frame injected by the SFU looks like.
    function transformer(side, ctx) {
        return async (frame, controller) => {
            if (side === "send") {
                if (ctx.mode() !== "e2ee") { ctx.count("passed"); controller.enqueue(frame); return; }
                const s = ctx.sealing();
                if (!s) { ctx.count("dropped"); return; }
                frame.data = await seal(s.key, s.epoch, s.leaf, ctx.flags(), frame.data);
                ctx.count("sealed");
                controller.enqueue(frame);
                return;
            }
            const id = peek(frame.data);
            const key = id && ctx.keyFor(id.epoch, id.leaf);
            if (key) {
                const opened = await open(key, frame.data);
                if (opened) {
                    frame.data = opened.data;
                    ctx.count("opened");
                    ctx.opened(id.leaf, opened.flags);
                    controller.enqueue(frame);
                    return;
                }
            }
            // A fallback call carries plaintext from whoever cannot seal.
            if (ctx.mode() !== "e2ee" && !id) { ctx.count("passed"); controller.enqueue(frame); return; }
            ctx.count("dropped");
        };
    }

    // Bit 2 of the sealed flags byte: a soundboard frame, not a voice (media.rs FLAG_SOUNDBOARD).
    const FLAG_SOUNDBOARD = 0x04;

    return { VERSION, TRAILER, FLAG_SOUNDBOARD, importKey, peek, seal, open, transformer };
})();

if (typeof module !== "undefined") module.exports = CairnFrame;
