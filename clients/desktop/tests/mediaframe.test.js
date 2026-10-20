// ui/mediaframe.js against the Rust reference, crates/cairn-crypto/src/media.rs.
//
// The two must agree byte for byte: a frame sealed in one client's webview is opened by
// another's, and the browser test additionally opens what the SFU held with the Rust code.
// This pins the format without a browser: Node's WebCrypto is the same API.
//
// Run: node --test clients/desktop/tests/mediaframe.test.js

const test = require("node:test");
const assert = require("node:assert");
const CairnFrame = require("../ui/mediaframe.js");

// `the_cross_language_vector` in media.rs.
const KEY = Buffer.from("0123456789abcdef");
const IV = Buffer.from("iv-iv-iv-iv-");
const SEALED = "e126fc7fb205e7918fdcf4dda551589a464b8df80e332b72e3f9b3" +
    "69762d69762d69762d69762d0102030400000005c1";

test("sealing matches the Rust vector exactly", async () => {
    const key = await CairnFrame.importKey(KEY);
    const out = await CairnFrame.seal(key, 0x01020304, 5, 1, Buffer.from("hello opus"), IV);
    assert.strictEqual(Buffer.from(out).toString("hex"), SEALED);
});

test("the Rust vector opens, with its flags and its key id", async () => {
    const key = await CairnFrame.importKey(KEY);
    const sealed = Buffer.from(SEALED, "hex");
    assert.deepStrictEqual(CairnFrame.peek(sealed), { epoch: 0x01020304, leaf: 5 });
    const opened = await CairnFrame.open(key, sealed);
    assert.strictEqual(opened.flags, 1);
    assert.strictEqual(Buffer.from(opened.data).toString(), "hello opus");
});

test("a frame does not open under another sender's key, or once altered", async () => {
    const other = await CairnFrame.importKey(Buffer.from("fedcba9876543210"));
    assert.strictEqual(await CairnFrame.open(other, Buffer.from(SEALED, "hex")), null);
    const key = await CairnFrame.importKey(KEY);
    const bent = Buffer.from(SEALED, "hex");
    bent[30] ^= 1;
    assert.strictEqual(await CairnFrame.open(key, bent), null);
});

// The transformer's rules, which decide what leaves the device and what is played.
function run(side, ctx, data) {
    const out = [];
    const frame = { data };
    return CairnFrame.transformer(side, { count: () => {}, opened: () => {}, flags: () => 0, ...ctx })(
        frame, { enqueue: (f) => out.push(f) }).then(() => out);
}

test("in an end-to-end call nothing leaves unsealed, even without a key yet", async () => {
    const out = await run("send", { mode: () => "e2ee", sealing: () => null }, Uint8Array.from(Buffer.from("audio")).buffer);
    assert.strictEqual(out.length, 0, "a sender with no key must drop, never send in the clear");
});

test("in an end-to-end call plaintext from the SFU is not played", async () => {
    const out = await run("receive", { mode: () => "e2ee", keyFor: () => null }, Uint8Array.from(Buffer.from("injected by the sfu")).buffer);
    assert.strictEqual(out.length, 0);
});

test("in a transport-only call plaintext is passed, and sealed frames still open", async () => {
    const plain = await run("receive", { mode: () => "transport", keyFor: () => null }, Uint8Array.from(Buffer.from("opus")).buffer);
    assert.strictEqual(plain.length, 1);
    const key = await CairnFrame.importKey(KEY);
    const sealed = await run("receive", { mode: () => "transport", keyFor: () => key }, Uint8Array.from(Buffer.from(SEALED, "hex")).buffer);
    assert.strictEqual(Buffer.from(sealed[0].data).toString(), "hello opus");
});

// A codec frame is arbitrary bytes, so about one plaintext frame in 256 ends in the version
// byte and is long enough to look sealed. In a fallback call it must still be played; found
// when the SFU browser test counted one such frame as "sealed" on a CI runner.
test("in a transport-only call plaintext that merely looks sealed is still played", async () => {
    const lookalike = Buffer.alloc(60, 0x5a);
    lookalike[lookalike.length - 1] = CairnFrame.VERSION;
    assert.ok(CairnFrame.peek(lookalike), "the lookalike does parse as a sealed frame");
    const key = await CairnFrame.importKey(KEY);
    for (const keyFor of [() => null, () => key]) {
        const out = await run("receive", { mode: () => "transport", keyFor }, Uint8Array.from(lookalike).buffer);
        assert.strictEqual(out.length, 1, "a plaintext frame in a fallback call is not dropped");
    }
    const e2ee = await run("receive", { mode: () => "e2ee", keyFor: () => key }, Uint8Array.from(lookalike).buffer);
    assert.strictEqual(e2ee.length, 0, "in an end-to-end call a frame that does not open is still dropped");
});
