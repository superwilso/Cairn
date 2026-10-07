// Attachments: photos and files. Presentation only.
//
// Sealing, the key, the size ceiling, the safe filename and — most importantly — whether a
// sender's "this is an image" is believed are all decided in Rust
// (cairn_client_core::session::attachments). This file is handed an `attachment` view with a
// `kind` already chosen and draws it. It never sees a key: it asks for an attachment's bytes
// by id, and Rust answers only for attachments that arrived in the open room.
//
// `send` takes bytes, a name and a type and nothing else, so anything that produces a file —
// the picker, a drop, a paste, a recorder — goes through the same path.

const CairnAttach = (() => {
    let invoke = null;
    let onError = () => {};
    let onNotice = () => {};
    let maxBytes = null;
    // Object URLs pin their bytes in memory until revoked. A room's are revoked when the
    // timeline is cleared, which is the only point at which nothing can still be showing them.
    const urls = new Set();

    function bind(opts) {
        invoke = opts.invoke;
        onError = opts.onError || onError;
        onNotice = opts.onNotice || onNotice;
    }

    async function limit() {
        if (maxBytes === null) {
            try { maxBytes = (await invoke("attachment_limits")).max_bytes; } catch (_) { /* Rust still refuses */ }
        }
        return maxBytes;
    }

    function humanSize(n) {
        if (n >= 1024 * 1024) return (n / (1024 * 1024)).toFixed(1) + " MiB";
        if (n >= 1024) return (n / 1024).toFixed(1) + " KiB";
        return n + " bytes";
    }

    // HTTP header values are ASCII, and a filename is not. JSON's own \u escapes keep the
    // header ASCII and decode back to the exact name on the Rust side — percent-encoding
    // would need a second decoder there for no gain.
    function header(name, mime) {
        return JSON.stringify({ name, mime }).replace(
            /[\u007f-￿]/g,
            (c) => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0"),
        );
    }

    // Raw bytes arrive as an ArrayBuffer over Tauri's ipc: protocol and as an array of
    // numbers over its postMessage fallback. Both are the same bytes.
    function bytesOf(raw) {
        return raw instanceof ArrayBuffer ? new Uint8Array(raw) : Uint8Array.from(raw);
    }

    /// Send bytes as a file to the open room. Resolves to the message view to show.
    async function sendBytes(bytes, name, mime) {
        const max = await limit();
        if (max !== null && bytes.length > max) {
            throw `${name} is ${humanSize(bytes.length)} — attachments are limited to ${humanSize(max)}`;
        }
        // The raw IPC body, not { bytes: [...] }: a JSON array of numbers makes a 25 MiB
        // photo roughly 100 MB of text.
        return invoke("send_file", bytes, {
            headers: { "x-cairn-file": header(name, mime || "application/octet-stream") },
        });
    }

    async function send(file) {
        const max = await limit();
        // Checked before reading, so a 2 GB video is refused without being pulled into memory.
        if (max !== null && file.size > max) {
            throw `${file.name} is ${humanSize(file.size)} — attachments are limited to ${humanSize(max)}`;
        }
        const bytes = new Uint8Array(await file.arrayBuffer());
        return sendBytes(bytes, file.name || "file", file.type);
    }

    async function objectUrl(att) {
        const bytes = bytesOf(await invoke("fetch_attachment", { id: att.id }));
        // The type is Rust's normalised one, and only reaches a Blob for kinds Rust chose to
        // show inline. A "file" never becomes a URL the webview could navigate to.
        const url = URL.createObjectURL(new Blob([bytes], { type: att.mime }));
        urls.add(url);
        return url;
    }

    async function save(att) {
        try {
            const where = await invoke("save_attachment", { id: att.id });
            onNotice("Saved " + att.name + " to " + where);
        } catch (e) { onError(e); }
    }

    function caption(att) {
        const row = document.createElement("div");
        row.className = "attach-caption";
        const name = document.createElement("span");
        name.className = "attach-name";
        // textContent: the name is the sender's and is attacker-controlled text.
        name.textContent = att.name;
        name.title = att.name;
        const size = document.createElement("span");
        size.className = "attach-size";
        size.textContent = humanSize(att.size);
        const btn = document.createElement("button");
        btn.type = "button";
        btn.className = "ghost attach-save";
        btn.textContent = "Save";
        btn.title = "Save to Downloads";
        btn.onclick = () => save(att);
        row.append(name, size, btn);
        return row;
    }

    function failed(box, e) {
        const p = document.createElement("span");
        p.className = "attach-failed";
        p.textContent = "Could not open: " + e;
        box.prepend(p);
    }

    /// Draw an attachment view. Bytes for images and audio are fetched after the element is
    /// in place, so a slow fetch never holds up the rest of the timeline.
    function render(att) {
        const box = document.createElement("div");
        box.className = "attach attach-" + att.kind;
        box.dataset.id = att.id;
        if (att.kind === "image") {
            const img = document.createElement("img");
            img.alt = att.name;
            box.append(img, caption(att));
            objectUrl(att).then((url) => { img.src = url; }, (e) => { img.remove(); failed(box, e); });
        } else if (att.kind === "audio") {
            const audio = document.createElement("audio");
            audio.controls = true;
            audio.preload = "metadata";
            box.append(audio, caption(att));
            objectUrl(att).then((url) => { audio.src = url; }, (e) => { audio.remove(); failed(box, e); });
        } else {
            box.append(caption(att));
        }
        return box;
    }

    function reset() {
        for (const u of urls) URL.revokeObjectURL(u);
        urls.clear();
    }

    return { bind, send, sendBytes, render, reset, header, bytesOf, humanSize };
})();
