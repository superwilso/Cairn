// The room's Customise panel: its custom emoji, stickers and soundboard clips.
//
// Presentation only. Who may change the set is decided twice in Rust — by this device before
// uploading, as a courtesy, and by every other member on receipt, which is the check that
// counts — so `can_edit` here only decides whether to draw the controls. Names are
// sanitised and file types sniffed from the bytes in Rust; the name prefilled here is a
// suggestion, and the limits shown are the numbers Rust handed over.
//
// The one check done here that Rust cannot do for every format: a clip's length, measured
// by decoding it. Rust measures WAV and Ogg itself; every client also cuts playback at the
// limit, so a longer MP3 that got past this still cannot play for longer.

const CairnCustomise = (() => {
    const $ = (id) => document.getElementById(id);
    let hooks = { invoke: (c, a, o) => window.__TAURI__.core.invoke(c, a, o), onError: () => {}, roomOpen: () => false };
    let limits = null;
    let tab = "emoji";
    let sheet = null;
    let busy = false;

    const KINDS = {
        emoji: { label: "Emoji", accept: "image/png,image/gif,image/webp", max: "emoji", bytes: "emoji_bytes" },
        sticker: { label: "Stickers", accept: "image/png,image/gif,image/webp", max: "stickers", bytes: "sticker_bytes" },
        sound: { label: "Sounds", accept: "audio/ogg,audio/opus,audio/mpeg,audio/wav,.ogg,.opus,.mp3,.wav", max: "sounds", bytes: "sound_bytes" },
    };

    const kib = (n) => (n >= 1048576 ? (n / 1048576).toFixed(1) + " MiB" : Math.ceil(n / 1024) + " KiB");

    // The same shape Rust produces, so the field shows what will be used. Rust decides.
    function suggest(filename) {
        const stem = filename.replace(/\.[a-z0-9]{1,4}$/i, "");
        return stem.toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, "").slice(0, 32);
    }

    function header(meta) {
        return JSON.stringify(meta).replace(/[\u007f-￿]/g, (c) => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0"));
    }

    function build() {
        sheet = document.createElement("div");
        sheet.id = "customise";
        sheet.className = "sheet";
        sheet.hidden = true;
        sheet.innerHTML = `
          <div class="panel" role="dialog" aria-modal="true" aria-labelledby="cz-title">
            <header>
              <h3 id="cz-title">Customise this room</h3>
              <span class="grow"></span>
              <button type="button" class="ghost" id="cz-close" title="Close (Esc)">Close</button>
            </header>
            <p class="how">Everyone in the room downloads the whole set as soon as it changes, so
              using an emoji, a sticker or a sound fetches nothing and tells your instance
              nothing. It stores them as encrypted files it cannot open, and never learns their
              names.</p>
            <div class="cz-tabs" role="tablist"></div>
            <div class="cz-list" id="cz-list"></div>
            <form class="cz-add" id="cz-add">
              <label>File <input type="file" id="cz-file"></label>
              <label>Name <input id="cz-name" placeholder="e.g. party_parrot" spellcheck="false" autocomplete="off" maxlength="40"></label>
              <button type="submit" class="primary" id="cz-submit">Add</button>
              <p class="note" id="cz-limit" style="grid-column: 1 / -1; margin: 0"></p>
            </form>
            <p class="cz-readonly" id="cz-readonly" hidden>Only this room's owner and moderators can
              change its emoji, stickers and sounds. Everyone else's devices ignore a change sent
              by anybody else.</p>
            <div class="cz-meter"><span id="cz-used"></span><span class="bar"><span id="cz-bar"></span></span></div>
            <p class="error" id="cz-error"></p>
          </div>`;
        document.body.append(sheet);
        sheet.addEventListener("click", (e) => { if (e.target === sheet) close(); });
        $("cz-close").addEventListener("click", close);
        $("cz-file").addEventListener("change", () => {
            const f = $("cz-file").files[0];
            if (f && !$("cz-name").value.trim()) $("cz-name").value = suggest(f.name);
        });
        $("cz-add").addEventListener("submit", (e) => { e.preventDefault(); add(); });
        document.addEventListener("keydown", (e) => { if (e.key === "Escape" && !sheet.hidden) close(); });
        CairnEmoji.onChange(() => { if (!sheet.hidden) draw(); });
    }

    function art(it) {
        const box = document.createElement("span");
        box.className = "cz-art";
        if (it.kind === "sound") {
            const b = document.createElement("button");
            b.type = "button";
            b.className = "cz-play";
            b.textContent = "▶";
            b.title = "Preview :" + it.name + ": on this device";
            b.disabled = !it.ready;
            b.addEventListener("click", () => CairnSoundboard.preview(it).catch(hooks.onError));
            box.append(b);
            return box;
        }
        const u = CairnEmoji.url(it.kind, it.name);
        if (u) {
            const img = document.createElement("img");
            img.src = u;
            img.alt = ":" + it.name + ":";
            box.append(img);
        } else {
            box.textContent = "…";
            box.title = "Downloading";
        }
        return box;
    }

    function draw() {
        const set = CairnEmoji.set;
        const tabs = sheet.querySelector(".cz-tabs");
        tabs.textContent = "";
        for (const [kind, k] of Object.entries(KINDS)) {
            const b = document.createElement("button");
            b.type = "button";
            b.className = "cz-tab ghost" + (kind === tab ? " on" : "");
            b.setAttribute("role", "tab");
            b.setAttribute("aria-selected", String(kind === tab));
            b.dataset.kind = kind;
            const n = document.createElement("span");
            n.className = "n";
            n.textContent = CairnEmoji.items(kind).length + "/" + (limits ? limits[k.max] : "");
            b.append(document.createTextNode(k.label), n);
            b.addEventListener("click", () => { tab = kind; draw(); });
            tabs.append(b);
        }

        const list = $("cz-list");
        list.textContent = "";
        const mine = CairnEmoji.items(tab);
        for (const it of mine) {
            const li = document.createElement("div");
            li.className = "cz-item " + it.kind;
            const name = document.createElement("span");
            name.className = "cz-name";
            name.textContent = ":" + it.name + ":";
            name.title = ":" + it.name + ": · " + kib(it.size);
            li.append(art(it), name);
            if (set.can_edit) {
                const rm = document.createElement("button");
                rm.type = "button";
                rm.className = "cz-remove";
                rm.textContent = "×";
                rm.title = "Remove :" + it.name + ":";
                rm.setAttribute("aria-label", "Remove " + it.name);
                rm.addEventListener("click", () => remove(it));
                li.append(rm);
            }
            list.append(li);
        }
        if (!mine.length) {
            const p = document.createElement("p");
            p.className = "cz-empty";
            p.textContent = "No " + KINDS[tab].label.toLowerCase() + " in this room yet.";
            list.append(p);
        }

        $("cz-add").hidden = !set.can_edit;
        $("cz-readonly").hidden = set.can_edit;
        $("cz-file").accept = KINDS[tab].accept;
        if (limits) {
            const per = kib(limits[KINDS[tab].bytes]);
            $("cz-limit").textContent = tab === "sound"
                ? "Ogg/Opus, MP3 or WAV, up to " + (limits.sound_ms / 1000) + " seconds and " + per + "."
                : "PNG, GIF or WebP, up to " + per + ". Animated GIFs and WebPs animate.";
            const used = Math.min(100, (100 * set.bytes) / limits.set_bytes);
            $("cz-used").textContent = kib(set.bytes) + " of " + kib(limits.set_bytes);
            $("cz-used").title = "Every member downloads the whole set, so it has a ceiling.";
            $("cz-bar").style.width = used.toFixed(1) + "%";
        }
    }

    async function seconds(file) {
        const ctx = new (window.OfflineAudioContext || window.webkitOfflineAudioContext)(1, 1, 44100);
        const buffer = await ctx.decodeAudioData(await file.arrayBuffer());
        return buffer.duration;
    }

    async function add() {
        if (busy) return;
        const file = $("cz-file").files[0];
        const err = $("cz-error");
        err.textContent = "";
        if (!file) { err.textContent = "Choose a file first."; return; }
        const max = limits && limits[KINDS[tab].bytes];
        if (max && file.size > max) { err.textContent = "That file is " + kib(file.size) + "; the limit is " + kib(max) + "."; return; }
        if (tab === "sound" && limits) {
            let s;
            try { s = await seconds(file); } catch (_) { err.textContent = "That file is not audio this device can play."; return; }
            if (s > limits.sound_ms / 1000 + 0.05) {
                err.textContent = "That clip is " + s.toFixed(1) + " seconds; sounds are limited to " + (limits.sound_ms / 1000) + ".";
                return;
            }
        }
        const name = $("cz-name").value.trim() || suggest(file.name);
        busy = true;
        $("cz-submit").disabled = true;
        $("cz-submit").textContent = "Adding…";
        try {
            const bytes = new Uint8Array(await file.arrayBuffer());
            const view = await hooks.invoke("custom_add", bytes, {
                headers: { "x-cairn-custom": header({ kind: tab, name }) },
            });
            $("cz-file").value = "";
            $("cz-name").value = "";
            await CairnEmoji.load(view);
        } catch (e) {
            err.textContent = String(e);
        } finally {
            busy = false;
            $("cz-submit").disabled = false;
            $("cz-submit").textContent = "Add";
        }
    }

    async function remove(it) {
        try {
            await CairnEmoji.load(await hooks.invoke("custom_remove", { kind: it.kind, name: it.name }));
        } catch (e) { $("cz-error").textContent = String(e); }
    }

    async function open() {
        if (!hooks.roomOpen()) return;
        if (!sheet) build();
        if (!limits) { try { limits = await hooks.invoke("custom_limits"); } catch (_) {} }
        // A member list is a role list in Rust; reading it first means `can_edit` is current.
        try { await hooks.invoke("members"); } catch (_) {}
        await CairnEmoji.load();
        $("cz-error").textContent = "";
        sheet.hidden = false;
        draw();
        sheet.querySelector(".cz-tab.on").focus();
    }

    function close() { if (sheet) sheet.hidden = true; }

    function bind(h) {
        hooks = { ...hooks, ...h };
        if (h.button) h.button.addEventListener("click", open);
        CairnEmoji.onChange((set) => { if (h.button) h.button.classList.toggle("has-set", set.items.length > 0); });
    }

    return { bind, open, close, suggest };
})();
