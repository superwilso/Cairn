// The GIF picker. Presentation only.
//
// Everything that matters is in Rust (cairn_client_core::gifs): searches tunnel through the
// user's own instance with TLS to the provider, adverts are dropped before results reach
// this file, and a chosen GIF is fetched, sealed and sent as an encrypted attachment. This
// file is handed opaque ids and asks for preview bytes by id. It never sees a provider URL,
// so nothing here can make the webview contact a provider — the CSP would refuse anyway.
//
// The placeholder ("Search KLIPY") and attribution ("Powered by GIPHY") are the providers'
// requirements and come from Rust with the provider list, so this file cannot forget them.

const CairnGifs = (() => {
    const DEBOUNCE_MS = 350;
    // Preview fetches in flight at once; matches the per-host connection pool in Rust.
    const PARALLEL = 4;

    let invoke = null;
    let onSent = () => {};
    let onError = () => {};
    let canSend = () => true;
    let button = null;
    let anchor = null;

    let panel = null;
    let providers = null;    // null until asked; [] means not configured here
    let current = null;      // the provider id shown
    let generation = 0;      // bumps on every search, so a stale answer is dropped
    let debounce = 0;
    const urls = new Set();

    function bytesOf(raw) {
        return raw instanceof ArrayBuffer ? new Uint8Array(raw) : Uint8Array.from(raw);
    }

    function el(tag, cls, text) {
        const e = document.createElement(tag);
        if (cls) e.className = cls;
        if (text !== undefined) e.textContent = text;
        return e;
    }

    function revoke() {
        for (const u of urls) URL.revokeObjectURL(u);
        urls.clear();
    }

    function build() {
        panel = el("div", "gif-picker");
        panel.id = "gif-picker";
        panel.hidden = true;
        panel.setAttribute("role", "dialog");
        panel.setAttribute("aria-label", "GIFs");
        panel.innerHTML =
            '<div class="gif-head">' +
            '  <div class="gif-tabs" role="tablist"></div>' +
            '  <input class="gif-search" type="search" spellcheck="false" autocomplete="off" aria-label="Search GIFs">' +
            '  <button type="button" class="ghost gif-close" title="Close (Esc)" aria-label="Close">&times;</button>' +
            "</div>" +
            '<div class="gif-body"><div class="gif-grid" role="list"></div><p class="gif-status"></p></div>' +
            '<div class="gif-foot"><span class="gif-privacy"></span><span class="gif-attribution"></span></div>';
        panel.querySelector(".gif-close").onclick = close;
        const input = panel.querySelector(".gif-search");
        input.addEventListener("input", () => {
            clearTimeout(debounce);
            debounce = setTimeout(() => search(input.value), DEBOUNCE_MS);
        });
        input.addEventListener("keydown", (ev) => {
            if (ev.key === "Enter") { clearTimeout(debounce); search(input.value); }
        });
        // On the document, not the panel: focus may still be on the GIF button, or on the
        // composer, while the provider list loads.
        document.addEventListener("keydown", (ev) => {
            if (ev.key === "Escape" && !panel.hidden) { ev.stopPropagation(); close(); }
        });
        document.body.append(panel);
        document.addEventListener("pointerdown", (ev) => {
            if (!panel.hidden && !panel.contains(ev.target) && !button.contains(ev.target)) close();
        });
        window.addEventListener("resize", place);
    }

    // Above the composer, aligned to it. Fixed positioning, so the timeline's scrolling and
    // whatever layout the composer has do not matter.
    function place() {
        if (!panel || panel.hidden) return;
        const r = anchor.getBoundingClientRect();
        const width = Math.min(440, Math.max(260, r.width - 24));
        panel.style.width = width + "px";
        panel.style.left = Math.max(8, Math.min(r.left + 12, window.innerWidth - width - 8)) + "px";
        panel.style.bottom = Math.max(8, window.innerHeight - r.top + 6) + "px";
        panel.style.maxHeight = Math.max(220, Math.min(460, r.top - 16)) + "px";
    }

    function status(text) {
        const p = panel.querySelector(".gif-status");
        p.textContent = text || "";
        p.hidden = !text;
    }

    function showUnconfigured() {
        panel.classList.add("unconfigured");
        panel.querySelector(".gif-tabs").hidden = true;
        panel.querySelector(".gif-grid").textContent = "";
        const p = panel.querySelector(".gif-status");
        p.textContent = "";
        p.hidden = false;
        p.append(
            el("strong", null, "GIF search isn't configured on this instance."),
            el("span", "gif-why",
                " It needs a KLIPY or GIPHY key from whoever runs the instance — Cairn ships none, " +
                "and never shows adverts. Photos and files still work."),
        );
        panel.querySelector(".gif-privacy").textContent = "";
        panel.querySelector(".gif-attribution").textContent = "";
    }

    function selectProvider(id) {
        const p = providers.find((x) => x.id === id) || providers[0];
        current = p.id;
        for (const t of panel.querySelectorAll(".gif-tab")) {
            const on = t.dataset.provider === current;
            t.classList.toggle("on", on);
            t.setAttribute("aria-selected", on ? "true" : "false");
        }
        const input = panel.querySelector(".gif-search");
        input.placeholder = p.placeholder;
        panel.querySelector(".gif-attribution").textContent = p.attribution || "";
        // Said plainly, as docs/14-gifs.md §3 asks: the relay hides who is searching from
        // the provider, not what is searched for — and a small instance is a small crowd.
        const privacy = panel.querySelector(".gif-privacy");
        privacy.textContent = "Searched through your instance";
        privacy.title = p.name + " sees what you search for, but not your address — the request comes from " +
            "your instance. On an instance with few people that hides you in a small crowd. Sent GIFs are " +
            "encrypted like photos; recipients never contact " + p.name + ".";
        search(input.value);
    }

    function renderTabs() {
        const tabs = panel.querySelector(".gif-tabs");
        tabs.textContent = "";
        // A tab only means something with a choice to make.
        if (providers.length < 2) {
            tabs.hidden = true;
            return;
        }
        tabs.hidden = false;
        for (const p of providers) {
            const t = el("button", "ghost gif-tab", p.name);
            t.type = "button";
            t.dataset.provider = p.id;
            t.setAttribute("role", "tab");
            t.onclick = () => { if (current !== p.id) selectProvider(p.id); };
            tabs.append(t);
        }
    }

    async function search(query) {
        const mine = ++generation;
        const grid = panel.querySelector(".gif-grid");
        status(query.trim() ? "Searching…" : "Loading trending…");
        let results;
        try {
            results = await invoke("gif_search", { provider: current, query });
        } catch (e) {
            if (mine === generation) status(String(e));
            return;
        }
        if (mine !== generation) return;
        revoke();
        grid.textContent = "";
        status(results.length ? "" : "No GIFs found.");
        const queue = [];
        for (const r of results) {
            const tile = el("button", "gif-tile");
            tile.type = "button";
            tile.dataset.id = r.id;
            tile.setAttribute("role", "listitem");
            // The title is the provider's and is untrusted text: it goes in attributes and
            // textContent only.
            tile.title = r.title || "GIF";
            tile.setAttribute("aria-label", "Send " + (r.title || "GIF"));
            if (r.width && r.height) tile.style.aspectRatio = r.width + " / " + r.height;
            tile.onclick = () => choose(tile, r);
            grid.append(tile);
            queue.push({ tile, r });
        }
        // A few at a time, in order, so the top of the grid fills first.
        const worker = async () => {
            while (queue.length && mine === generation) {
                const { tile, r } = queue.shift();
                try {
                    const bytes = bytesOf(await invoke("gif_preview", { id: r.id }));
                    if (mine !== generation) return;
                    const url = URL.createObjectURL(new Blob([bytes]));
                    urls.add(url);
                    const img = el("img");
                    img.alt = r.title || "GIF";
                    img.src = url;
                    tile.append(img);
                } catch (_) {
                    tile.classList.add("broken");
                }
            }
        };
        await Promise.all(Array.from({ length: PARALLEL }, worker));
    }

    async function choose(tile, r) {
        if (panel.classList.contains("sending")) return;
        if (!canSend()) return onError("Open a room before sending a GIF.");
        panel.classList.add("sending");
        tile.classList.add("chosen");
        status("Sending…");
        try {
            const view = await invoke("send_gif", { id: r.id });
            close();
            onSent(view);
        } catch (e) {
            status(String(e));
        } finally {
            panel.classList.remove("sending");
            tile.classList.remove("chosen");
        }
    }

    async function open() {
        if (!panel) build();
        panel.hidden = false;
        button.classList.add("on");
        button.setAttribute("aria-expanded", "true");
        place();
        panel.classList.remove("unconfigured");
        status("Loading…");
        try {
            providers = await invoke("gif_providers");
        } catch (e) {
            providers = null;
            status(String(e));
            return;
        }
        if (!providers.length) return showUnconfigured();
        renderTabs();
        selectProvider(current || providers[0].id);
        panel.querySelector(".gif-search").focus();
    }

    function close() {
        if (!panel || panel.hidden) return;
        panel.hidden = true;
        generation++;
        revoke();
        panel.querySelector(".gif-grid").textContent = "";
        button.classList.remove("on");
        button.setAttribute("aria-expanded", "false");
    }

    function bind(o) {
        invoke = o.invoke;
        onSent = o.onSent || onSent;
        onError = o.onError || onError;
        canSend = o.canSend || canSend;
        button = o.button;
        anchor = o.anchor;
        button.setAttribute("aria-expanded", "false");
        button.onclick = () => (panel && !panel.hidden ? close() : open());
    }

    return { bind, open, close };
})();
