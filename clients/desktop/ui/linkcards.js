// Link cards and the link-preview setting. Presentation only.
//
// Everything about a card was decided in Rust (cairn_client_core::embed::CardView): whether
// to show it at all, where the link really goes, what kind of post it is, which caveat
// applies, and the thumbnail's bytes. This file lays that out and forwards clicks.
//
// Rules it holds to, from docs/05-embeds.md §3:
// - textContent only. Every string on a card is the sender's; none is ever parsed as HTML.
// - The real destination host is always visible, computed in Rust from the URL rather than
//   taken from the card, so a card titled "Reuters" cannot hide that its link goes elsewhere.
// - The card reads as the sender's, never as verified: no tick, no accent, no "official".
// - No remote content. The thumbnail arrives as a data: URI the *sender's* device made, and
//   anything else is refused here as well as by the CSP (img-src 'self' data: blob:).
//   Loading an image from its original URL would have the recipient contact the platform —
//   the leak the whole design exists to prevent.
// - Clicking opens the link in the system browser through Rust, which accepts only a plain
//   http(s) URL. Nothing is ever loaded inside the client.

const CairnLinkCards = (() => {
    let invoke = (cmd, args) => window.__TAURI__.core.invoke(cmd, args);
    let onError = () => {};
    const $ = (id) => document.getElementById(id);

    function bind(opts) {
        if (opts.invoke) invoke = opts.invoke;
        if (opts.onError) onError = opts.onError;
        for (const box of siteBoxes()) box.addEventListener("change", save);
        const proxy = $("pref-ig-proxy");
        if (proxy) proxy.addEventListener("change", save);
    }

    // One checkbox per site, keyed by the field name Rust uses (embed::Sites).
    const siteBoxes = () => [...document.querySelectorAll("#prefs-previews input[data-site]")];
    // What Rust last confirmed. Used only to word the composer's status line; whether a
    // link is fetched is decided in Rust, against the stored settings.
    let current = {};

    const text = (cls, value) => {
        const el = document.createElement("div");
        el.className = cls;
        el.textContent = value;
        return el;
    };

    // Belt and braces with the CSP: only an inline JPEG of the shape Rust produces.
    const safeThumb = (uri) => typeof uri === "string" && uri.startsWith("data:image/jpeg;base64,");

    function render(c) {
        const card = document.createElement("div");
        card.className = "link-card" + (c.portrait ? " portrait" : "");
        card.tabIndex = 0;
        card.setAttribute("role", "link");
        card.setAttribute("aria-label", "Open " + c.host + " in your browser");
        card.title = c.url;
        const open = (ev) => {
            ev.stopPropagation();
            invoke("open_link", { url: c.url }).catch(onError);
        };
        card.addEventListener("click", open);
        card.addEventListener("keydown", (ev) => { if (ev.key === "Enter") open(ev); });
        // A double-click on a message sends a heart; on a card it would also open the link.
        card.addEventListener("dblclick", (ev) => ev.stopPropagation());

        // The picture: the sender's thumbnail, or — for a recognised post with nothing
        // fetched — a plain tile naming what the URL itself says it is.
        const thumb = safeThumb(c.thumbnail) ? c.thumbnail : null;
        if (thumb || c.platform) {
            const media = document.createElement("div");
            media.className = "lc-media";
            if (thumb) {
                const img = document.createElement("img");
                img.alt = "";
                img.decoding = "async";
                img.src = thumb;
                media.append(img);
            } else {
                media.classList.add("empty");
                media.append(text("lc-media-label", c.platform));
            }
            if (c.portrait) {
                // Not a player: the video is not in the message, and fetching it here would
                // contact the platform. The glyph says "opening this plays it", which is what
                // clicking does — in the browser.
                const play = document.createElement("span");
                play.className = "lc-play";
                play.setAttribute("aria-hidden", "true");
                media.append(play);
            }
            card.append(media);
        }

        const meta = document.createElement("div");
        meta.className = "lc-meta";
        // Platform and kind come from the URL, in Rust. A site name comes from the page, so
        // it is labelled as what the page says about itself, not shown as an attribution.
        const eyebrow = [c.platform, c.kind].filter(Boolean).join(" · ")
            || (c.claimed_site ? "page says: " + c.claimed_site : "");
        if (eyebrow) meta.append(text("lc-eyebrow", eyebrow));
        if (c.title) meta.append(text("lc-title", c.title));
        else if (c.platform) meta.append(text("lc-title", c.platform + " " + (c.kind || "link").toLowerCase()));
        if (c.author) meta.append(text("lc-author", c.author));
        if (c.description) meta.append(text("lc-desc", c.description));
        if (!c.title && !c.description) meta.append(text("lc-desc", "No preview available · open link"));

        const dest = text("lc-dest", "↗ " + c.host);
        dest.title = c.url;
        meta.append(dest);
        if (c.host_warning) meta.append(text("lc-warn", c.host_warning));
        if (c.caveat) meta.append(text("lc-warn", c.caveat));
        meta.append(text("lc-claim", "Preview supplied by the sender, not checked by Cairn"));

        card.append(meta);
        return card;
    }

    // ---- the settings ------------------------------------------------------
    //
    // Stored per profile and enforced in Rust (cairn_client_core::embed::Sites): every site
    // is off until switched on, and Rust refuses each request — redirects and thumbnails
    // included — to a site that is off. This only shows the switches and hands them back.
    // The proxy's disclosure text comes from Rust too, so every client says the same thing.

    function draw(s) {
        current = s || {};
        for (const box of siteBoxes()) box.checked = !!current[box.dataset.site];
        const proxy = $("pref-ig-proxy");
        if (proxy) {
            proxy.checked = !!current.instagram_proxy;
            // The proxy is a way to preview Instagram; with Instagram off it has no job.
            proxy.disabled = !current.instagram;
        }
    }

    async function loadSettings() {
        if (!siteBoxes().length) return;
        try {
            draw(await invoke("link_previews"));
            const note = $("ig-proxy-note");
            if (note) note.textContent = await invoke("instagram_proxy_disclosure");
        } catch (e) { onError(e); }
    }

    async function save() {
        const settings = {};
        for (const box of siteBoxes()) settings[box.dataset.site] = box.checked;
        const proxy = $("pref-ig-proxy");
        settings.instagram_proxy = !!settings.instagram && !!proxy && proxy.checked;
        try {
            await invoke("set_link_previews", { settings });
            draw(settings);
        } catch (e) {
            onError(e);
            await loadSettings();
        }
    }

    // While a message with a link waits for its preview (up to five seconds, in Rust), say
    // so, or the composer just looks stuck. Shown only when some site is switched on; Rust
    // decides whether this particular link is fetched. Returns a function that clears it.
    function sending(message) {
        const status = $("preview-status");
        const anyOn = siteBoxes().some((b) => current[b.dataset.site]);
        if (!status || !anyOn || !/https?:\/\//.test(message)) return () => {};
        status.textContent = "Checking for a link preview\u2026 if this site's previews are on, it can see this device's IP address.";
        status.hidden = false;
        return () => { status.hidden = true; status.textContent = ""; };
    }

    return { bind, render, loadSettings, sending };
})();
