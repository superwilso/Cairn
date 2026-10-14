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
        const previews = $("pref-previews");
        const proxy = $("pref-ig-proxy");
        if (previews) previews.addEventListener("change", save);
        if (proxy) proxy.addEventListener("change", save);
    }

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

    // ---- the setting -------------------------------------------------------
    //
    // Stored per profile by Rust. The proxy's disclosure text comes from Rust too, so every
    // client says the same thing about who sees the link.

    async function loadSettings() {
        const previews = $("pref-previews");
        const proxy = $("pref-ig-proxy");
        if (!previews) return;
        try {
            const s = await invoke("link_previews");
            previews.checked = !!s.enabled;
            if (proxy) {
                proxy.checked = !!s.instagram_proxy;
                proxy.disabled = !s.enabled;
            }
            const note = $("ig-proxy-note");
            if (note) note.textContent = await invoke("instagram_proxy_disclosure");
        } catch (e) { onError(e); }
    }

    async function save() {
        const previews = $("pref-previews");
        const proxy = $("pref-ig-proxy");
        const settings = {
            enabled: previews.checked,
            instagram_proxy: previews.checked && !!proxy && proxy.checked,
        };
        if (proxy) proxy.disabled = !settings.enabled;
        try {
            await invoke("set_link_previews", { settings });
        } catch (e) {
            onError(e);
            await loadSettings();
        }
    }

    // While a message with a link is waiting for its preview (up to five seconds, in Rust),
    // say so — otherwise the composer just looks stuck. Returns a function that clears it.
    function sending(message) {
        const status = $("preview-status");
        const previews = $("pref-previews");
        if (!status || (previews && !previews.checked) || !/https?:\/\//.test(message)) {
            return () => {};
        }
        status.textContent = "Fetching a link preview… the linked site can see this device's IP address.";
        status.hidden = false;
        return () => { status.hidden = true; status.textContent = ""; };
    }

    return { bind, render, loadSettings, sending };
})();
