// Appearance: themes, type, layout, and the user's own CSS. Client-side only.
//
// Nothing here goes below the FFI line. It never sees a message's meaning, a key or a tier;
// it decorates what app.js and messages.js already drew (docs/13-customisation.md §4), and
// nothing it stores leaves this device — the server is not involved in how a client looks.
//
// Loaded in <head>, before the page paints, so a saved theme is applied without a flash of
// the default one. The panel is built once the DOM exists.
//
// THE HAZARD (docs/13-customisation.md §5): a theming system that can repaint the whole
// interface can repaint the encryption badge. Three things stand against that:
//
//   1. Themes are data, not CSS. An imported theme is a list of colour tokens and a few
//      enumerated choices, validated key by key; it cannot carry a selector, so it cannot
//      reach the badge. The badge takes none of its colours from those tokens.
//   2. The badge's own rules live in style.css's `security` cascade layer, all !important.
//      The earliest layer's !important declarations outrank every later rule, so user CSS
//      cannot restyle the badge element itself. User CSS that declares or joins a layer is
//      refused — that is the one way to get into the same layer — and what is applied is the
//      browser's own re-serialisation of what was checked, so @import cannot slip through.
//   3. User CSS can still act on an *ancestor* — hide the sidebar, fade the header, cover
//      the badge with something else. checkIndicators() measures for that and switches user
//      CSS off when it trips. It is a tripwire on what the page can measure, not a proof:
//      for example an overlay with `pointer-events: none` is invisible to hit-testing. That
//      limit is stated here so nobody upgrades the claim later.

const CairnLook = (() => {
    const KEY = "cairn.look.v1";
    const html = document.documentElement;
    const $ = (id) => document.getElementById(id);

    const THEMES = [
        ["slate", "Slate", "The signature. Wet stone after rain."],
        ["fieldbook", "Fieldbook", "Light. Weathered paper, iron-gall ink."],
        ["basalt", "Basalt", "True black, for OLED screens."],
        ["survey", "Survey", "High contrast. No texture."],
        ["moss", "Moss", "Forest floor and lichen."],
        ["campfire", "Campfire", "Embers and woodsmoke."],
        ["ordnance", "Ordnance", "A gridded map sheet."],
    ];
    const FONTS = [
        ["schibsted", "Schibsted Grotesk", "Default"],
        ["alegreya", "Alegreya Sans", "Humanist"],
        ["atkinson", "Atkinson Hyperlegible", "Legibility"],
        ["literata", "Literata", "Bookish serif"],
        ["plex-mono", "IBM Plex Mono", "All mono"],
    ];
    const CHOICES = {
        layout: [["notebook", "Notebook"], ["bubbles", "Bubbles"], ["irc", "IRC lines"]],
        density: [["cozy", "Cozy"], ["compact", "Compact"]],
        avatar: [["stone", "Stone"], ["circle", "Circle"], ["square", "Square"], ["hex", "Hex"]],
        clock: [["24", "24-hour"], ["12", "12-hour"], ["off", "Hidden"]],
        motion: [["system", "Follow system"], ["reduce", "Reduced"], ["full", "Full"]],
    };
    const RANGES = {
        textSize: [12, 20, 0.5],
        uiScale: [80, 130, 5],
        sidebar: [200, 360, 4],
    };
    // Colour tokens a theme may set. Deliberately no badge, alarm or warning colours: those
    // are not tokens at all (see style.css, `@layer security`).
    const TOKENS = [
        "bg", "surface", "surface-2", "raised", "line", "line-soft",
        "text", "muted", "dim", "accent", "accent-2", "accent-ink",
        "ok", "warn", "danger", "topo-ink", "grain-ink",
    ];
    const NUMBERS = { "topo-alpha": [0, 0.4], "grain-alpha": [0, 0.6], "radius": [0, 16], "radius-sm": [0, 12] };

    const DEFAULTS = {
        theme: "slate",
        base: "slate",
        tokens: null,
        accent: null,
        font: "schibsted",
        textSize: 14.5,
        uiScale: 100,
        sidebar: 256,
        layout: "notebook",
        density: "cozy",
        avatar: "stone",
        clock: "24",
        motion: "system",
        customCss: "",
        customCssOn: false,
        customCssNote: "",
    };

    let s = load();
    let styleEl = null;
    let watch = null;
    let checkTimer = null;

    // ---- storage --------------------------------------------------------------
    // localStorage can be absent or throw (private windows, blocked storage, some webview
    // configurations). Every access is guarded and the page works with the defaults.

    function load() {
        try {
            const raw = localStorage.getItem(KEY);
            if (raw) return sanitize(JSON.parse(raw));
        } catch (_) { /* fall through to defaults */ }
        return { ...DEFAULTS };
    }

    function save() {
        try { localStorage.setItem(KEY, JSON.stringify(s)); } catch (_) { /* not persisted */ }
    }

    // Everything read back from storage or an import goes through here: unknown keys are
    // dropped, enums must be one of the listed values, numbers are clamped, colours must be
    // hex. The custom CSS string is only ever kept, never interpreted here.
    function sanitize(input) {
        const out = { ...DEFAULTS };
        if (!input || typeof input !== "object") return out;
        const themeIds = THEMES.map(([id]) => id);
        if (themeIds.includes(input.theme) || input.theme === "custom") out.theme = input.theme;
        if (themeIds.includes(input.base)) out.base = input.base;
        if (out.theme === "custom") out.tokens = cleanTokens(input.tokens);
        if (out.theme === "custom" && !out.tokens) out.theme = out.base;
        out.accent = hex(input.accent);
        if (FONTS.some(([id]) => id === input.font)) out.font = input.font;
        for (const [k, [lo, hi]] of Object.entries(RANGES)) {
            const n = Number(input[k]);
            if (Number.isFinite(n)) out[k] = Math.min(hi, Math.max(lo, n));
        }
        for (const [k, list] of Object.entries(CHOICES)) {
            if (list.some(([v]) => v === input[k])) out[k] = input[k];
        }
        if (typeof input.customCss === "string") out.customCss = input.customCss.slice(0, 50_000);
        out.customCssOn = input.customCssOn === true && out.customCss.trim() !== "";
        if (typeof input.customCssNote === "string") out.customCssNote = input.customCssNote.slice(0, 400);
        return out;
    }

    function hex(v) {
        if (typeof v !== "string") return null;
        const m = v.trim().match(/^#([0-9a-f]{3}|[0-9a-f]{6})$/i);
        if (!m) return null;
        const h = m[1].length === 3 ? m[1].split("").map((c) => c + c).join("") : m[1];
        return "#" + h.toLowerCase();
    }

    function cleanTokens(t) {
        if (!t || typeof t !== "object") return null;
        const out = {};
        for (const k of TOKENS) {
            const c = hex(t[k]);
            if (c) out[k] = c;
        }
        for (const [k, [lo, hi]] of Object.entries(NUMBERS)) {
            const n = Number(t[k]);
            if (t[k] !== undefined && Number.isFinite(n)) out[k] = Math.min(hi, Math.max(lo, n));
        }
        return Object.keys(out).length ? out : null;
    }

    // ---- applying -------------------------------------------------------------

    function inkFor(color) {
        const c = hex(color);
        if (!c) return "#000";
        const [r, g, b] = [1, 3, 5].map((i) => parseInt(c.slice(i, i + 2), 16) / 255)
            .map((x) => (x <= 0.03928 ? x / 12.92 : ((x + 0.055) / 1.055) ** 2.4));
        const lum = 0.2126 * r + 0.7152 * g + 0.0722 * b;
        return lum > 0.32 ? "#14110b" : "#fffaf0";
    }

    function apply() {
        html.dataset.theme = s.theme === "custom" ? s.base : s.theme;
        for (const k of TOKENS) html.style.removeProperty("--" + k);
        for (const k of Object.keys(NUMBERS)) html.style.removeProperty("--" + k);
        if (s.theme === "custom" && s.tokens) {
            for (const [k, v] of Object.entries(s.tokens)) {
                html.style.setProperty("--" + k, NUMBERS[k] && k.startsWith("radius") ? v + "px" : String(v));
            }
        }
        if (s.accent) {
            html.style.setProperty("--accent", s.accent);
            html.style.setProperty("--accent-ink", inkFor(s.accent));
        }
        html.dataset.font = s.font;
        html.dataset.layout = s.layout;
        html.dataset.density = s.density;
        html.dataset.avatar = s.avatar;
        html.dataset.clock = s.clock;
        html.dataset.motion = s.motion;
        html.style.setProperty("--msg-size", s.textSize + "px");
        html.style.setProperty("--sidebar-w", s.sidebar + "px");
        html.style.zoom = s.uiScale === 100 ? "" : String(s.uiScale / 100);
        retime();
        applyCustomCss();
    }

    function set(key, value) {
        s = sanitize({ ...s, [key]: value });
        save();
        apply();
        syncPanel();
    }

    // ---- user CSS -------------------------------------------------------------

    // Parsed by the browser, not by a regex: CSS escapes mean `@\6c ayer` is `@layer`, and
    // only the real parser agrees with the real parser.
    function inspectCss(text) {
        let sheet;
        try {
            sheet = new CSSStyleSheet();
            sheet.replaceSync(text);
        } catch (e) {
            return { ok: false, why: "That CSS could not be parsed." };
        }
        const bad = [];
        (function walk(rules) {
            for (const r of rules) {
                const name = r.constructor && r.constructor.name;
                if (name === "CSSLayerBlockRule" || name === "CSSLayerStatementRule") bad.push("@layer");
                if (name === "CSSImportRule") bad.push("@import");
                if (r.cssRules) walk(r.cssRules);
            }
        })(sheet.cssRules);
        if (bad.length) {
            return {
                ok: false,
                why: "Custom CSS may not use " + [...new Set(bad)].join(" or ") +
                    ": cascade layers are how the encryption badges are kept out of reach.",
            };
        }
        return { ok: true, css: [...sheet.cssRules].map((r) => r.cssText).join("\n") };
    }

    function applyCustomCss() {
        if (!s.customCssOn || !s.customCss.trim()) {
            if (styleEl) styleEl.remove();
            styleEl = null;
            stopWatching();
            return;
        }
        const checked = inspectCss(s.customCss);
        if (!checked.ok) {
            disableCustomCss(checked.why);
            return;
        }
        if (!styleEl) {
            styleEl = document.createElement("style");
            styleEl.id = "user-css";
        }
        styleEl.textContent = checked.css;
        // Last in <head>, so for equal specificity it wins over the app's own rules — except
        // the security layer, which it cannot outrank at any specificity.
        document.head.append(styleEl);
        startWatching();
        scheduleCheck();
    }

    function disableCustomCss(why) {
        s.customCssOn = false;
        s.customCssNote = why;
        save();
        if (styleEl) styleEl.remove();
        styleEl = null;
        stopWatching();
        syncPanel();
        toast(why);
    }

    // ---- the tripwire ---------------------------------------------------------

    const INDICATORS = ".badge, .tick, #safety-changed, #waiting, #member-list li.pending";
    // Colours the security layer paints. If a computed colour differs, something outranked
    // the layer — which should be impossible, so it is checked rather than assumed.
    const EXPECT = {
        ok: ["rgb(29, 107, 67)", "rgb(242, 255, 246)"],
        warn: ["rgb(242, 176, 30)", "rgb(29, 19, 0)"],
        bad: ["rgb(196, 43, 37)", "rgb(255, 255, 255)"],
        none: ["rgb(58, 62, 65)", "rgb(241, 239, 232)"],
    };
    // Things the app itself legitimately draws over the page.
    const overlay = (hit) =>
        hit.closest("#settings, #safety, #react-picker, #look-toast") ||
        (html.classList.contains("show-people") && hit.closest(".people"));

    function clipped(el, x, y) {
        for (let a = el.parentElement; a && a !== document.body; a = a.parentElement) {
            const cs = getComputedStyle(a);
            if (cs.overflowX === "visible" && cs.overflowY === "visible") continue;
            const r = a.getBoundingClientRect();
            if (x < r.left || x > r.right || y < r.top || y > r.bottom) return true;
        }
        return x < 0 || y < 0 || x > innerWidth || y > innerHeight;
    }

    function describe(el) {
        if (el.id === "room-tier") return "the room's encryption badge";
        if (el.id === "transport") return "the connection badge";
        if (el.closest("#rooms")) return "a room's encryption badge";
        if (el.closest("#channels")) return "a channel's encryption badge";
        if (el.closest("#member-list")) return "a member's safety indicator";
        if (el.closest("#safety")) return "a safety-number indicator";
        return "a security indicator";
    }

    // Returns a description of the first indicator found hidden or altered, or null.
    function checkIndicators() {
        for (const el of document.querySelectorAll(INDICATORS)) {
            if (!el.isConnected || el.closest("[hidden]")) continue;
            if (el.matches(".badge") && el.textContent.trim() === "") continue;
            const what = describe(el);
            if (el.checkVisibility && !el.checkVisibility({ opacityProperty: true, visibilityProperty: true })) {
                return what + " was hidden";
            }
            const r = el.getBoundingClientRect();
            if (r.width < 6 || r.height < 6) return what + " was shrunk out of sight";
            let opacity = 1;
            for (let a = el; a; a = a.parentElement) {
                const cs = getComputedStyle(a);
                opacity *= Number(cs.opacity);
                if (a !== el && cs.filter !== "none") return what + " was filtered";
                if (cs.mixBlendMode !== "normal" && !a.matches(".grain-layer")) return what + " was blended";
            }
            if (opacity < 0.9) return what + " was faded";
            if (el.matches(".badge")) {
                const tone = el.classList.contains("ok") ? "ok"
                    : el.classList.contains("warn") ? "warn"
                    : el.classList.contains("bad") ? "bad" : "none";
                const cs = getComputedStyle(el);
                const [bg, fg] = EXPECT[tone];
                if (cs.backgroundColor !== bg || cs.color !== fg) return what + " was recoloured";
            }
            const x = r.left + r.width / 2;
            const y = r.top + r.height / 2;
            if (!clipped(el, x, y)) {
                const hit = document.elementFromPoint(x, y);
                // The badge takes pointer events (the security layer says so), so an unobscured
                // badge is its own hit. A hit on an ancestor means one of its pseudo-elements, or
                // something else painted over it, is on top.
                if (hit && !el.contains(hit) && !overlay(hit)) {
                    return what + " was covered";
                }
            }
        }
        return null;
    }

    function settling() {
        // Wait out the arrival animations; a half-faded sidebar is not a violation.
        return document.getAnimations().some((a) => {
            const t = a.effect && a.effect.getComputedTiming ? a.effect.getComputedTiming() : null;
            return a.playState === "running" && t && Number.isFinite(t.endTime);
        });
    }

    function scheduleCheck(delay = 120) {
        clearTimeout(checkTimer);
        checkTimer = setTimeout(() => {
            if (!styleEl) return;
            if (settling()) return scheduleCheck(250);
            requestAnimationFrame(() => {
                const problem = checkIndicators();
                if (problem) {
                    disableCustomCss(
                        "Your custom CSS was switched off: " + problem + ". Encryption and " +
                        "safety indicators must stay visible and unaltered."
                    );
                }
            });
        }, delay);
    }

    function startWatching() {
        if (watch || !document.body) return;
        watch = new MutationObserver(() => scheduleCheck(200));
        watch.observe(document.body, {
            subtree: true, childList: true, attributes: true,
            attributeFilter: ["class", "hidden", "style"],
        });
        addEventListener("resize", onResize);
    }
    function stopWatching() {
        if (watch) watch.disconnect();
        watch = null;
        removeEventListener("resize", onResize);
    }
    function onResize() { scheduleCheck(200); }

    // ---- toast ----------------------------------------------------------------

    let toastTimer = null;
    function toast(text) {
        if (!document.body) return;
        let el = $("look-toast");
        if (!el) {
            el = document.createElement("div");
            el.id = "look-toast";
            el.setAttribute("role", "status");
            document.body.append(el);
        }
        el.textContent = text;
        el.hidden = false;
        clearTimeout(toastTimer);
        toastTimer = setTimeout(() => { el.hidden = true; }, 9000);
    }

    // ---- timestamps, avatars, grouping ----------------------------------------

    function formatTime(ms) {
        const d = new Date(Number(ms));
        if (Number.isNaN(d.getTime())) return "";
        if (s.clock === "12") {
            const h = d.getHours() % 12 || 12;
            return h + ":" + String(d.getMinutes()).padStart(2, "0") + (d.getHours() < 12 ? " am" : " pm");
        }
        return String(d.getHours()).padStart(2, "0") + ":" + String(d.getMinutes()).padStart(2, "0");
    }

    function retime() {
        for (const t of document.querySelectorAll("time.ts[data-ms]")) t.textContent = formatTime(t.dataset.ms);
    }

    // A hue per person, from the same two characters their avatar shows, so the colour in
    // the member list and in the timeline always agree.
    function hue(text) {
        // FNV-1a, then the golden angle, so ids that differ by one character still land
        // far apart on the colour wheel.
        let h = 0x811c9dc5;
        for (const ch of String(text)) h = Math.imul(h ^ ch.codePointAt(0), 0x01000193) >>> 0;
        return Math.round((h % 997) * 137.508) % 360;
    }
    const initials = (id) => String(id).replace(/^usr_|^rom_/, "").slice(0, 2).toUpperCase();

    function tint(el) {
        if (!el || !el.classList || !el.classList.contains("avatar")) return;
        const text = el.textContent.trim();
        if (text) el.style.setProperty("--h", hue(text));
    }

    // Adds an avatar, a header row and a timestamp to a message app.js is about to append.
    // Presentation only: reads the sender and the time Rust already supplied.
    function decorate(li, m) {
        if (!li || !li.classList.contains("msg")) return li;
        const who = li.querySelector(":scope > .who");
        const ini = initials(m.sender);
        li.style.setProperty("--h", hue(ini));
        li.dataset.from = m.sender;

        const av = document.createElement("span");
        av.className = "avatar";
        av.textContent = ini;
        av.setAttribute("aria-hidden", "true");
        av.style.setProperty("--h", hue(ini));

        const head = document.createElement("div");
        head.className = "head";
        if (who) head.append(who);
        const t = document.createElement("time");
        t.className = "ts";
        t.dataset.ms = m.sent_at_ms;
        const when = new Date(Number(m.sent_at_ms));
        if (!Number.isNaN(when.getTime())) {
            t.dateTime = when.toISOString();
            t.title = when.toLocaleString();
        }
        t.textContent = formatTime(m.sent_at_ms);
        head.append(t);
        li.prepend(av, head);

        // Consecutive messages from one person within five minutes read as one block.
        const prev = $("timeline") && $("timeline").lastElementChild;
        if (prev && prev.classList.contains("msg") && prev.dataset.from === m.sender && !m.reply_to &&
            Math.abs(Number(m.sent_at_ms) - Number(prev.dataset.sent)) < 5 * 60_000) {
            li.classList.add("cont");
        }
        li.classList.add("arrive");
        li.addEventListener("animationend", () => li.classList.remove("arrive"), { once: true });
        return li;
    }

    // ---- the panel --------------------------------------------------------------

    function el(tag, attrs = {}, ...kids) {
        const n = document.createElement(tag);
        for (const [k, v] of Object.entries(attrs)) {
            if (k === "class") n.className = v;
            else if (k === "text") n.textContent = v;
            else if (k.startsWith("data-") || k.startsWith("aria-") || k === "for" || k === "role") n.setAttribute(k, v);
            else n[k] = v;
        }
        for (const kid of kids) if (kid) n.append(kid);
        return n;
    }

    function section(title, note, ...body) {
        return el("section", { class: "set-section" },
            el("h4", { text: title }),
            note ? el("p", { class: "set-note", text: note }) : null,
            ...body);
    }

    function seg(key) {
        const box = el("div", { class: "seg", role: "radiogroup", "aria-label": key });
        for (const [value, label] of CHOICES[key]) {
            const id = "set-" + key + "-" + value;
            const input = el("input", { type: "radio", name: "set-" + key, id, value });
            input.addEventListener("change", () => set(key, value));
            box.append(input, el("label", { for: id, text: label, "data-value": value }));
        }
        return box;
    }

    function range(key, label, unit) {
        const [lo, hi, step] = RANGES[key];
        const out = el("output", { class: "mono", id: "set-" + key + "-out" });
        const input = el("input", { type: "range", min: lo, max: hi, step, id: "set-" + key });
        input.addEventListener("input", () => {
            out.textContent = input.value + unit;
            set(key, Number(input.value));
        });
        return el("div", { class: "range" }, el("label", { for: "set-" + key, text: label }), input, out);
    }

    // Link previews live here rather than in the members column, where seven toggles and
    // their explanations pushed the member list out of sight. The nodes come from
    // index.html, already bound by linkcards.js, so they are moved rather than rebuilt.
    function privacy() {
        const prefs = $("prefs-previews");
        if (!prefs) return el("span");
        prefs.hidden = false;
        return section("Link previews", null, prefs);
    }

    function build() {
        const sheet = $("settings");
        if (!sheet || sheet.dataset.built) return;
        sheet.dataset.built = "1";

        const themes = el("div", { class: "theme-grid" });
        for (const [id, name, blurb] of THEMES) {
            const card = el("button", { type: "button", class: "theme-card", "data-theme": id, "data-pick": id, title: blurb },
                el("span", { class: "tc-art" },
                    el("span", { class: "tc-side" }),
                    el("span", { class: "tc-main" },
                        el("span", { class: "tc-line l1" }),
                        el("span", { class: "tc-line l2" }),
                        el("span", { class: "tc-line l3" }),
                        el("span", { class: "tc-blaze" }))),
                el("span", { class: "tc-name", text: name }),
                el("span", { class: "tc-blurb", text: blurb }));
            card.addEventListener("click", () => {
                s = sanitize({ ...s, theme: id, base: id, tokens: null, accent: null });
                save(); apply(); syncPanel();
            });
            themes.append(card);
        }
        const custom = el("button", { type: "button", class: "theme-card custom", "data-pick": "custom", id: "set-custom-card", hidden: true },
            el("span", { class: "tc-art" }, el("span", { class: "tc-side" }), el("span", { class: "tc-main" },
                el("span", { class: "tc-line l1" }), el("span", { class: "tc-line l2" }), el("span", { class: "tc-blaze" }))),
            el("span", { class: "tc-name", text: "Imported" }),
            el("span", { class: "tc-blurb", text: "Your imported theme." }));
        themes.append(custom);

        const accent = el("input", { type: "color", id: "set-accent", "aria-label": "Accent colour" });
        accent.addEventListener("input", () => set("accent", accent.value));
        const accentReset = el("button", { type: "button", class: "ghost", id: "set-accent-reset", text: "Use the theme's" });
        accentReset.addEventListener("click", () => set("accent", null));

        const fonts = el("div", { class: "font-grid", role: "radiogroup", "aria-label": "Font" });
        for (const [id, name, tag] of FONTS) {
            const input = el("input", { type: "radio", name: "set-font", id: "set-font-" + id, value: id });
            input.addEventListener("change", () => set("font", id));
            fonts.append(input, el("label", { for: "set-font-" + id, class: "font-card", "data-font": id },
                el("span", { class: "fc-sample", text: "Ag" }),
                el("span", { class: "fc-name", text: name }),
                el("span", { class: "fc-tag", text: tag })));
        }

        const css = el("textarea", {
            id: "set-css", spellcheck: false, rows: 7,
            placeholder: "/* e.g. */\n.msg .body { letter-spacing: 0.01em; }\nmain { --atmos: none; }",
        });
        const cssOn = el("input", { type: "checkbox", id: "set-css-on" });
        const cssApply = el("button", { type: "button", class: "primary", id: "set-css-apply", text: "Apply CSS" });
        const cssOff = el("button", { type: "button", class: "ghost", id: "set-css-off", text: "Switch off" });
        cssApply.addEventListener("click", () => {
            s.customCss = css.value.slice(0, 50_000);
            s.customCssNote = "";
            const checked = inspectCss(s.customCss);
            if (!checked.ok) {
                s.customCssOn = false;
                s.customCssNote = checked.why;
            } else {
                s.customCssOn = s.customCss.trim() !== "";
            }
            save(); apply(); syncPanel();
        });
        cssOff.addEventListener("click", () => { s.customCssOn = false; s.customCssNote = ""; save(); apply(); syncPanel(); });
        cssOn.addEventListener("change", () => {
            s.customCssOn = cssOn.checked && s.customCss.trim() !== "";
            s.customCssNote = "";
            save(); apply(); syncPanel();
        });

        const json = el("textarea", { id: "theme-json", spellcheck: false, rows: 5, placeholder: "Paste a Cairn theme here, or export yours." });
        const exp = el("button", { type: "button", id: "theme-export", text: "Export current theme" });
        const imp = el("button", { type: "button", class: "primary", id: "theme-import", text: "Import" });
        const file = el("input", { type: "file", id: "theme-file", accept: ".json,application/json", hidden: true });
        const pick = el("button", { type: "button", class: "ghost", id: "theme-file-pick", text: "From a file…" });
        const copy = el("button", { type: "button", class: "ghost", id: "theme-copy", text: "Copy" });
        const status = el("p", { class: "set-status", id: "theme-status", role: "status" });
        exp.addEventListener("click", () => {
            json.value = JSON.stringify(exportTheme(), null, 2);
            status.textContent = "Exported. Copy it, or save it as a .json file to share.";
        });
        copy.addEventListener("click", async () => {
            try { await navigator.clipboard.writeText(json.value); status.textContent = "Copied."; }
            catch (_) { json.select(); status.textContent = "Selected — press Ctrl+C to copy."; }
        });
        imp.addEventListener("click", () => {
            const r = importTheme(json.value);
            status.textContent = r.ok ? "Imported." : r.why;
        });
        pick.addEventListener("click", () => file.click());
        file.addEventListener("change", async () => {
            const f = file.files && file.files[0];
            file.value = "";
            if (!f) return;
            if (f.size > 64 * 1024) { status.textContent = "That file is too large to be a theme."; return; }
            json.value = await f.text();
            const r = importTheme(json.value);
            status.textContent = r.ok ? "Imported " + f.name + "." : r.why;
        });

        const reset = el("button", { type: "button", class: "danger", id: "set-reset", text: "Reset appearance" });
        reset.addEventListener("click", () => {
            s = { ...DEFAULTS };
            save(); apply(); syncPanel();
        });

        const close = el("button", { type: "button", class: "ghost", id: "settings-close", title: "Close (Esc)", text: "Close" });
        close.addEventListener("click", closePanel);

        const panel = el("div", { class: "panel set-panel", role: "dialog", "aria-modal": "true", "aria-labelledby": "settings-title" },
            el("header", {},
                el("h3", { id: "settings-title", text: "Settings" }),
                el("span", { class: "grow mono", text: "this device only" }),
                close),
            el("div", { class: "set-body" },
                section("Theme", null, themes),
                section("Accent", "One colour for blazes, focus and links. Encryption badges keep their own colours whatever you pick.",
                    el("div", { class: "row" }, accent, el("span", { class: "mono", id: "set-accent-hex" }), accentReset)),
                section("Type", null, fonts, range("textSize", "Message text", "px"), range("uiScale", "Interface scale", "%")),
                section("Messages", null,
                    el("div", { class: "field" }, el("span", { class: "field-label", text: "Layout" }), seg("layout")),
                    el("div", { class: "field" }, el("span", { class: "field-label", text: "Density" }), seg("density")),
                    el("div", { class: "field" }, el("span", { class: "field-label", text: "Avatars" }), seg("avatar")),
                    el("div", { class: "field" }, el("span", { class: "field-label", text: "Timestamps" }), seg("clock"))),
                section("Window", null,
                    range("sidebar", "Sidebar width", "px"),
                    el("div", { class: "field" }, el("span", { class: "field-label", text: "Motion" }), seg("motion"))),
                section("Custom CSS",
                    "Applies to this client only: nobody else sees it, and it is never sent anywhere. " +
                    "It cannot restyle the encryption and safety badges themselves, and Cairn checks that " +
                    "they stay visible — CSS it finds hiding or covering one is switched off. " +
                    "Locked out by your own CSS? Ctrl+Shift+Backspace switches it off.",
                    css,
                    el("div", { class: "row" }, el("label", { class: "check", for: "set-css-on" }, cssOn, el("span", { text: "Enabled" })),
                        el("span", { class: "grow" }), cssOff, cssApply),
                    el("p", { class: "set-status", id: "set-css-status", role: "status" })),
                section("Share a theme",
                    "A theme is colours and layout choices only. Custom CSS is never part of one, so a theme " +
                    "someone sends you cannot carry code or reach the security indicators.",
                    json,
                    el("div", { class: "row" }, exp, copy, el("span", { class: "grow" }), pick, imp),
                    file, status),
                privacy(),
                el("div", { class: "row end" }, reset)));
        sheet.append(panel);
        sheet.addEventListener("click", (ev) => { if (ev.target === sheet) closePanel(); });
        syncPanel();
    }

    function syncPanel() {
        const sheet = $("settings");
        if (!sheet || !sheet.dataset.built) return;
        const active = s.theme === "custom" ? "custom" : s.theme;
        for (const c of sheet.querySelectorAll(".theme-card")) {
            const on = c.dataset.pick === active;
            c.classList.toggle("on", on);
            c.setAttribute("aria-pressed", String(on));
        }
        $("set-custom-card").hidden = s.theme !== "custom";
        const accent = getComputedStyle(html).getPropertyValue("--accent").trim();
        $("set-accent").value = hex(s.accent) || hex(accent) || "#e2a93b";
        $("set-accent-hex").textContent = s.accent ? s.accent : "theme default";
        $("set-accent-reset").disabled = !s.accent;
        const f = $("set-font-" + s.font);
        if (f) f.checked = true;
        for (const key of Object.keys(CHOICES)) {
            const r = $("set-" + key + "-" + s[key]);
            if (r) r.checked = true;
        }
        for (const [key, unit] of [["textSize", "px"], ["uiScale", "%"], ["sidebar", "px"]]) {
            $("set-" + key).value = s[key];
            $("set-" + key + "-out").textContent = s[key] + unit;
        }
        if (document.activeElement !== $("set-css")) $("set-css").value = s.customCss;
        $("set-css-on").checked = s.customCssOn;
        $("set-css-on").disabled = !s.customCss.trim();
        const st = $("set-css-status");
        st.textContent = s.customCssNote || (s.customCssOn ? "Custom CSS is on." : s.customCss.trim() ? "Custom CSS is off." : "");
        st.classList.toggle("warn", !!s.customCssNote);
    }

    function openPanel() {
        build();
        syncPanel();
        $("settings").hidden = false;
        const first = $("settings").querySelector(".theme-card.on") || $("settings-close");
        if (first) first.focus();
    }
    function closePanel() {
        const sheet = $("settings");
        if (sheet) sheet.hidden = true;
    }

    // ---- export / import --------------------------------------------------------

    function exportTheme() {
        const cs = getComputedStyle(html);
        const tokens = {};
        for (const k of TOKENS) {
            const v = hex(cs.getPropertyValue("--" + k).trim());
            if (v) tokens[k] = v;
        }
        for (const k of Object.keys(NUMBERS)) {
            const n = parseFloat(cs.getPropertyValue("--" + k));
            if (Number.isFinite(n)) tokens[k] = n;
        }
        const name = s.theme === "custom" ? "Imported" : (THEMES.find(([id]) => id === s.theme) || [, "Theme"])[1];
        return {
            "cairn-theme": 1,
            name: name + (s.accent ? " (custom accent)" : ""),
            base: s.theme === "custom" ? s.base : s.theme,
            tokens,
            look: {
                font: s.font, textSize: s.textSize, layout: s.layout, density: s.density,
                avatar: s.avatar, sidebar: s.sidebar,
            },
        };
    }

    function importTheme(text) {
        let data;
        try { data = JSON.parse(String(text)); } catch (_) { return { ok: false, why: "That is not valid JSON." }; }
        if (!data || data["cairn-theme"] !== 1) return { ok: false, why: "That is not a Cairn theme (no \"cairn-theme\": 1)." };
        const tokens = cleanTokens(data.tokens);
        if (!tokens) return { ok: false, why: "That theme has no usable colours." };
        const look = data.look && typeof data.look === "object" ? data.look : {};
        // Only the listed look keys are taken; anything else in the file — including any
        // attempt at customCss — is ignored by construction.
        const picked = {};
        for (const k of ["font", "textSize", "layout", "density", "avatar", "sidebar"]) {
            if (k in look) picked[k] = look[k];
        }
        s = sanitize({ ...s, ...picked, theme: "custom", base: data.base, tokens, accent: null });
        save();
        apply();
        syncPanel();
        return { ok: true };
    }

    // ---- wiring -----------------------------------------------------------------

    function wire() {
        const open = $("open-settings");
        if (open) open.addEventListener("click", openPanel);
        const people = $("toggle-people");
        if (people) people.addEventListener("click", () => {
            const on = html.classList.toggle("show-people");
            people.setAttribute("aria-pressed", String(on));
        });
        document.addEventListener("click", (ev) => {
            if (!html.classList.contains("show-people")) return;
            if (ev.target.closest(".people, #toggle-people")) return;
            html.classList.remove("show-people");
            if (people) people.setAttribute("aria-pressed", "false");
        });
        document.addEventListener("keydown", (ev) => {
            if (ev.key === "Escape") {
                if ($("settings") && !$("settings").hidden) closePanel();
                html.classList.remove("show-people");
            }
            // The way back from CSS that made the app unusable, panel included.
            if (ev.key === "Backspace" && ev.ctrlKey && ev.shiftKey && s.customCssOn) {
                ev.preventDefault();
                disableCustomCss("Custom CSS switched off from the keyboard.");
            }
        });

        // Avatars drawn by other code get the same per-person hue.
        for (const a of document.querySelectorAll(".avatar")) tint(a);
        new MutationObserver((records) => {
            for (const r of records) {
                const t = r.target.nodeType === 1 ? r.target : r.target.parentElement;
                if (t && t.closest) tint(t.closest(".avatar"));
                for (const n of r.addedNodes) {
                    if (n.nodeType !== 1) continue;
                    if (n.matches(".avatar")) tint(n);
                    for (const a of n.querySelectorAll(".avatar")) tint(a);
                }
            }
            // Rooms are redrawn on every refresh; let only the first drawing animate in.
            const rooms = $("rooms");
            if (rooms && rooms.children.length && !rooms.dataset.arrived) {
                rooms.dataset.arrived = "1";
                setTimeout(() => rooms.classList.add("settled"), 900);
            }
        }).observe(document.body, { subtree: true, childList: true, characterData: true });

        if (s.customCssOn) startWatching();
        applyCustomCss();
    }

    apply();
    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", wire);
    else wire();

    return {
        decorate, formatTime, checkIndicators, inspectCss, exportTheme, importTheme,
        open: openPanel, close: closePanel,
        get: () => ({ ...s }),
        set,
        THEMES: THEMES.map(([id]) => id),
    };
})();
