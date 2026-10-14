// Profiles: avatars, names, the profile card, and the editor. Presentation only.
//
// What a member is called, whether that name looks like somebody else's, and which status
// has expired are all decided in Rust (cairn_client_core::profile) and arrive as views. This
// file draws them. It never decides who someone *is*: the account id is always on the card,
// a name that collides with another is always drawn with its id beside it, and the safety
// panel — the only place that says anything about keys — is opened by id, never by name.
//
// Every string here was chosen by another member. It goes into the page with textContent,
// inside <bdi>, so a right-to-left name cannot reorder the text around it. Rust refuses the
// explicit direction overrides; <bdi> is the belt to that pair of braces.
//
// Images are fetched by (member, slot) and Rust answers only for members whose profile it
// holds in the open room. Nothing here sees a key.

const CairnProfile = (() => {
    const $ = (id) => document.getElementById(id);
    let hooks = { invoke: null, openSafety: () => {}, onError: () => {} };
    let me = null;
    let limits = null;
    const views = new Map();      // user -> ProfileView
    const keys = new Map();       // user -> { verified, key_changed, in_group }
    const urls = new Map();       // `${user}|${slot}|${id}` -> Promise<objectURL|null>

    const invoke = (cmd, args, opts) => hooks.invoke(cmd, args, opts);
    const shortOf = (user) => String(user).replace(/^usr_/, "").slice(0, 8);

    function viewOf(user) {
        return views.get(user) || {
            user, short_id: shortOf(user), tag: String(user).replace(/^usr_/, "").slice(0, 12),
            label: shortOf(user), ambiguous: false, is_me: user === me,
        };
    }

    function el(tag, cls, text) {
        const e = document.createElement(tag);
        if (cls) e.className = cls;
        if (text !== undefined && text !== null) e.textContent = text;
        return e;
    }

    // ---- images --------------------------------------------------------------

    function bytesOf(raw) {
        return raw instanceof ArrayBuffer ? new Uint8Array(raw) : Uint8Array.from(raw);
    }

    function imageUrl(user, slot, image) {
        if (!image) return Promise.resolve(null);
        const key = user + "|" + slot + "|" + image.id;
        if (!urls.has(key)) {
            urls.set(key, invoke("fetch_profile_image", { user, slot })
                .then((raw) => URL.createObjectURL(new Blob([bytesOf(raw)], { type: image.mime })))
                .catch(() => null));
        }
        return urls.get(key);
    }

    function gradient(v) {
        return v && v.colors
            ? "linear-gradient(160deg, " + v.colors[0] + ", " + v.colors[1] + ")"
            : "";
    }

    // An avatar: the member's image, else initials over their colours, else over the theme.
    function avatar(user, size) {
        const a = el("span", "pf-avatar");
        a.dataset.pfUser = user;
        a.dataset.pfSize = size || "";
        if (size) a.style.setProperty("--pf-size", size + "px");
        paintAvatar(a, viewOf(user));
        return a;
    }

    function initials(v) {
        const source = v.display_name || v.nickname ? v.label : v.short_id;
        const letters = [...String(source).trim()].filter((c) => /\p{L}|\p{N}/u.test(c));
        return (letters.slice(0, 2).join("") || "?").toUpperCase();
    }

    function paintAvatar(a, v) {
        a.textContent = "";
        a.style.background = gradient(v);
        a.classList.toggle("pf-colored", !!v.colors);
        a.append(el("span", "pf-initials", initials(v)));
        if (v.avatar) {
            imageUrl(v.user, "avatar", v.avatar).then((url) => {
                if (!url || a.dataset.pfUser !== v.user) return;
                const img = el("img");
                img.alt = "";
                img.src = url;
                a.textContent = "";
                a.append(img);
            });
        }
    }

    // A name, and — when Rust says it looks like someone else's — the id beside it.
    function nameInto(target, v, suffix) {
        target.textContent = "";
        const b = el("bdi", "pf-name", v.label);
        target.append(b);
        if (v.ambiguous) {
            const t = el("span", "pf-tag mono", "#" + v.tag);
            t.title = "Another member's name looks like this one. This is part of their id.";
            target.append(t);
        }
        if (suffix) target.append(el("span", "pf-suffix", suffix));
        target.title = v.user;
        target.dataset.pfUser = v.user;
        target.classList.toggle("pf-named", !!(v.display_name || v.nickname));
    }

    // ---- hooks the rest of the UI calls --------------------------------------

    // Decorate a message's author: their name, and their avatar beside the message.
    function author(li, who, m) {
        nameInto(who, viewOf(m.sender));
        who.classList.add("pf-link");
        who.addEventListener("click", (e) => { e.stopPropagation(); openCard(m.sender, who); });
        const a = avatar(m.sender, 28);
        a.classList.add("pf-link");
        a.addEventListener("click", (e) => { e.stopPropagation(); openCard(m.sender, a); });
        li.prepend(a);
        li.classList.add("pf-msg");
    }

    // Decorate a member-list row. The avatar opens the card; the row itself keeps opening
    // the safety panel, because that is about keys and the card is about presentation.
    function member(li, av, who, m) {
        if (m.profile) views.set(m.user, m.profile);
        keys.set(m.user, { verified: m.verified, key_changed: m.key_changed, in_group: m.in_group });
        const v = viewOf(m.user);
        const fresh = avatar(m.user, 22);
        fresh.classList.add("pf-link");
        fresh.title = "Show profile";
        fresh.addEventListener("click", (e) => { e.stopPropagation(); openCard(m.user, fresh); });
        av.replaceWith(fresh);
        nameInto(who, v, m.role === "owner" ? " · owner" : "");
        who.classList.add("who");
        if (v.status && v.status.emoji) {
            const s = el("span", "pf-status-mini", v.status.emoji);
            s.title = v.status.text || "";
            who.after(s);
        }
    }

    // Redraw every name and avatar on screen from the current views.
    function relabel() {
        for (const n of document.querySelectorAll(".who[data-pf-user], .pf-name-host[data-pf-user]")) {
            const suffix = n.querySelector(".pf-suffix");
            nameInto(n, viewOf(n.dataset.pfUser), suffix ? suffix.textContent : "");
        }
        for (const a of document.querySelectorAll(".pf-avatar[data-pf-user]")) {
            if (a.closest("#pf-editor")) continue;
            paintAvatar(a, viewOf(a.dataset.pfUser));
        }
        paintMe();
        const card = $("pf-card");
        if (card && !card.hidden && card.dataset.user) drawCard(card, viewOf(card.dataset.user));
    }

    function setAll(list) {
        for (const v of list) views.set(v.user, v);
        relabel();
    }

    async function load() {
        try { setAll(await invoke("profiles")); } catch (_) { /* no room open */ }
        try { const mine = await invoke("my_profile"); views.set(mine.user, mine); paintMe(); } catch (_) {}
    }

    function handle(ev) {
        if (ev.kind !== "profiles") return false;
        setAll(ev.profiles);
        return true;
    }

    // ---- the signed-in account, top left -------------------------------------

    function paintMe() {
        if (!me) return;
        const v = viewOf(me);
        const slot = $("avatar");
        if (slot) {
            slot.textContent = "";
            slot.classList.add("pf-me");
            slot.style.background = "";
            const a = avatar(me, 26);
            slot.append(a);
        }
        const who = $("whoami");
        if (who) {
            who.textContent = "";
            who.append(el("bdi", "pf-name", v.label));
            who.title = me + " — edit your profile";
        }
    }

    async function signedIn(user) {
        me = user;
        try { limits = await invoke("profile_limits"); } catch (_) {}
        try { const mine = await invoke("my_profile"); views.set(mine.user, mine); } catch (_) {}
        paintMe();
        const you = document.querySelector(".you");
        if (you && !you.dataset.pfBound) {
            you.dataset.pfBound = "1";
            for (const id of ["avatar", "whoami"]) {
                const n = $(id);
                if (!n) continue;
                n.classList.add("pf-link");
                n.addEventListener("click", () => openEditor());
            }
        }
    }

    // ---- the card ------------------------------------------------------------

    function cardEl() {
        let card = $("pf-card");
        if (card) return card;
        card = el("div", "pf-card pf-floating");
        card.id = "pf-card";
        card.hidden = true;
        card.setAttribute("role", "dialog");
        document.body.append(card);
        document.addEventListener("mousedown", (e) => {
            if (!card.hidden && !card.contains(e.target) && !e.target.closest(".pf-link")) closeCard();
        });
        document.addEventListener("keydown", (e) => { if (e.key === "Escape") { closeCard(); closeEditor(); } });
        return card;
    }

    function closeCard() {
        const card = $("pf-card");
        if (card) { card.hidden = true; delete card.dataset.user; }
    }

    // Lay a profile card out into `card`. Used for the popout and for the editor's preview.
    function drawCard(card, v, opts = {}) {
        card.textContent = "";
        const banner = el("div", "pf-banner");
        banner.style.background = gradient(v) || "";
        if (v.banner) {
            const src = opts.bannerUrl ? Promise.resolve(opts.bannerUrl) : imageUrl(v.user, "banner", v.banner);
            src.then((url) => { if (url) banner.style.backgroundImage = "url(\"" + url + "\")"; });
        }
        card.append(banner);

        const body = el("div", "pf-body");
        const av = opts.avatarUrl !== undefined ? previewAvatar(v, opts.avatarUrl) : avatar(v.user, 76);
        av.classList.add("pf-big");
        body.append(av);

        const names = el("div", "pf-names");
        const title = el("div", "pf-title pf-name-host");
        nameInto(title, v);
        names.append(title);
        if (v.pronouns) names.append(el("div", "pf-pronouns", v.pronouns));
        // The id, in full, every time. This is who they are; the line above is what they
        // chose to be called.
        const id = el("div", "pf-id mono", v.user);
        id.title = "Account id — the name above is chosen by them; this is not";
        names.append(id);
        body.append(names);

        if (v.ambiguous) {
            body.append(el("div", "pf-warn",
                "Another member's name looks like this one. Tell them apart by the id, " +
                "or by comparing safety numbers."));
        }

        if (v.status) {
            const s = el("div", "pf-status");
            if (v.status.emoji) s.append(el("span", "pf-status-emoji", v.status.emoji));
            if (v.status.text) s.append(el("bdi", "", v.status.text));
            body.append(s);
        }

        if (v.about) {
            body.append(el("div", "pf-section", "About me"));
            body.append(el("div", "pf-about", v.about));
        }

        if (!opts.preview) {
            const k = keys.get(v.user);
            const foot = el("div", "pf-foot");
            if (v.is_me) {
                const edit = el("button", "primary", "Edit profile");
                edit.type = "button";
                edit.onclick = () => { closeCard(); openEditor(); };
                foot.append(edit);
            } else {
                const state = el("span", "pf-keys");
                if (k && k.key_changed) {
                    state.classList.add("bad");
                    state.textContent = "Key changed since you verified";
                } else if (k && k.verified) {
                    state.classList.add("ok");
                    state.textContent = "✓ Verified";
                    state.title = "You compared safety numbers with this account";
                } else {
                    state.textContent = k && !k.in_group ? "Not in the encrypted group" : "Not verified";
                }
                foot.append(state);
                if (k && k.in_group) {
                    const safety = el("button", "", "Safety numbers");
                    safety.type = "button";
                    safety.onclick = () => { closeCard(); hooks.openSafety(v.user); };
                    foot.append(safety);
                }
            }
            body.append(foot);
        }
        card.append(body);
    }

    function openCard(user, anchor) {
        const card = cardEl();
        card.dataset.user = user;
        drawCard(card, viewOf(user));
        card.hidden = false;
        const r = anchor.getBoundingClientRect();
        const w = card.offsetWidth, h = card.offsetHeight;
        let left = r.right + 10;
        if (left + w > window.innerWidth - 8) left = r.left - w - 10;
        left = Math.max(8, Math.min(left, window.innerWidth - w - 8));
        const top = Math.max(8, Math.min(r.top - 20, window.innerHeight - h - 8));
        card.style.left = left + "px";
        card.style.top = top + "px";
    }

    // ---- the editor ----------------------------------------------------------

    let draft = null;   // pending image changes: { avatar: {bytes,mime,url}|null|undefined, banner: ... }

    function previewAvatar(v, url) {
        const a = el("span", "pf-avatar");
        a.style.setProperty("--pf-size", "76px");
        a.style.background = gradient(v);
        if (url) {
            const img = el("img");
            img.alt = "";
            img.src = url;
            a.append(img);
        } else {
            a.append(el("span", "pf-initials", initials(v)));
        }
        return a;
    }

    function field(label, input, counter) {
        const wrap = el("label", "pf-field");
        const head = el("span", "pf-label", label);
        if (counter) head.append(counter);
        wrap.append(head, input);
        return wrap;
    }

    function counted(input, max) {
        const c = el("span", "pf-count");
        const update = () => {
            const n = [...input.value].length;
            c.textContent = max ? n + "/" + max : "";
            c.classList.toggle("over", !!max && n > max);
        };
        input.addEventListener("input", update);
        update();
        return c;
    }

    const EXPIRY = [
        ["Don't clear", 0], ["30 minutes", 30 * 60e3], ["1 hour", 3600e3],
        ["4 hours", 4 * 3600e3], ["Today", -1], ["This week", 7 * 24 * 3600e3],
    ];

    function editorEl() {
        let sheet = $("pf-editor");
        if (sheet) return sheet;
        sheet = el("div", "sheet");
        sheet.id = "pf-editor";
        sheet.hidden = true;
        const panel = el("div", "panel pf-editor-panel");
        panel.setAttribute("role", "dialog");
        panel.setAttribute("aria-modal", "true");

        const header = el("header");
        header.append(el("h3", "", "Your profile"));
        header.append(el("span", "grow", "Sent encrypted, only to rooms you are in"));
        const close = el("button", "ghost", "Close");
        close.type = "button";
        close.onclick = closeEditor;
        header.append(close);

        const grid = el("div", "pf-editor-grid");
        const form = el("form", "pf-form");
        form.id = "pf-form";
        const L = limits || {};

        const name = el("input"); name.id = "pf-display-name"; name.maxLength = 64; name.autocomplete = "off";
        const pronouns = el("input"); pronouns.id = "pf-pronouns"; pronouns.maxLength = 80;
        const about = el("textarea"); about.id = "pf-about"; about.rows = 4;
        const c1 = el("input"); c1.type = "color"; c1.id = "pf-color-1";
        const c2 = el("input"); c2.type = "color"; c2.id = "pf-color-2";
        const useColors = el("input"); useColors.type = "checkbox"; useColors.id = "pf-use-colors";
        const emoji = el("input"); emoji.id = "pf-status-emoji"; emoji.maxLength = 16; emoji.placeholder = "🙂";
        const status = el("input"); status.id = "pf-status-text"; status.placeholder = "What are you up to?";
        const expiry = el("select"); expiry.id = "pf-status-expiry";
        for (const [label, ms] of EXPIRY) { const o = el("option", "", label); o.value = String(ms); expiry.append(o); }
        const nick = el("input"); nick.id = "pf-nickname"; nick.placeholder = "Only this room sees it";

        const colours = el("div", "pf-row");
        const useLabel = el("label", "pf-check");
        useLabel.append(useColors, document.createTextNode(" Banner colours"));
        colours.append(useLabel, c1, c2);

        const statusRow = el("div", "pf-row");
        emoji.classList.add("pf-emoji-input");
        statusRow.append(emoji, status);

        const images = el("div", "pf-row pf-images");
        images.append(imagePicker("avatar", "Avatar"), imagePicker("banner", "Banner"));

        form.append(
            field("Display name", name, counted(name, L.name_chars)),
            field("Pronouns", pronouns, counted(pronouns, L.pronouns_chars)),
            field("About me", about, counted(about, L.about_chars)),
            images,
            colours,
            field("Custom status", statusRow, counted(status, L.status_chars)),
            field("Clear status after", expiry),
            field("Nickname in this room", nick, counted(nick, L.name_chars)),
        );
        const err = el("p", "error"); err.id = "pf-error";
        const save = el("button", "primary", "Save");
        save.type = "submit";
        const actions = el("div", "pf-actions");
        actions.append(err, save);
        form.append(actions);

        const previewCol = el("div", "pf-preview-col");
        previewCol.append(el("div", "pf-section", "Preview"));
        const preview = el("div", "pf-card pf-preview");
        preview.id = "pf-preview";
        previewCol.append(preview);
        previewCol.append(el("p", "pf-note",
            "Your name is a label, not an identity. Members still see your account id, and " +
            "anyone checking who you are compares safety numbers, not names."));

        grid.append(form, previewCol);
        panel.append(header, grid);
        sheet.append(panel);
        document.body.append(sheet);

        sheet.addEventListener("click", (e) => { if (e.target === sheet) closeEditor(); });
        form.addEventListener("input", drawPreview);
        form.addEventListener("change", drawPreview);
        form.addEventListener("submit", (e) => { e.preventDefault(); saveEditor(); });
        return sheet;
    }

    function imagePicker(slot, label) {
        const box = el("div", "pf-picker");
        const input = el("input");
        input.type = "file";
        input.accept = "image/png,image/jpeg,image/webp,image/gif";
        input.hidden = true;
        input.id = "pf-" + slot + "-input";
        const choose = el("button", "", "Upload");
        choose.type = "button";
        choose.onclick = () => input.click();
        const remove = el("button", "ghost", "Remove");
        remove.type = "button";
        remove.id = "pf-" + slot + "-remove";
        remove.onclick = () => { draft[slot] = null; drawPreview(); };
        input.onchange = async () => {
            const file = input.files && input.files[0];
            input.value = "";
            if (!file) return;
            try {
                draft[slot] = await shrink(file, slot);
                $("pf-error").textContent = "";
            } catch (e) { $("pf-error").textContent = String(e); }
            drawPreview();
        };
        box.append(el("span", "pf-label", label), choose, remove, input);
        return box;
    }

    // Downscale before sending: every member downloads every image, in every room. A
    // GIF is kept as it is, so an animated avatar stays animated.
    async function shrink(file, slot) {
        const max = (limits && limits.image_bytes) || 1 << 20;
        if (file.type === "image/gif") {
            if (file.size > max) throw "That GIF is larger than " + Math.round(max / 1024) + " KiB.";
            const bytes = new Uint8Array(await file.arrayBuffer());
            return { bytes, mime: "image/gif", url: URL.createObjectURL(file) };
        }
        const bitmap = await createImageBitmap(file);
        const [w, h] = slot === "avatar" ? [256, 256] : [960, 340];
        const scale = Math.max(w / bitmap.width, h / bitmap.height);
        const canvas = document.createElement("canvas");
        canvas.width = w;
        canvas.height = h;
        const g = canvas.getContext("2d");
        const sw = w / scale, sh = h / scale;
        g.drawImage(bitmap, (bitmap.width - sw) / 2, (bitmap.height - sh) / 2, sw, sh, 0, 0, w, h);
        let blob = await new Promise((r) => canvas.toBlob(r, "image/webp", 0.86));
        if (!blob || blob.type !== "image/webp") blob = await new Promise((r) => canvas.toBlob(r, "image/png"));
        if (blob.size > max) throw "That image is still too large after shrinking it.";
        return { bytes: new Uint8Array(await blob.arrayBuffer()), mime: blob.type, url: URL.createObjectURL(blob) };
    }

    function readForm() {
        const value = (id) => $(id).value;
        const ms = Number(value("pf-status-expiry"));
        let expires = null;
        if (ms > 0) expires = Date.now() + ms;
        if (ms === -1) { const d = new Date(); d.setHours(23, 59, 59, 0); expires = d.getTime(); }
        return {
            display_name: value("pf-display-name"),
            pronouns: value("pf-pronouns"),
            about: value("pf-about"),
            colors: $("pf-use-colors").checked ? [value("pf-color-1"), value("pf-color-2")] : null,
            status_emoji: value("pf-status-emoji"),
            status_text: value("pf-status-text"),
            status_expires_at_ms: expires,
        };
    }

    function drawPreview() {
        const base = viewOf(me);
        const f = readForm();
        const nick = $("pf-nickname").value.trim();
        const name = f.display_name.trim();
        const v = {
            ...base,
            display_name: name || null,
            nickname: nick || null,
            label: nick || name || base.short_id,
            ambiguous: false,
            pronouns: f.pronouns.trim() || null,
            about: f.about.trim() || null,
            colors: f.colors,
            status: f.status_emoji.trim() || f.status_text.trim()
                ? { emoji: f.status_emoji.trim() || null, text: f.status_text.trim() || null } : null,
            banner: draft.banner === null ? null : (draft.banner ? { id: "draft" } : base.banner),
        };
        const avatarUrl = draft.avatar === null ? null : draft.avatar ? draft.avatar.url : undefined;
        const opts = { preview: true };
        if (avatarUrl !== undefined) opts.avatarUrl = avatarUrl;
        if (draft.banner) opts.bannerUrl = draft.banner.url;
        drawCard($("pf-preview"), v, opts);
        $("pf-avatar-remove").disabled = !(draft.avatar || (draft.avatar === undefined && base.avatar));
        $("pf-banner-remove").disabled = !(draft.banner || (draft.banner === undefined && base.banner));
    }

    async function openEditor() {
        if (!me) return;
        try { const mine = await invoke("my_profile"); views.set(mine.user, mine); } catch (_) {}
        if (!limits) { try { limits = await invoke("profile_limits"); } catch (_) {} }
        const sheet = editorEl();
        const v = viewOf(me);
        draft = {};
        $("pf-display-name").value = v.display_name || "";
        $("pf-pronouns").value = v.pronouns || "";
        $("pf-about").value = v.about || "";
        $("pf-use-colors").checked = !!v.colors;
        $("pf-color-1").value = v.colors ? v.colors[0] : "#6ea8fe";
        $("pf-color-2").value = v.colors ? v.colors[1] : "#8b7dfb";
        $("pf-status-emoji").value = (v.status && v.status.emoji) || "";
        $("pf-status-text").value = (v.status && v.status.text) || "";
        $("pf-status-expiry").value = "0";
        $("pf-nickname").value = v.nickname || "";
        $("pf-nickname").disabled = !hooks.roomOpen();
        $("pf-error").textContent = "";
        sheet.hidden = false;
        drawPreview();
        $("pf-display-name").focus();
    }

    function closeEditor() {
        const sheet = $("pf-editor");
        if (sheet) sheet.hidden = true;
    }

    // The header value is ASCII JSON, as attachments.js does it for filenames.
    function header(obj) {
        return JSON.stringify(obj).replace(/[\u007f-￿]/g,
            (c) => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0"));
    }

    async function saveEditor() {
        const err = $("pf-error");
        err.textContent = "";
        try {
            let v = await invoke("set_profile", { edit: readForm() });
            for (const slot of ["avatar", "banner"]) {
                if (draft[slot] === null) {
                    v = await invoke("clear_profile_image", { slot });
                } else if (draft[slot]) {
                    v = await invoke("set_profile_image", draft[slot].bytes, {
                        headers: { "x-cairn-image": header({ slot, mime: draft[slot].mime }) },
                    });
                }
            }
            if (hooks.roomOpen()) {
                const nick = $("pf-nickname").value.trim();
                if ((nick || null) !== (viewOf(me).nickname || null)) {
                    v = await invoke("set_nickname", { nickname: nick || null });
                }
            }
            views.set(v.user, v);
            closeEditor();
            await load();
            relabel();
        } catch (e) {
            // Rust's sentence, verbatim: it names the field and the rule.
            err.textContent = String(e);
        }
    }

    function init(h) {
        hooks = { roomOpen: () => true, ...hooks, ...h };
    }

    return { init, signedIn, load, handle, author, member, openCard, openEditor, relabel };
})();
