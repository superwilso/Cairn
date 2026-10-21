// Messages in the timeline: drawing them, replying to them, reacting to them, and editing
// and deleting your own.
//
// Presentation only. Rust decides what a reply quotes (from this device's own transcript,
// never from the sender), whose reaction is whose, what counts as an emoji, which messages
// may be edited or deleted (`can_edit`, `can_delete`), what an edited message now says and
// what it said before; this file draws what it is handed and forwards what the user did. In
// particular it never builds a quote from text it has on screen — a quote shown here is
// always one Rust resolved, including after an edit or a delete.
//
// The gestures follow the messaging apps people already know: hover a message for react
// and reply buttons, double-click it to send a heart, swipe it right on a touch screen to
// reply.

const CairnMessages = (() => {
    const invoke = (cmd, args) => window.__TAURI__.core.invoke(cmd, args);
    const $ = (id) => document.getElementById(id);

    // Escaped rather than literal so the file's encoding cannot mangle them.
    const QUICK = ["❤️", "\u{1F602}", "\u{1F62E}", "\u{1F622}", "\u{1F621}", "\u{1F44D}"];
    const HEART = QUICK[0];
    const SWIPE_PX = 56;

    let hooks = { me: () => null, short: (s) => s, onError: () => {}, author: () => {} };
    let replyingTo = null;

    // What delete-for-everyone is, said before the user commits to it. It is a request:
    // honest clients remove the message, and nothing can make a modified one do so.
    const DELETE_WARNING =
        "Removes it from your devices and asks everyone else's to remove it too. " +
        "Honest Cairn clients do. A modified client, a screenshot, or a report already " +
        "filed keeps it.";

    const find = (sender, id) =>
        [...document.querySelectorAll("#timeline li.msg[data-id]")].find(
            (li) => li.dataset.id === id && li.dataset.sender === sender
        );

    function icon(name) {
        const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
        svg.setAttribute("width", "15");
        svg.setAttribute("height", "15");
        const use = document.createElementNS("http://www.w3.org/2000/svg", "use");
        use.setAttribute("href", "#" + name);
        svg.append(use);
        return svg;
    }

    function render(m) {
        const li = document.createElement("li");
        li.className = "msg" + (m.historic ? " historic" : "") + (m.sender === hooks.me() ? " mine" : "")
            + (m.attachment ? " with-attachment" : "") + (m.deleted ? " deleted" : "");
        // What an `expired` event is measured against; see timer.js.
        li.dataset.sent = m.sent_at_ms;

        const who = document.createElement("span");
        who.className = "mono who";
        who.textContent = hooks.short(m.sender);
        who.title = m.sender;

        const content = document.createElement("div");
        content.className = "content";
        if (m.reply_to && !m.deleted) content.append(quote(m.reply_to));
        let body;
        const emoji = typeof CairnEmoji !== "undefined" ? CairnEmoji : null;
        if (m.deleted) {
            // Rust has already removed the text from this device; there is nothing to show.
            body = document.createElement("span");
            body.className = "body tombstone";
            body.textContent = m.sender === hooks.me() ? "You deleted this message" : "Message deleted";
        } else if (m.sticker && emoji) {
            // Drawn from this device's copy of the room's set. The body is `:name:`, shown
            // instead until the set arrives — never fetched by name.
            body = emoji.renderSticker(m.sticker, m.body);
            body.classList.add("body");
            li.classList.add("with-sticker");
        } else if (m.attachment) {
            // The body of an attachment message is its filename, for clients that cannot show
            // the attachment; the attachment's own caption already says it.
            body = CairnAttach.render(m.attachment);
            body.classList.add("body");
        } else {
            body = document.createElement("span");
            body.className = "body";
            // textContent, never innerHTML: a message body is attacker-controlled text and
            // this is the one line standing between that and script execution in the client.
            // emoji.js builds text nodes too, with `:name:` drawn from the local cache.
            if (emoji) {
                const frag = emoji.renderText(m.body);
                if (frag.jumbo) body.classList.add("ce-jumbo");
                body.append(frag);
            } else {
                body.textContent = m.body;
            }
        }
        const reactions = document.createElement("div");
        reactions.className = "reactions";
        content.append(body);
        if (m.edited_at_ms !== null && m.edited_at_ms !== undefined && !m.deleted) {
            content.append(editedMarker(m));
        }
        // A link card, already vetted by Rust against this message's own text.
        if (m.card && typeof CairnLinkCards !== "undefined") {
            content.append(CairnLinkCards.render(m.card));
            li.classList.add("with-card");
        }
        content.append(reactions);
        li.append(who, content);
        // Name and avatar are profile.js's to draw.
        hooks.author(li, who, m);

        // A message recorded before replies existed has no id and cannot be answered.
        if (m.id) {
            li.dataset.id = m.id;
            li.dataset.sender = m.sender;
        }
        if (m.id && !m.deleted) {
            drawReactions(li, m.reactions || []);
            li.append(actions(li, m));
            li.addEventListener("dblclick", (e) => {
                if (e.target.closest(".actions, .reactions, .quote, .edit-box, .delete-confirm, .edited-wrap")) return;
                pop(li);
                react(li, HEART);
            });
            // A double-click would otherwise select a word as well as sending a heart.
            li.addEventListener("mousedown", (e) => { if (e.detail > 1) e.preventDefault(); });
            swipeToReply(li, m);
        }
        return li;
    }

    // "(edited)", which opens what the message said before. The versions are Rust's, as this
    // device received them.
    function editedMarker(m) {
        const wrap = document.createElement("div");
        wrap.className = "edited-wrap";
        const mark = document.createElement("button");
        mark.type = "button";
        mark.className = "edited";
        mark.textContent = "(edited)";
        const when = new Date(Number(m.edited_at_ms));
        mark.title = "Edited " + (Number.isNaN(when.getTime()) ? "" : when.toLocaleString()) +
            " — show earlier versions";
        mark.setAttribute("aria-expanded", "false");
        const list = document.createElement("ol");
        list.className = "revisions";
        list.hidden = true;
        for (const r of m.revisions || []) {
            const item = document.createElement("li");
            const t = document.createElement("time");
            const at = new Date(Number(r.at_ms));
            t.textContent = Number.isNaN(at.getTime()) ? "" : at.toLocaleString();
            const text = document.createElement("span");
            text.className = "revision-text";
            text.textContent = r.body;
            item.append(t, text);
            list.append(item);
        }
        mark.addEventListener("click", (e) => {
            e.stopPropagation();
            list.hidden = !list.hidden;
            mark.setAttribute("aria-expanded", String(!list.hidden));
        });
        wrap.append(mark, list);
        return wrap;
    }

    function quote(q) {
        const el = document.createElement("div");
        el.className = "quote";
        el.dataset.refSender = q.sender;
        el.dataset.refId = q.id;
        const who = document.createElement("span");
        who.className = "mono quote-who";
        who.textContent = hooks.short(q.sender);
        const text = document.createElement("span");
        text.className = "quote-text";
        el.append(who, text);
        el.addEventListener("click", () => {
            if (el.classList.contains("gone")) return;
            const original = find(q.sender, q.id);
            if (!original) return;
            original.scrollIntoView({ block: "center", behavior: "smooth" });
            original.classList.remove("flash");
            void original.offsetWidth;
            original.classList.add("flash");
        });
        fillQuote(el, q);
        return el;
    }

    function fillQuote(el, q) {
        el.classList.remove("gone", "deleted");
        if (q.deleted) {
            gone(el, "Original message was deleted");
            el.classList.add("deleted");
        } else if (q.snippet === null || q.snippet === undefined) {
            gone(el);
        } else {
            el.querySelector(".quote-text").textContent = q.snippet + (q.edited ? " (edited)" : "");
            if (q.sent_at_ms !== null && q.sent_at_ms !== undefined) el.dataset.sent = q.sent_at_ms;
            el.title = "Show the original";
        }
    }

    // Unavailable is a statement, not an error: the original expired, predates this device,
    // or the reference was never true. Which of those is not something to guess at.
    function gone(el, why) {
        el.classList.add("gone");
        el.querySelector(".quote-text").textContent = why || "Original message unavailable";
        el.title = "";
        delete el.dataset.sent;
    }

    function actions(li, m) {
        const bar = document.createElement("div");
        bar.className = "actions";
        const reactBtn = document.createElement("button");
        reactBtn.type = "button";
        reactBtn.title = "React";
        reactBtn.setAttribute("aria-label", "React");
        reactBtn.className = "act-react";
        reactBtn.append(icon("i-react"));
        reactBtn.addEventListener("click", (e) => { e.stopPropagation(); openPicker(li, reactBtn); });
        const replyBtn = document.createElement("button");
        replyBtn.type = "button";
        replyBtn.title = "Reply";
        replyBtn.setAttribute("aria-label", "Reply");
        replyBtn.className = "act-reply";
        replyBtn.append(icon("i-reply"));
        replyBtn.addEventListener("click", () => startReply(m));
        bar.append(reactBtn, replyBtn);
        // Offered only where Rust said so: an edit or delete it would refuse, or that every
        // recipient would drop, is not a button.
        if (m.can_edit) {
            const editBtn = button("act-edit", "Edit", "i-edit");
            editBtn.addEventListener("click", (e) => { e.stopPropagation(); startEdit(li, m); });
            bar.append(editBtn);
        }
        if (m.can_delete) {
            const delBtn = button("act-delete", "Delete for everyone", "i-delete");
            delBtn.addEventListener("click", (e) => { e.stopPropagation(); confirmDelete(li, m); });
            bar.append(delBtn);
        }
        return bar;
    }

    function button(cls, label, iconName) {
        const b = document.createElement("button");
        b.type = "button";
        b.title = label;
        b.setAttribute("aria-label", label);
        b.className = cls;
        b.append(icon(iconName));
        return b;
    }

    // ---- editing and deleting your own -------------------------------------------

    function startEdit(li, m) {
        if (li.querySelector(".edit-box")) return;
        const body = li.querySelector(".content > .body");
        const box = document.createElement("form");
        box.className = "edit-box";
        const input = document.createElement("textarea");
        input.className = "edit-input";
        input.rows = 1;
        input.value = m.body;
        input.setAttribute("aria-label", "Edit message");
        const hint = document.createElement("span");
        hint.className = "edit-hint";
        hint.textContent = "Enter to save · Esc to cancel · everyone will see the earlier version";
        const save = document.createElement("button");
        save.type = "submit";
        save.className = "primary";
        save.textContent = "Save";
        const cancel = document.createElement("button");
        cancel.type = "button";
        cancel.className = "ghost";
        cancel.textContent = "Cancel";
        const row = document.createElement("div");
        row.className = "edit-row";
        row.append(hint, cancel, save);
        box.append(input, row);
        if (body) body.hidden = true;
        body ? body.after(box) : li.querySelector(".content").prepend(box);
        li.classList.add("editing");
        const close = () => { box.remove(); if (body) body.hidden = false; li.classList.remove("editing"); };
        cancel.addEventListener("click", close);
        input.addEventListener("keydown", (e) => {
            if (e.key === "Escape") { e.stopPropagation(); close(); }
            if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); box.requestSubmit(); }
        });
        box.addEventListener("submit", async (e) => {
            e.preventDefault();
            const text = input.value;
            if (text === m.body) { close(); return; }
            if (!text.trim()) { hooks.onError("An edit needs some text. To remove a message, delete it."); return; }
            try {
                apply(await invoke("edit_message", { id: m.id, text }));
            } catch (err) { hooks.onError(err); close(); }
        });
        input.focus();
        input.setSelectionRange(input.value.length, input.value.length);
    }

    function confirmDelete(li, m) {
        if (li.querySelector(".delete-confirm")) return;
        const bar = document.createElement("div");
        bar.className = "delete-confirm";
        bar.setAttribute("role", "alertdialog");
        bar.setAttribute("aria-label", "Delete for everyone?");
        const text = document.createElement("p");
        const strong = document.createElement("strong");
        strong.textContent = "Delete for everyone? ";
        text.append(strong, document.createTextNode(DELETE_WARNING));
        const cancel = document.createElement("button");
        cancel.type = "button";
        cancel.className = "ghost";
        cancel.textContent = "Keep it";
        const go = document.createElement("button");
        go.type = "button";
        go.className = "danger";
        go.textContent = "Delete";
        const row = document.createElement("div");
        row.className = "edit-row";
        row.append(cancel, go);
        bar.append(text, row);
        li.querySelector(".content").append(bar);
        cancel.addEventListener("click", (e) => { e.stopPropagation(); bar.remove(); });
        go.addEventListener("click", async (e) => {
            e.stopPropagation();
            try { apply(await invoke("delete_message", { id: m.id })); }
            catch (err) { hooks.onError(err); bar.remove(); }
        });
        cancel.focus();
    }

    // Redraw a message Rust says changed, and every quote of it, with what Rust resolved.
    // In place: the avatar, time and grouping around it are the original message's.
    function apply(revised) {
        const m = revised.message;
        const old = find(m.sender, m.id);
        if (old) {
            const fresh = render({ ...m, historic: old.classList.contains("historic") });
            for (const part of [".content", ".actions"]) {
                const was = old.querySelector(":scope > " + part);
                const now = fresh.querySelector(":scope > " + part);
                if (was && now) was.replaceWith(now);
                else if (was) was.remove();
                else if (now) old.append(now);
            }
            old.classList.toggle("deleted", !!m.deleted);
            old.classList.remove("editing");
        }
        for (const q of document.querySelectorAll("#timeline .quote")) {
            if (q.dataset.refSender === m.sender && q.dataset.refId === m.id) fillQuote(q, revised.quote);
        }
        if (m.deleted && replyingTo && replyingTo.sender === m.sender && replyingTo.id === m.id) {
            cancelReply();
        }
    }

    function drawReactions(li, list) {
        const box = li.querySelector(".reactions");
        if (!box) return;
        box.textContent = "";
        const me = hooks.me();
        for (const r of list) {
            const chip = document.createElement("button");
            chip.type = "button";
            const mine = r.by.includes(me);
            chip.className = "chip" + (mine ? " mine" : "");
            // A room emoji is drawn from the local cache; anything else is text.
            if (typeof CairnEmoji !== "undefined") chip.append(CairnEmoji.chip(r.emoji));
            else chip.append(document.createTextNode(r.emoji));
            if (r.by.length > 1) chip.append(document.createTextNode(" " + r.by.length));
            chip.title = r.by.map((u) => (u === me ? "you" : hooks.short(u))).join(", ") +
                (mine ? " — click to remove yours" : "");
            // Clicking your own chip takes it back; clicking someone else's adds the same.
            chip.addEventListener("click", () => react(li, mine ? null : r.emoji));
            box.append(chip);
        }
    }

    async function react(li, emoji) {
        try {
            const now = await invoke("react", { sender: li.dataset.sender, id: li.dataset.id, emoji });
            drawReactions(li, now);
        } catch (e) { hooks.onError(e); }
    }

    // The heart that blooms on a double-click, so the gesture visibly did something before
    // the round trip to Rust comes back.
    function pop(li) {
        const p = document.createElement("span");
        p.className = "pop";
        p.textContent = HEART;
        li.append(p);
        p.addEventListener("animationend", () => p.remove());
    }

    // ---- the emoji picker ----------------------------------------------------

    function picker() {
        let el = $("react-picker");
        if (el) return el;
        el = document.createElement("div");
        el.id = "react-picker";
        el.setAttribute("role", "menu");
        el.hidden = true;
        for (const emoji of QUICK) {
            const b = document.createElement("button");
            b.type = "button";
            b.textContent = emoji;
            b.setAttribute("role", "menuitem");
            b.addEventListener("click", () => {
                const li = el.target;
                closePicker();
                if (li) react(li, emoji);
            });
            el.append(b);
        }
        // Everything else — the full set, search, and the room's own emoji — is emoji.js's.
        if (typeof CairnEmoji !== "undefined") {
            const more = document.createElement("button");
            more.type = "button";
            more.className = "more";
            more.textContent = "+";
            more.title = "More emoji";
            more.setAttribute("aria-label", "More emoji");
            more.setAttribute("role", "menuitem");
            more.addEventListener("click", (e) => {
                e.stopPropagation();
                const li = el.target;
                const anchor = el.anchor;
                closePicker();
                if (!li) return;
                CairnEmoji.open({ anchor: anchor || li, onPick: (emoji) => react(li, emoji) });
            });
            el.append(more);
        }
        document.body.append(el);
        document.addEventListener("click", (e) => {
            if (!el.hidden && !el.contains(e.target)) closePicker();
        });
        return el;
    }

    function openPicker(li, anchor) {
        const el = picker();
        el.target = li;
        el.anchor = anchor;
        el.hidden = false;
        const a = anchor.getBoundingClientRect();
        const w = el.offsetWidth;
        el.style.left = Math.max(8, Math.min(window.innerWidth - w - 8, a.right - w)) + "px";
        el.style.top = Math.max(8, a.top - el.offsetHeight - 6) + "px";
        el.querySelector("button").focus();
    }

    function closePicker() {
        const el = $("react-picker");
        if (el) { el.hidden = true; el.target = null; }
    }

    // ---- replying ------------------------------------------------------------

    function swipeToReply(li, m) {
        let start = null;
        li.addEventListener("pointerdown", (e) => {
            // Touch and pen only: with a mouse, dragging is how text gets selected.
            if (e.pointerType === "mouse") return;
            start = { x: e.clientX, y: e.clientY };
        });
        li.addEventListener("pointermove", (e) => {
            if (!start) return;
            const dx = e.clientX - start.x;
            if (Math.abs(e.clientY - start.y) > 30) { reset(); return; }
            li.style.transform = "translateX(" + Math.max(0, Math.min(dx, SWIPE_PX * 1.4)) + "px)";
            li.classList.toggle("swipe-ready", dx >= SWIPE_PX);
        });
        const finish = (e) => {
            if (!start) return;
            const dx = e.clientX - start.x;
            reset();
            if (dx >= SWIPE_PX) startReply(m);
        };
        const reset = () => {
            start = null;
            li.style.transform = "";
            li.classList.remove("swipe-ready");
        };
        li.addEventListener("pointerup", finish);
        li.addEventListener("pointercancel", reset);
    }

    function startReply(m) {
        replyingTo = { sender: m.sender, id: m.id };
        const bar = $("reply-bar");
        bar.querySelector(".reply-who").textContent =
            m.sender === hooks.me() ? "yourself" : hooks.short(m.sender);
        // A preview of what the user is about to answer, from their own screen. What the
        // recipients see is resolved by Rust from their transcripts, not from this.
        bar.querySelector(".reply-text").textContent = m.body;
        bar.hidden = false;
        $("text").focus();
    }

    function cancelReply() {
        replyingTo = null;
        const bar = $("reply-bar");
        if (bar) bar.hidden = true;
    }

    // Send the composer's text — as a reply when one is being written. Returns the message
    // as Rust recorded it, for the timeline.
    async function send(text) {
        const view = replyingTo
            ? await invoke("reply", { text, sender: replyingTo.sender, id: replyingTo.id })
            : await invoke("send", { text });
        cancelReply();
        return view;
    }

    // Returns true when the event was this module's alone.
    function handle(ev) {
        if (ev.kind === "updated") {
            apply(ev);
            return true;
        }
        if (ev.kind === "reactions") {
            const li = find(ev.sender, ev.id);
            if (li) drawReactions(li, ev.reactions);
            return true;
        }
        if (ev.kind === "expired") {
            // The messages themselves are timer.js's to remove; a quote of one goes with it,
            // because Rust has already forgotten the text it showed.
            for (const q of document.querySelectorAll("#timeline .quote[data-sent]")) {
                if (Number(q.dataset.sent) <= ev.before_ms && !q.classList.contains("gone")) gone(q);
            }
            const replying = replyingTo && find(replyingTo.sender, replyingTo.id);
            if (replyingTo && (!replying || Number(replying.dataset.sent) <= ev.before_ms)) {
                cancelReply();
            }
        }
        return false;
    }

    // ---- keeping the newest message in view ------------------------------------
    //
    // A photo's bytes arrive after its message is drawn, so it grows from a placeholder to
    // its real height after the timeline has already scrolled to the bottom — and pushes
    // the newest messages out of view. Anything else that grows late (audio controls, a
    // reply bar, the call stage shrinking the timeline) does the same.
    //
    // So: whether the reader is at the bottom is decided only when *they* scroll, and while
    // they are, any change of size keeps them there. Someone who scrolled up to read history
    // is never moved. Measured by ResizeObserver, not timers, so it holds however slowly the
    // bytes arrive.
    const PIN_PX = 48;
    let pinned = true;
    // New messages that arrived while the reader was up in the history. They are counted on
    // a button rather than scrolled to: a message landing should not take someone's place.
    let unseen = 0;
    let jump = null;

    function showJump() {
        if (!jump) return;
        jump.hidden = unseen === 0;
        jump.textContent = unseen === 1 ? "1 new message \u2193" : unseen + " new messages \u2193";
    }

    function toBottom(timeline) {
        pinned = true;
        unseen = 0;
        showJump();
        timeline.scrollTop = timeline.scrollHeight;
    }

    // Called by the app for every message or notice it appends. The reader's own messages
    // always bring them down to it; anything else only does if they were already there.
    function arrived(li, mine) {
        const timeline = $("timeline");
        if (!timeline) return;
        if (pinned || mine) {
            toBottom(timeline);
            li.scrollIntoView({ block: "end" });
        } else {
            unseen += 1;
            showJump();
        }
    }

    function follow(timeline) {
        const atBottom = () =>
            timeline.scrollHeight - timeline.scrollTop - timeline.clientHeight <= PIN_PX;
        // Only an upward scroll unpins. A scroll event is dispatched a frame after the
        // scroll, and if a photo grew in between, the bottom has moved away from a reader who
        // never moved: judging by distance alone unpinned them under load. Growth, scroll
        // anchoring and our own scrolling all move down; leaving the bottom means moving up.
        let lastTop = timeline.scrollTop;
        timeline.addEventListener("scroll", () => {
            const top = timeline.scrollTop;
            if (atBottom()) {
                pinned = true;
                if (unseen) { unseen = 0; showJump(); }
            } else if (top < lastTop) pinned = false;
            lastTop = top;
        }, { passive: true });
        const sizes = new ResizeObserver(() => {
            if (pinned) timeline.scrollTop = timeline.scrollHeight;
            // Content that shrank (a font swapping in) clamps scrollTop upward without anyone
            // scrolling. Recording where this left it means that clamp is not later mistaken
            // for the reader moving up — which a probe under load showed it was.
            lastTop = timeline.scrollTop;
        });
        sizes.observe(timeline);
        new MutationObserver((records) => {
            for (const r of records) {
                for (const n of r.addedNodes) if (n.nodeType === 1) sizes.observe(n);
                for (const n of r.removedNodes) if (n.nodeType === 1) sizes.unobserve(n);
            }
            // A cleared timeline is a newly opened room, which starts at its newest message.
            if (!timeline.firstElementChild) { pinned = true; lastTop = 0; unseen = 0; showJump(); }
        }).observe(timeline, { childList: true });

        jump = document.createElement("button");
        jump.type = "button";
        jump.id = "jump-new";
        jump.className = "jump-new";
        jump.hidden = true;
        jump.addEventListener("click", () => toBottom(timeline));
        timeline.after(jump);
    }

    function init(h) {
        hooks = { ...hooks, ...h };
        const timeline = $("timeline");
        if (timeline) follow(timeline);
        const cancel = $("reply-cancel");
        if (cancel) cancel.addEventListener("click", cancelReply);
        document.addEventListener("keydown", (e) => {
            if (e.key !== "Escape") return;
            closePicker();
            cancelReply();
        });
    }

    return { init, render, send, handle, cancelReply, arrived, QUICK };
})();
