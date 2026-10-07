// Messages in the timeline: drawing them, replying to them, reacting to them.
//
// Presentation only. Rust decides what a reply quotes (from this device's own transcript,
// never from the sender), whose reaction is whose, and what counts as an emoji; this file
// draws what it is handed and forwards what the user did. In particular it never builds a
// quote from text it has on screen — a quote shown here is always one Rust resolved.
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

    let hooks = { me: () => null, short: (s) => s, onError: () => {} };
    let replyingTo = null;

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
        li.className = "msg" + (m.historic ? " historic" : "") + (m.sender === hooks.me() ? " mine" : "");
        // What an `expired` event is measured against; see timer.js.
        li.dataset.sent = m.sent_at_ms;

        const who = document.createElement("span");
        who.className = "mono who";
        who.textContent = hooks.short(m.sender);
        who.title = m.sender;

        const content = document.createElement("div");
        content.className = "content";
        if (m.reply_to) content.append(quote(m.reply_to));
        const body = document.createElement("span");
        body.className = "body";
        // textContent, never innerHTML: a message body is attacker-controlled text and this
        // is the one line standing between that and script execution in the client.
        body.textContent = m.body;
        const reactions = document.createElement("div");
        reactions.className = "reactions";
        content.append(body, reactions);
        li.append(who, content);

        // A message recorded before replies existed has no id and cannot be answered.
        if (m.id) {
            li.dataset.id = m.id;
            li.dataset.sender = m.sender;
            drawReactions(li, m.reactions || []);
            li.append(actions(li, m));
            li.addEventListener("dblclick", (e) => {
                if (e.target.closest(".actions, .reactions, .quote")) return;
                pop(li);
                react(li, HEART);
            });
            // A double-click would otherwise select a word as well as sending a heart.
            li.addEventListener("mousedown", (e) => { if (e.detail > 1) e.preventDefault(); });
            swipeToReply(li, m);
        }
        return li;
    }

    function quote(q) {
        const el = document.createElement("div");
        el.className = "quote";
        const who = document.createElement("span");
        who.className = "mono quote-who";
        who.textContent = hooks.short(q.sender);
        const text = document.createElement("span");
        text.className = "quote-text";
        el.append(who, text);
        if (q.snippet === null || q.snippet === undefined) {
            gone(el);
        } else {
            text.textContent = q.snippet;
            if (q.sent_at_ms !== null && q.sent_at_ms !== undefined) el.dataset.sent = q.sent_at_ms;
            el.title = "Show the original";
            el.addEventListener("click", () => {
                const original = find(q.sender, q.id);
                if (!original) return;
                original.scrollIntoView({ block: "center", behavior: "smooth" });
                original.classList.remove("flash");
                void original.offsetWidth;
                original.classList.add("flash");
            });
        }
        return el;
    }

    // Unavailable is a statement, not an error: the original expired, predates this device,
    // or the reference was never true. Which of those is not something to guess at.
    function gone(el) {
        el.classList.add("gone");
        el.querySelector(".quote-text").textContent = "Original message unavailable";
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
        return bar;
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
            chip.textContent = r.emoji + (r.by.length > 1 ? " " + r.by.length : "");
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
        document.body.append(el);
        document.addEventListener("click", (e) => {
            if (!el.hidden && !el.contains(e.target)) closePicker();
        });
        return el;
    }

    function openPicker(li, anchor) {
        const el = picker();
        el.target = li;
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
        if (ev.kind === "reactions") {
            const li = find(ev.sender, ev.id);
            if (li) drawReactions(li, ev.reactions);
            return true;
        }
        if (ev.kind === "expired") {
            // The messages themselves are timer.js's to remove; a quote of one goes with it,
            // because Rust has already forgotten the text it showed.
            for (const q of document.querySelectorAll("#timeline .quote[data-sent]")) {
                if (Number(q.dataset.sent) <= ev.before_ms) gone(q);
            }
            const replying = replyingTo && find(replyingTo.sender, replyingTo.id);
            if (replyingTo && (!replying || Number(replying.dataset.sent) <= ev.before_ms)) {
                cancelReply();
            }
        }
        return false;
    }

    function init(h) {
        hooks = { ...hooks, ...h };
        const cancel = $("reply-cancel");
        if (cancel) cancel.addEventListener("click", cancelReply);
        document.addEventListener("keydown", (e) => {
            if (e.key !== "Escape") return;
            closePicker();
            cancelReply();
        });
    }

    return { init, render, send, handle, cancelReply, QUICK };
})();
