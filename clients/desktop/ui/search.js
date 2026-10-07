// Message search, in the sidebar.
//
// Presentation only. The search runs in Rust over this device's own transcripts — the
// query is never sent to the instance — and Rust decides what matched: each hit arrives
// already split into before / matched / after, and this file draws the three parts rather
// than searching the text again with its own idea of case and Unicode.

const CairnSearch = (() => {
    const invoke = (cmd, args) => window.__TAURI__.core.invoke(cmd, args);
    const $ = (id) => document.getElementById(id);
    const DEBOUNCE_MS = 180;

    let hooks = { openRoom: async () => {}, current: () => null, short: (s) => s, onError: () => {} };
    let timer = null;
    let seq = 0;

    function showing(on) {
        $("search-results").hidden = !on;
        $("rooms").hidden = on;
        $("rooms-heading").hidden = on;
    }

    function when(ms) {
        const d = new Date(ms);
        const today = new Date().toDateString() === d.toDateString();
        return today
            ? d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
            : d.toLocaleDateString([], { month: "short", day: "numeric" });
    }

    function draw(results) {
        const list = $("search-hits");
        list.textContent = "";
        for (const hit of results.hits) {
            const li = document.createElement("li");
            const meta = document.createElement("div");
            meta.className = "hit-meta";
            const who = document.createElement("span");
            who.className = "mono";
            who.textContent = hooks.short(hit.sender);
            const where = document.createElement("span");
            where.className = "mono hit-room";
            where.textContent = "in " + hooks.short(hit.room);
            const at = document.createElement("span");
            at.className = "hit-when";
            at.textContent = when(hit.sent_at_ms);
            meta.append(who, where, at);

            // Three text nodes and a <mark>: never innerHTML, since every part of this is
            // somebody's message.
            const text = document.createElement("div");
            text.className = "hit-text";
            const mark = document.createElement("mark");
            mark.textContent = hit.matched;
            text.append(document.createTextNode(hit.before), mark, document.createTextNode(hit.after));

            li.append(meta, text);
            li.tabIndex = 0;
            li.addEventListener("click", () => jump(hit));
            li.addEventListener("keydown", (e) => { if (e.key === "Enter") jump(hit); });
            list.append(li);
        }

        const notes = [];
        if (results.hits.length === 0) notes.push("No messages found.");
        if (results.unsearched.length > 0) {
            const n = results.unsearched.length;
            // Said rather than hidden: a search that silently skipped a room would read as
            // "it was never said there".
            notes.push(
                n + (n === 1 ? " room was" : " rooms were") + " not searched: its disappearing " +
                "timer could not be checked, and an expired message must not come back."
            );
        }
        notes.push("Searched on this device only. The query is never sent to the instance.");
        $("search-note").textContent = notes.join(" ");
    }

    async function run() {
        const query = $("search").value;
        if (!query.trim()) { showing(false); return; }
        const mine = ++seq;
        try {
            const results = await invoke("search", { query });
            // A slower, older search must not overwrite a newer one.
            if (mine !== seq) return;
            showing(true);
            draw(results);
        } catch (e) { hooks.onError(e); }
    }

    async function jump(hit) {
        if (hooks.current() !== hit.room) await hooks.openRoom(hit.room);
        if (!hit.id) return;
        const li = [...document.querySelectorAll("#timeline li.msg[data-id]")].find(
            (l) => l.dataset.id === hit.id && l.dataset.sender === hit.sender
        );
        if (!li) return;
        li.scrollIntoView({ block: "center" });
        li.classList.remove("flash");
        void li.offsetWidth;
        li.classList.add("flash");
    }

    function clear() {
        $("search").value = "";
        seq++;
        showing(false);
    }

    function init(h) {
        hooks = { ...hooks, ...h };
        const input = $("search");
        if (!input) return;
        input.addEventListener("input", () => {
            clearTimeout(timer);
            timer = setTimeout(run, DEBOUNCE_MS);
        });
        input.addEventListener("keydown", (e) => {
            if (e.key === "Escape") { e.stopPropagation(); clear(); input.blur(); }
            if (e.key === "Enter") { clearTimeout(timer); run(); }
        });
    }

    return { init, clear };
})();
