// Disappearing messages — the control in the room header, and the notices it leaves.
//
// Presentation only. The timer lives on the instance; Rust reads it, sets it, re-reads it
// while polling, deletes expired messages from this device's transcript, and tells this file
// which messages to take off the screen (`expired` events). Nothing here decides what has
// expired — it removes what Rust says has gone.
//
// Uses `addNotice` from app.js, which is loaded after this file but long before anything
// here runs.

const CairnTimer = (() => {
    const invoke = (cmd, args) => window.__TAURI__.core.invoke(cmd, args);
    const select = () => document.getElementById("room-timer");

    const MINUTE = 60_000;
    const HOUR = 60 * MINUTE;
    const DAY = 24 * HOUR;
    const CHOICES = [
        [5 * MINUTE, "5 minutes"],
        [HOUR, "1 hour"],
        [DAY, "1 day"],
        [7 * DAY, "1 week"],
    ];

    // Anything another client set that is not one of the presets — the CLI takes seconds —
    // still has to read as a duration rather than a raw number of milliseconds.
    function describe(ms) {
        if (ms === null || ms === undefined) return "off";
        const known = CHOICES.find(([v]) => v === ms);
        if (known) return known[1];
        const units = [[7 * DAY, "week"], [DAY, "day"], [HOUR, "hour"], [MINUTE, "minute"], [1000, "second"]];
        for (const [size, name] of units) {
            if (ms >= size && ms % size === 0) {
                const n = ms / size;
                return n + " " + name + (n === 1 ? "" : "s");
            }
        }
        return (ms / 1000).toFixed(1) + " seconds";
    }

    // The option list is rebuilt rather than patched so a non-preset value from another
    // client gets an entry of its own, and disappears again once it is no longer in force.
    function render(ttl) {
        const el = select();
        el.textContent = "";
        const off = new Option("Off", "");
        el.append(off);

        // **The label is the warning.** The instance measures every stored message against
        // the current timer, so turning one on deletes messages already older than it — not
        // only future ones. That has to be visible *before* a value is picked, and an open
        // dropdown is the one place it certainly is. See
        // crates/cairn-server/tests/disappearing_session.rs, which fails if it stops being
        // true.
        const group = document.createElement("optgroup");
        group.label = "Also deletes older messages already sent";
        for (const [value, label] of CHOICES) group.append(new Option(label, String(value)));
        if (ttl !== null && !CHOICES.some(([v]) => v === ttl)) {
            group.append(new Option(describe(ttl), String(ttl)));
        }
        el.append(group);

        el.value = ttl === null ? "" : String(ttl);
        el.disabled = false;
        const on = ttl !== null;
        el.parentElement.classList.toggle("on", on);
        el.parentElement.title = on
            ? "Messages in this room disappear " + describe(ttl) + " after they are sent — " +
              "from the instance and from members' devices. Anyone in the room can still " +
              "have kept a copy."
            : "Disappearing messages are off.";
    }

    async function load() {
        try {
            render(await invoke("room_timer"));
        } catch (_) {
            render(null);
            select().disabled = true;
        }
    }

    async function choose() {
        const raw = select().value;
        const asked = raw === "" ? null : Number(raw);
        try {
            const now = await invoke("set_room_timer", { ttlMs: asked });
            render(now);
            if (now === null) {
                addNotice("You turned disappearing messages off. New messages are kept.");
            } else {
                addNotice(
                    "You set disappearing messages to " + describe(now) + ". Anything older — " +
                    "including messages sent before now — is deleted from the instance and " +
                    "from members' devices. Anyone in the room can still have kept a copy."
                );
            }
        } catch (e) {
            // Put the control back to what is actually in force rather than what was asked.
            await load();
            const err = document.getElementById("error");
            if (err) err.textContent = String(e);
        }
    }

    function init() {
        const el = select();
        if (!el) return;
        el.onchange = choose;
        render(null);
        el.disabled = true;
    }

    // Returns true when the event was this module's to handle.
    function handle(ev) {
        if (ev.kind === "timer") {
            render(ev.ttl_ms);
            // Unattributed on purpose: the instance does not say who changed it, and a name
            // taken from a message would be that sender's claim.
            addNotice(
                ev.ttl_ms === null
                    ? "Disappearing messages were turned off."
                    : "Disappearing messages are now " + describe(ev.ttl_ms) +
                      ". Older messages, including ones already sent, are deleted."
            );
            return true;
        }
        if (ev.kind === "expired") {
            // Rust has already deleted these from the transcript on disk.
            for (const li of document.querySelectorAll("#timeline li.msg[data-sent]")) {
                if (Number(li.dataset.sent) <= ev.before_ms) li.remove();
            }
            return true;
        }
        return false;
    }

    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
    else init();

    return { load, handle, describe };
})();
