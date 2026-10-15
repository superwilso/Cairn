// Spaces: the rail on the far left, and a space's channels in the sidebar.
//
// Presentation only, and the line matters more here than anywhere else in the UI: this file
// shows who may do what in a space, and it decides none of it. Every button below is drawn
// or withheld on a flag Rust handed over — `my_permissions`, `manageable`, `can_send` — and
// those flags are the instance's answer, computed by the same rules that refuse the request
// if the button is pressed anyway (crates/cairn-server/src/state.rs). A UI that worked out
// the role hierarchy itself would be a second copy of the rule that nobody tests.
//
// The tier badge on each channel is Rust's too: derived on this device from the space's
// sealed shape and refused if the instance's listing disagrees. See ADR-011.

const CairnSpaces = (() => {
    const $ = (id) => document.getElementById(id);
    let api = null;           // { invoke, selectRoom, addNotice, fail, short, initials }
    let spaces = [];          // [{ id, name }]
    let active = null;        // the open space's id, or null for Home
    let view = null;          // the open space as Rust described it
    let openChannel = null;

    const has = (perm) => !!view && view.my_permissions.includes(perm);
    const err = (e) => api.fail($("error"), e);

    function bind(deps) {
        api = deps;
        $("rail-home").onclick = () => showHome();
        $("new-space").onclick = () => toggleForm("space-create");
        $("join-space").onclick = () => toggleForm("space-join");
        $("space-create").onsubmit = (ev) => { ev.preventDefault(); createSpace(); };
        $("space-join").onsubmit = (ev) => { ev.preventDefault(); joinSpace(); };
        $("new-channel").onclick = () => toggleForm("channel-create");
        $("channel-create").onsubmit = (ev) => { ev.preventDefault(); createChannel(); };
        $("space-invite").onclick = () => mintInvite();
        $("space-leave").onclick = () => leave();
    }

    function toggleForm(id) {
        const form = $(id);
        const opening = form.hidden;
        for (const f of document.querySelectorAll(".rail-form")) f.hidden = true;
        form.hidden = !opening;
        if (opening) form.querySelector("input").focus();
    }

    // ---- the rail ----------------------------------------------------------

    async function signedIn() {
        await refreshSpaces();
        showHome();
    }

    async function refreshSpaces() {
        try { spaces = (await api.invoke("spaces")) || []; } catch (e) { err(e); spaces = []; }
        const list = $("space-list");
        list.textContent = "";
        for (const s of spaces) {
            const li = document.createElement("li");
            const b = document.createElement("button");
            b.className = "rail-btn space" + (s.id === active ? " active" : "");
            b.dataset.space = s.id;
            b.title = s.name;
            b.setAttribute("aria-label", s.name);
            b.textContent = monogram(s.name);
            b.style.setProperty("--h", hue(s.id));
            b.onclick = () => openSpace(s.id);
            li.append(b);
            list.append(li);
        }
        $("rail-home").classList.toggle("active", active === null);
    }

    // Two letters from the name, as Discord does. Display only; a name is not an identity.
    function monogram(name) {
        const words = String(name).trim().split(/\s+/).filter(Boolean);
        const letters = words.length > 1 ? words[0][0] + words[1][0] : String(name).slice(0, 2);
        return letters.toUpperCase();
    }

    function hue(id) {
        let h = 0;
        for (const c of String(id)) h = (h * 31 + c.charCodeAt(0)) % 360;
        return String(h);
    }

    function showHome() {
        active = null;
        view = null;
        $("home-pane").hidden = false;
        $("space-pane").hidden = true;
        $("space-people").hidden = true;
        document.documentElement.classList.remove("in-space");
        for (const b of document.querySelectorAll("#space-list .rail-btn")) b.classList.remove("active");
        $("rail-home").classList.add("active");
    }

    // ---- one space ---------------------------------------------------------

    async function openSpace(id) {
        active = id;
        await reload();
        $("home-pane").hidden = true;
        $("space-pane").hidden = false;
        document.documentElement.classList.add("in-space");
        $("rail-home").classList.remove("active");
        for (const b of document.querySelectorAll("#space-list .rail-btn")) {
            b.classList.toggle("active", b.dataset.space === id);
        }
    }

    async function reload() {
        if (!active) return;
        try {
            view = await api.invoke("space", { space: active });
            if (!view) throw new Error("no answer for this space");
        } catch (e) {
            // Most likely removed from the space. Say so and go home rather than leave a
            // channel list on screen for a space this account can no longer read.
            err(e);
            active = null;
            await refreshSpaces();
            showHome();
            return;
        }
        render();
    }

    function render() {
        $("space-name").textContent = view.name;
        $("space-name").title = view.name;
        // Rust's sentence, not ours: what the instance can see of a space is a claim about
        // the threat model, and it is made in one place.
        $("space-note").textContent = view.visibility_note;

        // Drawn on the instance's answer. Pressing them without it is refused there anyway.
        $("new-channel").hidden = !has("manage_channels");
        $("space-invite").hidden = !has("invite");
        $("space-leave").hidden = view.i_am_owner;
        $("channel-create").hidden = true;

        const list = $("channels");
        list.textContent = "";
        for (const c of view.channels) {
            const li = document.createElement("li");
            li.dataset.channel = c.id;
            li.className = c.id === openChannel ? "active" : "";

            const tier = document.createElement("span");
            tier.className = "badge " + (c.e2ee ? "ok" : "warn");
            tier.textContent = c.tier;
            tier.title = c.e2ee
                ? "End-to-end encrypted. The instance stores ciphertext it cannot read."
                : "Transport-encrypted. The instance can read this channel.";

            const name = document.createElement("span");
            name.className = "channel-name";
            name.textContent = c.name;

            li.append(tier, name);
            if (!c.can_send) {
                const ro = document.createElement("span");
                ro.className = "chan-flag";
                ro.textContent = "read-only";
                li.append(ro);
            }
            if (!c.joined) {
                const pend = document.createElement("span");
                pend.className = "pending";
                pend.textContent = "waiting";
                pend.title = "In the channel, but not yet in its encrypted group";
                li.append(pend);
            }
            li.onclick = () => api.selectRoom(c.id);
            list.append(li);
        }
        if (view.channels.length === 0) {
            const li = document.createElement("li");
            li.className = "empty";
            li.textContent = has("manage_channels") ? "No channels yet. Make the first." : "No channels you can see.";
            list.append(li);
        }
        renderPeople();
    }

    function renderPeople() {
        $("space-people").hidden = false;
        const list = $("space-members");
        list.textContent = "";
        const roleName = new Map(view.roles.map((r) => [r.id, r]));
        const canKick = has("kick");
        for (const m of view.members) {
            const li = document.createElement("li");
            li.dataset.user = m.user;

            const head = document.createElement("div");
            head.className = "sm-head";
            const av = document.createElement("span");
            av.className = "avatar";
            av.textContent = api.initials(m.user);
            const who = document.createElement("span");
            who.className = "mono who";
            who.textContent = api.short(m.user);
            who.title = m.user;
            head.append(av, who);
            if (m.owner) {
                const own = document.createElement("span");
                own.className = "role-chip owner";
                own.textContent = "owner";
                head.append(own);
            }
            // Kick only where Rust said this member ranks below the viewer *and* the viewer
            // holds `kick`. Both are the instance's facts; neither is worked out here.
            if (canKick && m.manageable) {
                const kick = document.createElement("button");
                kick.className = "ghost kick";
                kick.textContent = "Remove";
                kick.title = "Remove from the space. They lose every channel at once, and cannot rejoin by invite until the bar is lifted.";
                kick.onclick = () => kickMember(m.user);
                head.append(kick);
            }
            li.append(head);

            const chips = document.createElement("div");
            chips.className = "chips";
            for (const id of m.roles) {
                const r = roleName.get(id);
                if (!r) continue;
                const chip = document.createElement("span");
                chip.className = "role-chip";
                chip.style.setProperty("--h", hue(r.id));
                chip.textContent = r.name;
                chip.title = r.permissions.join(", ") || "no permissions";
                if (m.roles_editable && r.manageable) {
                    const x = document.createElement("button");
                    x.className = "chip-x";
                    x.textContent = "×";
                    x.setAttribute("aria-label", "Take " + r.name + " away");
                    x.onclick = () => roleChange("unassign_role", m.user, r.id);
                    chip.append(x);
                }
                chips.append(chip);
            }
            // Only roles Rust marked assignable: below the viewer *and* carrying nothing the
            // viewer lacks. Offering more would only collect refusals.
            const offer = view.roles.filter((r) => r.assignable && !m.roles.includes(r.id));
            if (m.roles_editable && offer.length > 0) {
                const pick = document.createElement("select");
                pick.className = "role-pick";
                pick.setAttribute("aria-label", "Give a role");
                const first = document.createElement("option");
                first.value = "";
                first.textContent = "+ role";
                pick.append(first);
                for (const r of offer) {
                    const o = document.createElement("option");
                    o.value = r.id;
                    o.textContent = r.name;
                    pick.append(o);
                }
                pick.onchange = () => { if (pick.value) roleChange("assign_role", m.user, pick.value); };
                chips.append(pick);
            }
            if (chips.childElementCount > 0) li.append(chips);
            list.append(li);
        }
    }

    // ---- actions -----------------------------------------------------------
    // Each asks Rust, then redraws from Rust's fresh answer rather than patching the screen
    // with what it hoped happened.

    async function createSpace() {
        const name = $("space-create-name").value.trim();
        if (!name) return;
        try {
            const id = await api.invoke("create_space", { name });
            $("space-create-name").value = "";
            $("space-create").hidden = true;
            await refreshSpaces();
            await openSpace(id);
        } catch (e) { err(e); }
    }

    async function joinSpace() {
        const token = $("space-join-token").value.trim();
        if (!token) return;
        try {
            const id = await api.invoke("redeem_space_invite", { token });
            $("space-join-token").value = "";
            $("space-join").hidden = true;
            await refreshSpaces();
            await openSpace(id);
            // Joining grants no keys, as with a room invite. Said so an empty channel does
            // not read as a fault.
            api.addNotice("Joined. In each encrypted channel a member must admit you before it is readable.");
        } catch (e) { err(e); }
    }

    async function createChannel() {
        const name = $("channel-create-name").value.trim();
        if (!name || !active) return;
        try {
            const room = await api.invoke("create_channel", { space: active, name });
            $("channel-create-name").value = "";
            await reload();
            await api.selectRoom(room);
        } catch (e) { err(e); }
    }

    async function mintInvite() {
        try {
            const token = await api.invoke("create_space_invite", { space: active, uses: 1, hours: 24 });
            api.addNotice("Space invite (1 use, 24h) — shown once: " + token);
        } catch (e) { err(e); }
    }

    async function kickMember(user) {
        try {
            await api.invoke("kick", { space: active, user });
            api.addNotice(
                "Removed " + api.short(user) + " from the space. In each encrypted channel " +
                "they still hold the group's keys until someone removes them from it."
            );
            await reload();
        } catch (e) { err(e); }
    }

    async function roleChange(cmd, user, role) {
        try {
            await api.invoke(cmd, { space: active, user, role });
            await reload();
        } catch (e) { err(e); await reload(); }
    }

    async function leave() {
        try {
            await api.invoke("leave_space", { space: active });
            active = null;
            await refreshSpaces();
            showHome();
        } catch (e) { err(e); }
    }

    // ---- hooks from app.js -------------------------------------------------

    // A room was opened. If it is one of this space's channels, mark it and name it.
    function opened(room) {
        openChannel = room;
        for (const li of document.querySelectorAll("#channels li")) {
            li.classList.toggle("active", li.dataset.channel === room);
        }
        const c = view && view.channels.find((x) => x.id === room);
        if (c) {
            $("room-id").textContent = "# " + c.name;
            $("room-id").title = room;
        }
    }

    // The open channel's membership changed — someone admitted, someone removed — so the
    // `waiting` marks may have too.
    function membershipChanged() { if (active) reload(); }

    return { bind, signedIn, opened, membershipChanged, reload };
})();
