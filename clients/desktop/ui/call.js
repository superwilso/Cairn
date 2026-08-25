// Cairn calls — WebRTC mesh over the encrypted signalling transport.
//
// ## What is here and what is not
//
// This file negotiates peer connections and moves media. It never decides *who* may be in
// a call, never touches a key, and never talks to the network directly: every signal goes
// out through `invoke("signal", ...)` and comes back as a `signal` event from `poll`, both
// of which ride inside the encrypted message body. The instance relays ciphertext and never
// sees an SDP offer. See crates/cairn-client-core/src/call.rs.
//
// ## Who offers
//
// Glare — both peers offering at once — is the classic mesh bug, and it presents as "the
// call connects for one person". The rule here is deterministic and needs no negotiation:
// **the peer with the lexicographically smaller user id sends the offer.** Both sides
// compute the same answer from ids they already have.
//
// For that rule to fire, both sides must know the other exists. A newcomer broadcasts
// `join`; everyone already in the call replies with a `join` addressed *to the newcomer*.
// That ack is what tells a newcomer the roster — without it, a newcomer with a smaller id
// than an existing participant would sit waiting for an offer nobody would send.
//
// ## Why every call negotiates a video line, even a voice call
//
// Adding a track to a live peer connection needs a renegotiation, and renegotiation in a
// mesh is precisely where glare bugs live. So each connection is set up with an *empty*
// video transceiver from the start and `replaceTrack` fills it later. Turning a camera on
// mid-call, and starting a screen share, then cost one function call and no new SDP — which
// is also why they are instant rather than taking a second to re-handshake with everyone.

/* eslint-env browser */

const CairnCall = (() => {
    let config = null;         // ice servers, ceiling, relay honesty — from Rust
    let callId = null;
    let me = null;
    let local = null;          // MediaStream: the mic, and the camera when it is on
    let screen = null;         // MediaStream from getDisplayMedia, when sharing
    const peers = new Map();   // user id -> { pc, pending, stream, audioSender, videoSender }

    // The UI hands these in so this file has no opinions about the DOM.
    let ui = {
        onPeer: () => {},      // (userId, MediaStream | null)
        onState: () => {},     // (userId, connectionState)
        onNotice: () => {},    // (text)
        onEnd: () => {},       // ()
    };

    const wanted = { mic: "", camera: "", speaker: "" };

    async function loadConfig() {
        if (!config) config = await window.__TAURI__.core.invoke("call_config");
        return config;
    }

    // ---- devices -----------------------------------------------------------

    // Labels are empty until the user has granted permission at least once, which is why
    // the picker is populated *after* capture rather than before. Showing "Microphone 1,
    // Microphone 2" and asking someone to choose is not a device picker.
    async function devices() {
        const all = await navigator.mediaDevices.enumerateDevices();
        return {
            mic: all.filter((d) => d.kind === "audioinput"),
            camera: all.filter((d) => d.kind === "videoinput"),
            speaker: all.filter((d) => d.kind === "audiooutput"),
        };
    }

    const micConstraint = () => (wanted.mic ? { deviceId: { exact: wanted.mic } } : true);
    const camConstraint = () => ({
        ...(wanted.camera ? { deviceId: { exact: wanted.camera } } : {}),
        width: { ideal: 1280 },
        height: { ideal: 720 },
    });

    // Output device selection is not part of getUserMedia — it is set per media element
    // with setSinkId, so every remote element has to be told. Not universally supported;
    // when it is missing the UI says so instead of silently ignoring the choice.
    const canChooseSpeaker = () =>
        typeof HTMLMediaElement !== "undefined" && "setSinkId" in HTMLMediaElement.prototype;

    async function applySpeaker(el) {
        if (!wanted.speaker || !canChooseSpeaker()) return;
        try { await el.setSinkId(wanted.speaker); } catch (e) { ui.onNotice("Output device: " + e); }
    }

    // ---- peer connections --------------------------------------------------

    const videoTrack = () =>
        (screen && screen.getVideoTracks()[0]) || (local && local.getVideoTracks()[0]) || null;

    function peerFor(user) {
        const existing = peers.get(user);
        if (existing) return existing;

        const pc = new RTCPeerConnection({ iceServers: (config && config.ice_servers) || [] });
        const entry = { pc, pending: [], stream: new MediaStream(), audioSender: null, videoSender: null };
        peers.set(user, entry);

        const audio = local && local.getAudioTracks()[0];
        if (audio) entry.audioSender = pc.addTrack(audio, local);

        // The empty video line described at the top of this file — but **only on the side
        // that offers**.
        //
        // Found by running two real browsers against each other, never by reading. A
        // transceiver created with `addTransceiver` is not eligible for reuse when a remote
        // offer is applied; only `addTrack` ones are. Pre-creating one on the answering side
        // therefore left it stranded, unassociated, while Chromium built a *third*,
        // `recvonly` transceiver for the offer's video m-line. The call still reached
        // "connected" and looked entirely healthy — and video flowed one way only.
        if (me < user) {
            const video = videoTrack();
            const tx = video
                ? pc.addTransceiver(video, { direction: "sendrecv" })
                : pc.addTransceiver("video", { direction: "sendrecv" });
            entry.videoSender = tx.sender;
        }

        pc.onicecandidate = (ev) => {
            if (!ev.candidate) return;
            send({ kind: "ice", to: user, payload: JSON.stringify(ev.candidate) });
        };
        pc.ontrack = (ev) => {
            entry.stream.addTrack(ev.track);
            // A track that is muted is a camera that is off, not a camera that is missing.
            // Without these the tile shows a frozen last frame forever.
            ev.track.onmute = () => ui.onPeer(user, entry.stream);
            ev.track.onunmute = () => ui.onPeer(user, entry.stream);
            ui.onPeer(user, entry.stream);
        };
        pc.onconnectionstatechange = () => {
            ui.onState(user, pc.connectionState);
            // "failed" is where a call without a TURN relay actually dies. Saying so beats
            // leaving someone staring at a black tile deciding their internet is broken.
            if (pc.connectionState === "failed") {
                ui.onNotice(
                    config && config.has_relay
                        ? "Could not reach " + shortId(user) + "."
                        : "Could not reach " + shortId(user) + " — no TURN relay is configured, " +
                          "so calls cannot cross some home networks."
                );
            }
        };
        return entry;
    }

    async function offerTo(user) {
        const { pc } = peerFor(user);
        await pc.setLocalDescription(await pc.createOffer());
        await send({ kind: "offer", to: user, payload: JSON.stringify(pc.localDescription) });
    }

    // ---- signalling --------------------------------------------------------

    function send(partial) {
        if (!callId) return Promise.resolve();
        return window.__TAURI__.core
            .invoke("signal", { signal: { call: callId, payload: "", ...partial } })
            .catch((e) => ui.onNotice("Signalling failed: " + e));
    }

    // Every signal that survived the Rust-side filters lands here. Which call a signal
    // belongs to is settled in `Session::reconcile` before it gets this far, so the id on
    // the signal is the agreed one — including after two simultaneous starts renamed the
    // call out from under this side.
    async function handle(from, signal) {
        if (!callId) return;
        callId = signal.call;

        try {
            if (signal.kind === "join") {
                // Tell the newcomer we are here, so they can apply the same offer rule.
                // Addressed, so it does not loop: an ack never triggers another ack.
                if (!signal.to) await send({ kind: "join", to: from });

                // The mesh ceiling, enforced where the count is real: not "how many people
                // are in this room" — a group of eight can hold a call between two — but how
                // many peer connections this device is holding. Each participant uploads once
                // per peer, so this is the number that runs out of upstream.
                const ceiling = (config && config.max_participants) || 6;
                if (!peers.has(from) && peers.size >= ceiling - 1) {
                    ui.onNotice(
                        "This call is full at " + ceiling + " people, so " + shortId(from) +
                        " could not be connected. A larger call needs a server to mix it."
                    );
                    return;
                }
                // Offer once per peer, on the first join seen from them. A joiner sends a
                // broadcast and then acknowledges the replies, so without this a peer gets
                // an offer per join announcement and the second tears down the first.
                const known = peers.has(from);
                peerFor(from);
                if (!known && me < from) await offerTo(from);
                return;
            }

            if (signal.kind === "leave") {
                drop(from);
                return;
            }

            if (signal.kind === "offer") {
                const entry = peerFor(from);
                await entry.pc.setRemoteDescription(JSON.parse(signal.payload));
                await adoptVideoLine(entry);
                await flush(entry);
                await entry.pc.setLocalDescription(await entry.pc.createAnswer());
                await send({
                    kind: "answer",
                    to: from,
                    payload: JSON.stringify(entry.pc.localDescription),
                });
                return;
            }

            if (signal.kind === "answer") {
                const entry = peers.get(from);
                if (!entry) return;
                await entry.pc.setRemoteDescription(JSON.parse(signal.payload));
                await flush(entry);
                return;
            }

            if (signal.kind === "ice") {
                const entry = peerFor(from);
                const candidate = JSON.parse(signal.payload);
                // Candidates routinely arrive before the description they belong to; adding
                // one early throws and loses it, which shows up as a call that negotiates
                // and then never connects.
                if (entry.pc.remoteDescription) await entry.pc.addIceCandidate(candidate);
                else entry.pending.push(candidate);
            }
        } catch (e) {
            ui.onNotice("Call error: " + e);
        }
    }

    // The answering half of the note in `peerFor`. The video m-line arrives with the offer,
    // so this claims the transceiver it created — setting it to sendrecv and putting our own
    // track in it. After this both sides hold a `videoSender` and the same `replaceTrack`
    // path serves a camera switch and a screen share on either end.
    async function adoptVideoLine(entry) {
        if (entry.videoSender) return;
        const tx = entry.pc
            .getTransceivers()
            .find((t) => t.receiver && t.receiver.track && t.receiver.track.kind === "video");
        if (!tx) return;
        tx.direction = "sendrecv";
        entry.videoSender = tx.sender;
        const video = videoTrack();
        if (video) await tx.sender.replaceTrack(video);
    }

    async function flush(entry) {
        while (entry.pending.length) {
            try { await entry.pc.addIceCandidate(entry.pending.shift()); } catch (_) { /* stale */ }
        }
    }

    function drop(user) {
        const entry = peers.get(user);
        if (!entry) return;
        try { entry.pc.close(); } catch (_) {}
        peers.delete(user);
        ui.onPeer(user, null);
    }

    // ---- lifecycle ---------------------------------------------------------

    async function join({ video, myUser }) {
        await loadConfig();
        me = myUser;
        local = await navigator.mediaDevices.getUserMedia({
            audio: micConstraint(),
            video: video ? camConstraint() : false,
        });
        // call_join enforces the mesh ceiling in Rust and returns the call id. Capture runs
        // first so a refused call does not leave a microphone light on.
        try {
            callId = await window.__TAURI__.core.invoke("call_join");
        } catch (e) {
            stopTracks();
            throw e;
        }
        return { callId, local, config };
    }

    async function leave() {
        // The announcement is `call_leave`'s job, not this one's — Session::call_leave sends
        // it. Sending one here too put two leaves on the wire for every hang-up.
        try { await window.__TAURI__.core.invoke("call_leave"); } catch (_) {}
        for (const user of [...peers.keys()]) drop(user);
        stopTracks();
        callId = null;
        ui.onEnd();
    }

    function stopTracks() {
        for (const s of [local, screen]) if (s) s.getTracks().forEach((t) => t.stop());
        local = null;
        screen = null;
    }

    // ---- in-call controls --------------------------------------------------

    // Muting is `enabled = false`, not stopping the track: stopping it would tear down the
    // negotiated media line and need a renegotiation to come back. The remote sees the
    // track go muted, which is what a mute indicator should be driven by.
    function setMuted(muted) {
        if (local) local.getAudioTracks().forEach((t) => { t.enabled = !muted; });
    }

    // Every peer's video sender at once. `replaceTrack(null)` genuinely stops sending
    // rather than transmitting black frames, so a camera that is off costs no bandwidth.
    async function replaceVideoEverywhere(track) {
        for (const entry of peers.values()) {
            if (entry.videoSender) await entry.videoSender.replaceTrack(track);
        }
    }

    // Turning a camera on during a voice call. Possible only because of the empty video
    // transceiver: no renegotiation, no glare, no delay.
    async function setCameraOn(on) {
        if (!local) return null;
        if (!on) {
            local.getVideoTracks().forEach((t) => { t.stop(); local.removeTrack(t); });
            if (!screen) await replaceVideoEverywhere(null);
            return local;
        }
        if (!local.getVideoTracks().length) {
            const fresh = await navigator.mediaDevices.getUserMedia({ audio: false, video: camConstraint() });
            local.addTrack(fresh.getVideoTracks()[0]);
        }
        if (!screen) await replaceVideoEverywhere(local.getVideoTracks()[0]);
        return local;
    }

    async function startScreenShare() {
        screen = await navigator.mediaDevices.getDisplayMedia({ video: true, audio: false });
        const track = screen.getVideoTracks()[0];
        // The browser's own "stop sharing" control is outside our UI, so the track ending
        // is the only reliable signal that sharing stopped.
        track.onended = () => { stopScreenShare().then((s) => ui.onPeer(me, s)).catch(() => {}); };
        await replaceVideoEverywhere(track);
        return screen;
    }

    // Returns the stream the local preview should show next: the camera if one is running,
    // otherwise the mic-only stream, which the UI renders as an audio-only tile.
    async function stopScreenShare() {
        if (!screen) return local;
        screen.getTracks().forEach((t) => t.stop());
        screen = null;
        await replaceVideoEverywhere((local && local.getVideoTracks()[0]) || null);
        return local;
    }

    // Switching microphone mid-call: capture from the new device and swap the sender's
    // track, the same trick as the screen share.
    async function useMicrophone(deviceId) {
        wanted.mic = deviceId;
        if (!local) return;
        const fresh = await navigator.mediaDevices.getUserMedia({ audio: micConstraint(), video: false });
        const track = fresh.getAudioTracks()[0];
        for (const entry of peers.values()) {
            if (entry.audioSender) await entry.audioSender.replaceTrack(track);
        }
        local.getAudioTracks().forEach((t) => { t.stop(); local.removeTrack(t); });
        local.addTrack(track);
    }

    async function useCamera(deviceId) {
        wanted.camera = deviceId;
        if (!local || !local.getVideoTracks().length) return null;
        const fresh = await navigator.mediaDevices.getUserMedia({ audio: false, video: camConstraint() });
        const track = fresh.getVideoTracks()[0];
        local.getVideoTracks().forEach((t) => { t.stop(); local.removeTrack(t); });
        local.addTrack(track);
        if (!screen) await replaceVideoEverywhere(track);
        return local;
    }

    function useSpeaker(deviceId) { wanted.speaker = deviceId; }

    const shortId = (id) => String(id).replace(/^usr_/, "").slice(0, 8);

    return {
        loadConfig, devices, join, leave, handle,
        setMuted, setCameraOn,
        startScreenShare, stopScreenShare,
        useMicrophone, useCamera, useSpeaker, applySpeaker, canChooseSpeaker,
        get callId() { return callId; },
        get peerCount() { return peers.size; },
        bind(handlers) { ui = { ...ui, ...handlers }; },
    };
})();
