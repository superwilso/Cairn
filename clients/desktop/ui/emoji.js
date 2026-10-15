// Emoji: the picker, and drawing a room's custom emoji and stickers.
//
// ## Where the bytes come from, and where they never come from
//
// A room's custom set arrives as one encrypted record and Rust downloads **every** image in
// it as soon as it changes (`custom_sync`). Drawing `:party_parrot:` then reads this
// device's cache through `custom_asset`, which has no network path at all. So nothing this
// file does at render time — a message, a reaction chip, a sticker, the picker — can tell
// the instance which emoji somebody used. That is the design in docs/13-customisation.md §3,
// and the reason this file never asks for an image by name, only by the id the set gave it.
//
// An emoji whose bytes are not here yet is drawn as its `:name:` text and upgraded in place
// when the sync finishes. It is never fetched on demand.
//
// Everything a member chose — names included — is drawn with textContent. Names are already
// `[a-z0-9_]` (Rust refuses anything else), but this file does not rely on that.

const CairnEmoji = (() => {
    const $ = (id) => document.getElementById(id);
    let hooks = {
        invoke: (cmd, args, opts) => window.__TAURI__.core.invoke(cmd, args, opts),
        onError: () => {},
        onSent: () => {},
        canSend: () => true,
    };

    // ---- the room's set -------------------------------------------------------

    let set = { items: [], can_edit: false, author: null, bytes: 0 };
    const urls = new Map();       // asset id -> object URL, for this room only
    const listeners = [];
    let generation = 0;           // bumped on room change, so a late load cannot land in the next room
    const TOKEN = /:([a-z0-9_]{2,32}):/g;

    const bytesOf = (raw) => (raw instanceof ArrayBuffer ? new Uint8Array(raw) : Uint8Array.from(raw));
    const item = (kind, name) => set.items.find((i) => i.kind === kind && i.name === name) || null;
    const items = (kind) => set.items.filter((i) => i.kind === kind);

    function url(kind, name) {
        const it = item(kind, name);
        return it ? urls.get(it.id) || null : null;
    }

    // Raw bytes of one item, from Rust's cache. For the soundboard, which decodes them.
    async function bytes(it) {
        return bytesOf(await hooks.invoke("custom_asset", { id: it.id }));
    }

    async function apply(view, gen) {
        if (gen !== generation) return;
        set = view;
        const live = new Set(view.items.map((i) => i.id));
        for (const [id, u] of urls) {
            if (!live.has(id)) { URL.revokeObjectURL(u); urls.delete(id); }
        }
        for (const it of view.items) {
            if (!it.ready || urls.has(it.id) || it.kind === "sound") continue;
            try {
                const raw = await hooks.invoke("custom_asset", { id: it.id });
                if (gen !== generation) return;
                urls.set(it.id, URL.createObjectURL(new Blob([bytesOf(raw)], { type: it.mime })));
            } catch (_) { /* not cached after all; drawn as its name */ }
        }
        refresh();
        for (const fn of listeners) { try { fn(set); } catch (_) {} }
    }

    // Read the set, draw what is cached, then download whatever is missing — all of it, at
    // once — and draw again. Called when a room opens and whenever Rust says the set changed.
    async function load(view) {
        const gen = generation;
        try {
            await apply(view || await hooks.invoke("custom_set"), gen);
            if (set.items.some((i) => !i.ready)) {
                await hooks.invoke("custom_sync");
                await apply(await hooks.invoke("custom_set"), gen);
            }
        } catch (_) { /* no room open, or not in the group yet */ }
    }

    function reset() {
        generation += 1;
        for (const u of urls.values()) URL.revokeObjectURL(u);
        urls.clear();
        set = { items: [], can_edit: false, author: null, bytes: 0 };
        for (const fn of listeners) { try { fn(set); } catch (_) {} }
        close();
    }

    function handle(ev) {
        if (ev.kind !== "custom") return false;
        load(ev.set);
        return true;
    }

    // ---- drawing ----------------------------------------------------------------

    function customNode(name) {
        const span = document.createElement("span");
        span.className = "ce";
        span.dataset.ce = name;
        span.title = ":" + name + ":";
        upgrade(span);
        return span;
    }

    function upgrade(span) {
        const name = span.dataset.ce;
        const u = url("emoji", name);
        if (u) {
            if (span.firstChild && span.firstChild.tagName === "IMG" && span.firstChild.src === u) return;
            const img = document.createElement("img");
            img.className = "ce-img";
            img.alt = ":" + name + ":";
            img.draggable = false;
            img.src = u;
            span.replaceChildren(img);
            span.classList.remove("ce-missing");
        } else {
            span.textContent = ":" + name + ":";
            span.classList.add("ce-missing");
        }
    }

    // A message body, with `:name:` drawn as the room's emoji where it has one. Text nodes
    // only, never markup. A message of nothing but emoji is drawn large, as apps do.
    function renderText(text) {
        const frag = document.createDocumentFragment();
        let last = 0;
        let emojiOnly = true;
        let count = 0;
        TOKEN.lastIndex = 0;
        for (let m = TOKEN.exec(text); m; m = TOKEN.exec(text)) {
            const before = text.slice(last, m.index);
            if (before) frag.append(document.createTextNode(before));
            if (before.trim()) emojiOnly = false;
            frag.append(customNode(m[1]));
            count += 1;
            last = m.index + m[0].length;
        }
        const rest = text.slice(last);
        if (rest) frag.append(document.createTextNode(rest));
        if (rest.trim() || !count) emojiOnly = false;
        frag.jumbo = emojiOnly && count <= 3;
        return frag;
    }

    // A reaction chip's glyph. A `:name:` the room's set does not hold is a placeholder, not
    // its name: a chip under someone's message must not become a place for words.
    function chip(emoji) {
        const m = /^:([a-z0-9_]{2,32}):$/.exec(emoji || "");
        if (!m) return document.createTextNode(emoji);
        const span = customNode(m[1]);
        span.classList.add("ce-chip");
        if (!item("emoji", m[1])) {
            span.textContent = "◌";
            span.classList.add("ce-unknown");
            span.title = ":" + m[1] + ": — not in this room's set";
        }
        return span;
    }

    function renderSticker(name, body) {
        const box = document.createElement("div");
        box.className = "sticker";
        box.dataset.sticker = name;
        box.title = ":" + name + ":";
        drawSticker(box, body);
        return box;
    }

    function drawSticker(box, body) {
        const u = url("sticker", box.dataset.sticker);
        if (u) {
            const img = document.createElement("img");
            img.alt = "sticker :" + box.dataset.sticker + ":";
            img.draggable = false;
            img.src = u;
            box.replaceChildren(img);
            box.classList.remove("missing");
        } else {
            box.textContent = body || ":" + box.dataset.sticker + ":";
            box.classList.add("missing");
        }
    }

    // Redraw every custom emoji and sticker already on screen — after a sync, or a set change.
    function refresh() {
        for (const span of document.querySelectorAll(".ce:not(.ce-unknown)")) upgrade(span);
        for (const span of document.querySelectorAll(".ce.ce-unknown")) {
            if (item("emoji", span.dataset.ce)) {
                span.classList.remove("ce-unknown");
                span.title = ":" + span.dataset.ce + ":";
                upgrade(span);
            }
        }
        for (const box of document.querySelectorAll(".sticker[data-sticker]")) drawSticker(box);
        if (panel && !panel.hidden) draw();
    }

    // ---- the unicode set --------------------------------------------------------
    //
    // A curated list rather than the whole of Unicode: no build step and no data file to
    // fetch, and every entry carries words to search by. Each line is the emoji, then words.

    const CATEGORIES = [
        ["Smileys", "😀", `
😀 grin happy smile|😃 smiley happy|😄 smile happy laugh|😁 beaming grin|😆 laughing squint|😅 sweat smile relief|🤣 rofl rolling laughing|😂 joy tears laughing|🙂 slight smile|🙃 upside down|😉 wink|😊 blush smile|😇 halo angel innocent|🥰 hearts love adore|😍 heart eyes love|🤩 star struck|😘 kiss blow|😋 yum tasty|😛 tongue|😜 wink tongue|🤪 zany crazy|🤑 money|🤗 hug|🤭 oops giggle|🤫 shush quiet|🤔 thinking hmm|🤐 zipper mouth|🤨 raised eyebrow|😐 neutral|😑 expressionless|😶 no mouth|😏 smirk|😒 unamused|🙄 eye roll|😬 grimace awkward|😌 relieved|😔 pensive|😪 sleepy|🤤 drool|😴 sleeping zzz|😷 mask sick|🤒 thermometer ill|🤕 bandage hurt|🤢 nauseated|🤮 vomit|🥵 hot|🥶 cold freezing|🥴 woozy|😵 dizzy|🤯 mind blown exploding|🤠 cowboy|🥳 party celebrate|😎 cool sunglasses|🤓 nerd|🧐 monocle|😕 confused|😟 worried|🙁 frown|😮 open mouth wow|😯 hushed|😲 astonished|😳 flushed|🥺 pleading puppy|😦 frowning|😧 anguished|😨 fearful|😰 anxious sweat|😥 sad relieved|😢 cry tear|😭 sob crying|😱 scream|😖 confounded|😣 persevere|😞 disappointed|😓 downcast sweat|😩 weary|😫 tired|🥱 yawn|😤 triumph huff|😡 angry pout|😠 angry|🤬 cursing|😈 devil smiling|👿 imp|💀 skull dead|💩 poop|🤡 clown|👻 ghost|👽 alien|🤖 robot|😺 cat smile|😹 cat joy|😻 cat heart eyes`],
        ["People", "👋", `
👋 wave hello bye|🤚 raised back hand|✋ hand stop high five|🖖 vulcan|👌 ok perfect|🤌 pinched fingers|🤏 pinch small|✌️ peace victory|🤞 fingers crossed luck|🤟 love you|🤘 rock horns|🤙 call me shaka|👈 point left|👉 point right|👆 point up|👇 point down|☝️ index up|👍 thumbs up yes like|👎 thumbs down no dislike|✊ fist|👊 punch fist bump|🤛 left fist|🤜 right fist|👏 clap applause|🙌 raised hands celebrate|👐 open hands|🤲 palms up|🤝 handshake deal|🙏 pray please thanks|✍️ writing|💅 nail polish|🤳 selfie|💪 muscle strong flex|🧠 brain smart|👀 eyes look|👁️ eye|👅 tongue|👄 mouth|🫶 heart hands|🧑 person|👶 baby|🧒 child|👩 woman|👨 man|🧓 older person|🧑‍💻 technologist coder|🧑‍🍳 cook|🧑‍🚀 astronaut|🕵️ detective|🧙 mage wizard|🧛 vampire|🧟 zombie|🙋 raising hand|🤷 shrug|🤦 facepalm|🙇 bow|💁 tipping hand|🙆 ok gesture|🙅 no gesture|💃 dance|🕺 dancing man|🚶 walk|🏃 run`],
        ["Nature", "🌿", `
🐶 dog puppy|🐱 cat kitten|🐭 mouse|🐹 hamster|🐰 rabbit bunny|🦊 fox|🐻 bear|🐼 panda|🐨 koala|🐯 tiger|🦁 lion|🐮 cow|🐷 pig|🐸 frog|🐵 monkey|🙈 see no evil|🙉 hear no evil|🙊 speak no evil|🐔 chicken|🐧 penguin|🐦 bird|🦆 duck|🦉 owl|🦇 bat|🐺 wolf|🐗 boar|🐴 horse|🦄 unicorn|🐝 bee|🐛 bug caterpillar|🦋 butterfly|🐌 snail|🐞 ladybug|🐢 turtle|🐍 snake|🦖 dinosaur t rex|🐙 octopus|🦀 crab|🐠 fish tropical|🐬 dolphin|🐳 whale|🦈 shark|🐊 crocodile|🦒 giraffe|🐘 elephant|🦔 hedgehog|🌵 cactus|🌲 evergreen tree|🌳 tree|🌴 palm tree|🌱 seedling sprout|🌿 herb leaf|🍀 four leaf clover luck|🍁 maple leaf autumn|🍂 fallen leaves|🍄 mushroom|🌷 tulip|🌹 rose|🌻 sunflower|🌸 blossom cherry|💐 bouquet flowers|🌍 earth globe|🌙 moon crescent|⭐ star|🌟 glowing star|✨ sparkles|⚡ lightning zap|🔥 fire lit hot|🌈 rainbow|☀️ sun|⛅ cloud sun|🌧️ rain|❄️ snowflake snow|☃️ snowman|🌊 wave ocean|💧 droplet water`],
        ["Food", "🍕", `
🍏 green apple|🍎 apple red|🍐 pear|🍊 orange tangerine|🍋 lemon|🍌 banana|🍉 watermelon|🍇 grapes|🍓 strawberry|🫐 blueberries|🍒 cherries|🍑 peach|🥭 mango|🍍 pineapple|🥥 coconut|🥝 kiwi|🍅 tomato|🥑 avocado|🍆 eggplant aubergine|🥕 carrot|🌽 corn|🌶️ hot pepper chili|🥦 broccoli|🧄 garlic|🧅 onion|🥔 potato|🍞 bread|🥐 croissant|🥖 baguette|🧀 cheese|🥚 egg|🍳 cooking fried egg|🥞 pancakes|🧇 waffle|🥓 bacon|🍔 burger hamburger|🍟 fries|🍕 pizza|🌭 hot dog|🥪 sandwich|🌮 taco|🌯 burrito|🥗 salad|🍝 spaghetti pasta|🍜 ramen noodles|🍲 stew pot|🍣 sushi|🍱 bento|🥟 dumpling|🍤 shrimp tempura|🍙 rice ball|🍚 rice|🍦 ice cream soft|🍩 doughnut donut|🍪 cookie|🎂 birthday cake|🍰 cake slice|🧁 cupcake|🍫 chocolate|🍬 candy|🍭 lollipop|🍿 popcorn|☕ coffee hot|🍵 tea|🧋 bubble tea boba|🥤 cup straw soda|🍺 beer|🍻 cheers beers|🍷 wine|🥂 champagne toast|🍸 cocktail|🧉 mate|🍾 bottle popping`],
        ["Activities", "⚽", `
⚽ soccer football|🏀 basketball|🏈 american football|⚾ baseball|🎾 tennis|🏐 volleyball|🏉 rugby|🎱 billiards eight ball|🏓 ping pong|🏸 badminton|🥅 goal net|⛳ golf|🏹 bow arrow|🎣 fishing|🥊 boxing|🥋 martial arts|⛸️ ice skate|🎿 ski|🛹 skateboard|🏋️ weight lifting|🚴 cycling bike|🏊 swimming|🧗 climbing|🏆 trophy win|🥇 gold medal first|🥈 silver medal|🥉 bronze medal|🏅 medal|🎖️ military medal|🎫 ticket|🎪 circus|🎭 theater masks|🎨 art palette|🎬 clapper film|🎤 microphone sing|🎧 headphones|🎼 score music|🎹 piano keyboard|🥁 drum|🎷 saxophone|🎺 trumpet|🎸 guitar|🎻 violin|🎲 dice game|♟️ chess pawn|🎯 bullseye target|🎳 bowling|🎮 video game controller|🧩 puzzle|🎉 party popper tada|🎊 confetti|🎈 balloon|🎁 gift present|🎀 ribbon|🪅 pinata|🎆 fireworks|🎇 sparkler`],
        ["Travel", "🚀", `
🚗 car|🚕 taxi|🚌 bus|🏎️ racing car|🚓 police car|🚑 ambulance|🚒 fire engine|🚚 truck|🚲 bicycle|🛵 scooter|🏍️ motorcycle|🚂 train locomotive|🚆 train|🚇 metro subway|✈️ airplane plane|🛫 departure|🛬 arrival|🚁 helicopter|🚀 rocket launch|🛸 ufo flying saucer|⛵ sailboat|🚤 speedboat|🚢 ship|⚓ anchor|🗺️ map|🧭 compass|🏔️ mountain snow|⛰️ mountain|🌋 volcano|🏕️ camping|🏖️ beach|🏜️ desert|🏝️ island|🏠 house home|🏡 house garden|🏢 office building|🏥 hospital|🏦 bank|🏫 school|🏰 castle|🗼 tower|🗽 statue liberty|⛪ church|🕌 mosque|⛩️ shrine|🌃 night city|🌆 cityscape dusk|🌉 bridge night|🎡 ferris wheel|🎢 roller coaster|🗻 fuji|⛲ fountain|🧳 luggage|⌛ hourglass|⏰ alarm clock|🌅 sunrise|🌄 sunrise mountains|🌌 milky way|🪨 rock stone cairn`],
        ["Objects", "💡", `
⌚ watch|📱 phone mobile|💻 laptop computer|⌨️ keyboard|🖥️ desktop computer|🖨️ printer|🖱️ mouse computer|💾 floppy save|💿 cd disc|📷 camera|📸 camera flash|🎥 movie camera|📺 television tv|📻 radio|🔋 battery|🔌 plug|💡 bulb idea|🔦 flashlight|🕯️ candle|📚 books|📖 book open|📝 memo note|✏️ pencil|🖊️ pen|📌 pushpin|📎 paperclip|✂️ scissors|📅 calendar|📈 chart up|📉 chart down|📊 bar chart|🗂️ dividers|📦 package box|✉️ envelope|📧 email|📨 incoming|📬 mailbox|🔒 lock locked|🔓 unlock|🔑 key|🗝️ old key|🔨 hammer|🪓 axe|🔧 wrench|🔩 nut bolt|⚙️ gear settings|🧲 magnet|🧪 test tube|🔬 microscope|🔭 telescope|💊 pill|🩹 bandage|🧸 teddy bear|🛒 cart|💰 money bag|💳 card credit|💎 gem diamond|⚖️ scale balance|🧰 toolbox|🪜 ladder|🛡️ shield|🔔 bell|📣 megaphone|🔊 speaker loud|🔇 muted|💤 zzz sleep`],
        ["Symbols", "❤️", `
❤️ red heart love|🧡 orange heart|💛 yellow heart|💚 green heart|💙 blue heart|💜 purple heart|🖤 black heart|🤍 white heart|🤎 brown heart|💔 broken heart|❣️ heart exclamation|💕 two hearts|💞 revolving hearts|💓 beating heart|💗 growing heart|💖 sparkling heart|💘 cupid|💝 heart ribbon|💯 hundred perfect|💢 anger|💥 boom collision|💫 dizzy star|💦 sweat drops|💨 dash|💬 speech bubble|🗯️ anger bubble|💭 thought bubble|✅ check done|☑️ ballot check|✔️ check mark|❌ cross no|❎ cross button|➕ plus|➖ minus|➗ divide|❓ question|❗ exclamation|‼️ double exclamation|⁉️ interrobang|⚠️ warning|🚫 prohibited|⛔ no entry|🔞 eighteen|♻️ recycle|🔱 trident|⚜️ fleur de lis|🔰 beginner|⭕ circle|🔴 red circle|🟠 orange circle|🟡 yellow circle|🟢 green circle|🔵 blue circle|🟣 purple circle|⚫ black circle|⚪ white circle|🔺 red triangle|🔻 down triangle|🔶 orange diamond|🔷 blue diamond|▶️ play|⏸️ pause|⏹️ stop|⏺️ record|⏭️ next|🔁 repeat|🔀 shuffle|🎵 music note|🎶 notes|➡️ right arrow|⬅️ left arrow|⬆️ up arrow|⬇️ down arrow|🔄 counterclockwise|🆗 ok button|🆕 new|🆒 cool button|🆓 free|🏳️‍🌈 rainbow flag pride|🏴‍☠️ pirate flag|🏁 checkered flag finish`],
    ].map(([name, icon, raw]) => ({
        name,
        icon,
        entries: raw.trim().split("|").map((line) => {
            const [glyph, ...words] = line.trim().split(/\s+/);
            return { glyph, words: words.join(" ") };
        }),
    }));

    // ---- the picker -------------------------------------------------------------

    let panel = null;
    let state = { tab: "emoji", query: "", onPick: null, stickers: false, anchor: null };
    const RECENT_KEY = "cairn.emoji.recent";

    function recent() {
        try { return JSON.parse(localStorage.getItem(RECENT_KEY) || "[]").slice(0, 16); }
        catch (_) { return []; }
    }
    function remember(value) {
        try {
            const list = [value, ...recent().filter((v) => v !== value)].slice(0, 16);
            localStorage.setItem(RECENT_KEY, JSON.stringify(list));
        } catch (_) { /* a private window, or storage blocked: recents are a convenience */ }
    }

    function build() {
        panel = document.createElement("div");
        panel.id = "emoji-picker";
        panel.className = "ep";
        panel.hidden = true;
        panel.setAttribute("role", "dialog");
        panel.setAttribute("aria-label", "Emoji picker");

        const head = document.createElement("div");
        head.className = "ep-head";
        const tabs = document.createElement("div");
        tabs.className = "ep-tabs";
        for (const [tab, label] of [["emoji", "Emoji"], ["stickers", "Stickers"]]) {
            const b = document.createElement("button");
            b.type = "button";
            b.className = "ep-tab ghost";
            b.dataset.tab = tab;
            b.textContent = label;
            b.addEventListener("click", () => { state.tab = tab; draw(); });
            tabs.append(b);
        }
        const search = document.createElement("input");
        search.className = "ep-search";
        search.placeholder = "Search emoji";
        search.spellcheck = false;
        search.autocomplete = "off";
        search.setAttribute("aria-label", "Search emoji");
        search.addEventListener("input", () => { state.query = search.value.trim().toLowerCase(); draw(); });
        search.addEventListener("keydown", (e) => {
            if (e.key === "Enter") {
                e.preventDefault();
                const first = panel.querySelector(".ep-body button.ep-cell");
                if (first) first.click();
            }
        });
        head.append(tabs, search);

        const cats = document.createElement("nav");
        cats.className = "ep-cats";

        const body = document.createElement("div");
        body.className = "ep-body";

        const foot = document.createElement("div");
        foot.className = "ep-foot";
        const big = document.createElement("span");
        big.className = "ep-big";
        const label = document.createElement("span");
        label.className = "ep-label mono";
        foot.append(big, label);

        panel.append(head, cats, body, foot);
        document.body.append(panel);
        document.addEventListener("pointerdown", (e) => {
            if (!panel.hidden && !panel.contains(e.target) && e.target !== state.anchor &&
                !(state.anchor && state.anchor.contains(e.target))) close();
        });
        window.addEventListener("resize", place);
    }

    function cell(content, title, value, sticker) {
        const b = document.createElement("button");
        b.type = "button";
        b.className = "ep-cell" + (sticker ? " ep-sticker" : "");
        b.title = title;
        b.setAttribute("aria-label", title);
        b.append(content);
        const preview = () => {
            panel.querySelector(".ep-big").replaceChildren(content.cloneNode(true));
            panel.querySelector(".ep-label").textContent = title;
        };
        b.addEventListener("mouseenter", preview);
        b.addEventListener("focus", preview);
        b.addEventListener("click", () => pick(value));
        return b;
    }

    function customImg(it) {
        const u = urls.get(it.id);
        if (!u) {
            const s = document.createElement("span");
            s.className = "ep-pending";
            s.textContent = it.name.slice(0, 2);
            return s;
        }
        const img = document.createElement("img");
        img.src = u;
        img.alt = ":" + it.name + ":";
        img.draggable = false;
        return img;
    }

    function section(body, id, title, cells) {
        if (!cells.length) return;
        const h = document.createElement("h4");
        h.className = "ep-section";
        h.id = "ep-sec-" + id;
        h.textContent = title;
        const grid = document.createElement("div");
        grid.className = "ep-grid";
        grid.append(...cells);
        body.append(h, grid);
    }

    function draw() {
        if (!panel) return;
        const body = panel.querySelector(".ep-body");
        const cats = panel.querySelector(".ep-cats");
        const tabs = panel.querySelector(".ep-tabs");
        tabs.hidden = !state.stickers;
        for (const b of tabs.querySelectorAll(".ep-tab")) b.classList.toggle("on", b.dataset.tab === state.tab);
        const search = panel.querySelector(".ep-search");
        search.placeholder = state.tab === "stickers" ? "Search stickers" : "Search emoji";
        body.textContent = "";
        cats.textContent = "";
        const q = state.query;

        if (state.tab === "stickers") {
            cats.hidden = true;
            const list = items("sticker").filter((s) => !q || s.name.includes(q));
            section(body, "stickers", "This room's stickers",
                list.map((s) => cell(customImg(s), ":" + s.name + ":", { sticker: s.name }, true)));
            if (!list.length) empty(body, items("sticker").length ? "No sticker matches." :
                "This room has no stickers yet." + (set.can_edit ? " Add some in Customise." : ""));
            return;
        }

        cats.hidden = !!q;
        const custom = items("emoji").filter((e) => !q || e.name.includes(q));
        const navTo = (id, icon, title) => {
            const b = document.createElement("button");
            b.type = "button";
            b.className = "ghost ep-cat";
            b.title = title;
            b.setAttribute("aria-label", title);
            b.append(icon);
            b.addEventListener("click", () => {
                const target = panel.querySelector("#ep-sec-" + id);
                if (target) body.scrollTop = target.offsetTop - body.offsetTop;
            });
            cats.append(b);
        };

        if (!q) {
            const rec = recent().filter((v) => !v.startsWith(":") || item("emoji", v.slice(1, -1)));
            if (rec.length) {
                navTo("recent", document.createTextNode("\u{1F552}"), "Recent");
                section(body, "recent", "Recent", rec.map((v) => {
                    const m = /^:([a-z0-9_]+):$/.exec(v);
                    return m ? cell(customImg(item("emoji", m[1])), v, v) : cell(document.createTextNode(v), v, v);
                }));
            }
        }
        if (custom.length) {
            navTo("room", customImg(custom[0]), "This room");
            section(body, "room", "This room", custom.map((e) => cell(customImg(e), ":" + e.name + ":", ":" + e.name + ":")));
        }
        for (const [n, cat] of CATEGORIES.entries()) {
            const list = cat.entries.filter((e) => !q || e.words.includes(q));
            if (!list.length) continue;
            if (!q) navTo("u" + n, document.createTextNode(cat.icon), cat.name);
            section(body, "u" + n, cat.name, list.map((e) => cell(document.createTextNode(e.glyph), e.words.split(" ")[0], e.glyph)));
        }
        if (!body.childElementCount) empty(body, "No emoji matches “" + q + "”.");
    }

    function empty(body, text) {
        const p = document.createElement("p");
        p.className = "ep-empty";
        p.textContent = text;
        body.append(p);
    }

    async function pick(value) {
        const onPick = state.onPick;
        if (typeof value === "string") remember(value);
        close();
        if (onPick) await onPick(value);
    }

    function place() {
        if (!panel || panel.hidden || !state.anchor) return;
        const a = state.anchor.getBoundingClientRect();
        const w = Math.min(352, window.innerWidth - 16);
        panel.style.width = w + "px";
        const h = Math.min(420, window.innerHeight - 16);
        panel.style.height = h + "px";
        panel.style.left = Math.max(8, Math.min(window.innerWidth - w - 8, a.right - w)) + "px";
        const above = a.top - h - 6;
        panel.style.top = (above >= 8 ? above : Math.min(window.innerHeight - h - 8, a.bottom + 6)) + "px";
    }

    // `stickers: true` adds the sticker tab; the composer passes it, a reaction does not.
    function open({ anchor, onPick, stickers = false, tab = "emoji" }) {
        if (!panel) build();
        state = { tab: stickers ? tab : "emoji", query: "", onPick, stickers, anchor };
        const search = panel.querySelector(".ep-search");
        search.value = "";
        panel.hidden = false;
        draw();
        place();
        panel.querySelector(".ep-big").textContent = "";
        panel.querySelector(".ep-label").textContent = "";
        search.focus();
    }

    function close() {
        if (panel) panel.hidden = true;
        if (state.anchor && state.anchor.id === "emoji") state.anchor.classList.remove("on");
    }

    const isOpen = () => !!panel && !panel.hidden;

    // ---- the composer's button --------------------------------------------------

    function insertAtCaret(input, text) {
        const start = input.selectionStart ?? input.value.length;
        const end = input.selectionEnd ?? input.value.length;
        const before = input.value.slice(0, start);
        const pad = before && !/\s$/.test(before) && text.startsWith(":") ? " " : "";
        input.value = before + pad + text + input.value.slice(end);
        const at = start + pad.length + text.length;
        input.focus();
        input.setSelectionRange(at, at);
    }

    function bindComposer(button, input) {
        button.addEventListener("click", () => {
            if (isOpen()) return close();
            button.classList.add("on");
            open({
                anchor: button,
                stickers: true,
                onPick: async (value) => {
                    if (value && value.sticker) {
                        if (!hooks.canSend()) return;
                        try { hooks.onSent(await hooks.invoke("send_sticker", { name: value.sticker })); }
                        catch (e) { hooks.onError(e); }
                        return;
                    }
                    insertAtCaret(input, value.startsWith(":") ? value + " " : value);
                },
            });
        });
    }

    function bind(h) {
        hooks = { ...hooks, ...h };
        document.addEventListener("keydown", (e) => { if (e.key === "Escape" && isOpen()) close(); });
        if (h.button && h.input) bindComposer(h.button, h.input);
    }

    return {
        bind, load, reset, handle, open, close, isOpen,
        renderText, renderSticker, chip, refresh,
        get set() { return set; }, items, url, bytes,
        onChange: (fn) => listeners.push(fn),
        CATEGORIES,
    };
})();
