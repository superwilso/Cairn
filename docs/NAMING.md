# Naming

## The name

**Cairn** — a stack of stones placed by many hands to mark a trail for those who follow.
Open source, self-hosted, community-built. Short, concrete, and carries no existing baggage
in messaging or security software.

Ship the wordmark as **Cairn Chat**, on the canonical domain **`cairn.chat`**. Never
compete for the bare keyword "cairn".

## Known collisions

Research found real crowding, none of it in messaging:

| Entity | Space | Assessment |
|---|---|---|
| **Cairn** (The Game Bakers) | Video game, released 2026-01-29 | Nice class 9 software neighbour and a genuine SEO competitor. The most significant of these — check its registration specifically |
| **Cairn RPG** (Yochai Gal) | Tabletop RPG, CC-BY-SA | Low legal risk; some SEO overlap |
| **cairn.info** | French academic publishing portal | SEO only; dominates the bare term |
| **Cairn Energy** | Oil and gas | No meaningful conflict |

## Why this matters more than it looks

**Revolt — the largest open-source Discord alternative, around 600,000 users — received a
cease-and-desist over its name and rebranded to Stoat on 2025-10-01.** The codebase and
community were unaffected; only the name changed. Our closest comparable project lost a
naming fight within the last year.

A rename after launch costs the domain, the app store listings, the search ranking, the
social handles, and a chunk of accumulated goodwill. Clearance is cheap by comparison.

## Clearance — required before any public announcement

**Status: NOT DONE.** None of the following has been verified. Attempts to check domain
registration (RDAP) and trademark databases from the development environment were blocked
by network policy, so nothing here should be treated as confirmed.

- [ ] Register **`cairn.chat`** (canonical), plus defensive `cairnchat.com`, `getcairn.com`
- [ ] **USPTO** clearance search, Nice classes **9** (software), **38** (telecoms), **42**
      (SaaS) — pay specific attention to the video game's class 9 registration
- [ ] **EUIPO** clearance search, same classes
- [ ] Check UKIPO if the UK is a target market
- [ ] Claim handles: GitHub org, npm, crates.io, Mastodon, Bluesky, Matrix
- [ ] **Lawyer sign-off before the first public post**
- [ ] Draft the trademark policy required by [ADR-004](adr/004-licensing.md) — the code is
      free, the name is not

**Worth doing:** ask Stoat's maintainers what happened to them. That is a free and directly
relevant case study, and they have every reason to be candid about it.

## If Cairn has to be abandoned

Alternatives considered, retaining the "proof, trust, or shelter" theme. Each needs its own
clearance search — none has been run:

- **Tessera** — the Roman *tessera hospitalis* was a token broken in two, each party keeping
  half to prove a bond. A key exchange from 100 BC. Strong concept fit; emptier namespace.
- **Signet** — a signet ring seals a letter: proves the sender, hides the contents. That is
  literally message franking. Risk: confusion with Signal.
- **Skein**, **Roost**, **Parley** — emptier namespaces, weaker concept fit. Note *Skein*
  is also a cryptographic hash function, which cuts both ways.

## Decision

Keep **Cairn**, ship as **Cairn Chat**, complete clearance before announcing. If clearance
fails, **Tessera** is the strongest fallback.
