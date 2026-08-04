# ADR-004: Split licensing — copyleft server, permissive clients and protocol

**Status:** Accepted
**Date:** 2026-08-04

## Context

Licensing looks like a formality and is not. Two constraints make a single-license choice
actively harmful here:

1. **GPL-family licenses conflict with app store distribution.** The Apple App Store's
   terms impose usage restrictions that are incompatible with GPL/AGPL terms. This is a
   long-standing, well-documented friction that has caused real projects real problems, and
   an AGPL mobile client is a recurring distribution headache rather than a one-time
   argument.
2. **Protocol adoption is the moat, and copyleft suppresses it.** If the Cairn protocol
   libraries are AGPL, no other project will embed them. If they are permissive, other
   clients, bots, and bridges can — and every adopter increases the value of the protocol.
   The strategic goal for protocol code is *ubiquity*, which is the opposite of the goal for
   server code.

Meanwhile the server has the opposite need: prevent a well-funded company from taking the
work closed-source as a hosted service, contributing nothing back. This is precisely what
AGPL exists for, and it is what Stoat (formerly Revolt), our closest comparable, uses.

## Decision

**Split the licensing by component, according to what each component needs.**

| Component | License | Rationale |
|---|---|---|
| Server / backend | **AGPL-3.0** | Prevents closed hosted forks; matches Stoat |
| Clients (desktop, mobile, web) | **Apache-2.0** | App store compatible; patent grant |
| Protocol libraries, SDKs | **Apache-2.0** | Maximize adoption — ubiquity is the goal |
| Specifications, docs | **CC-BY-SA-4.0** | Share-alike for the written work |

Additional rules:

1. **A CLA or DCO is required before accepting external contributions.** Without one, the
   license cannot be changed later even when everyone agrees it should be. Prefer a **DCO**
   (lightweight, no copyright assignment, respected by contributors) over a CLA that
   assigns rights to a single entity — the latter reads as a rug-pull risk to exactly the
   community we are recruiting.
2. **Trademark is licensed separately from code.** The code is free; the name is not. Only
   builds meeting stated criteria may call themselves "Cairn." This is what lets us say a
   modified client is not Cairn — and it matters because
   [`01-threat-model.md`](../01-threat-model.md) §7 accepts that malicious forks exist.
3. **The AGPL boundary must be documented**, so self-hosters know exactly what their
   obligations are when they modify the server.

## Consequences

### Positive

- Mobile clients ship to the App Store without a licensing fight.
- Third parties can build alternative clients and bots on permissive protocol libraries,
  which grows the ecosystem.
- The server stays protected from closed commercial forks.
- Trademark separation gives an enforcement mechanism against hostile forks that does not
  depend on restricting the code.

### Negative

- **Multiple licenses in one repository is a real maintenance burden.** Every file needs
  clear provenance, and contributors must know which license applies to what. Mitigated by
  enforcing per-directory `LICENSE` files and a top-level map.
- A permissive client license means someone can build a proprietary Cairn client.
  Accepted — trademark handles the worst case, and it is the price of app store viability.
- DCO adds friction to first-time contributions.
- If server and client code ever need to share a library, the license boundary constrains
  the code layout. Plan the module structure around it rather than discovering it later.

## Alternatives rejected

**AGPL everything.** Rejected: app store friction on clients, and it suppresses exactly the
protocol adoption we want.

**Apache-2.0 everything.** Rejected: permits a closed, hosted commercial fork of the server
with no reciprocity.

**GPL-3.0 for the server.** Rejected: does not close the hosted-service gap, which is the
main risk for a self-hostable chat platform.

**Business Source License / other source-available.** Rejected outright: not open source,
and adopting it would forfeit the community this project depends on.

## Action items

- [ ] Add verbatim `LICENSE` files — AGPL-3.0 at root, Apache-2.0 under client and protocol
      directories once those exist. **Not yet added**: the license texts must be copied
      verbatim from an authoritative source, and outbound access to `gnu.org` and
      `apache.org` was blocked from the environment where these docs were drafted. Use
      GitHub's license picker or `curl https://www.gnu.org/licenses/agpl-3.0.txt`.
- [ ] Add `DCO` and a `Signed-off-by` requirement to `CONTRIBUTING.md`.
- [ ] Draft the trademark policy (can follow the naming clearance in
      [`NAMING.md`](../NAMING.md)).
- [ ] Document the AGPL boundary for self-hosters.
