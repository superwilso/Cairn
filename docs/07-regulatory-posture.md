# Regulatory Posture

**Status:** Draft — **not legal advice**, and requires review by an actual lawyer

Cairn's stated goal is to respect privacy **while remaining within international law**.
Those two aims mostly coexist. Where they genuinely conflict, this document says what the
project does instead of pretending the conflict does not exist.

## The governing principle

> **Cairn complies with lawful obligations that do not require breaking its security
> model. It does not build backdoors, key escrow, or client-side scanning mandates — not
> for any government, and not for us.**

The consequence is stated plainly rather than buried: **in jurisdictions that legally
require exceptional access to encrypted content, Cairn cannot be operated compliantly as an
E2EE service.** The options there are to run T3-only communities, or not to operate. There
is no third option, and any project claiming otherwise is either not really encrypted or
not really compliant.

This is not defiance. It is the same position Signal holds, and it is the only position
consistent with the guarantees in `01-threat-model.md`.

## What Cairn can comply with, and how

| Obligation | Where | Cairn's answer |
|---|---|---|
| Content removal orders | EU DSA, UK OSA | Works on T3 (server-readable). On T1/T2, the operator can remove *access* and the account, but cannot produce content it never held |
| Transparency reporting | DSA, various | Straightforward; commit to publishing |
| Notice-and-action / appeals | DSA | Moderator tooling requirement, tracked in `04-safety-architecture.md` §6 |
| Trusted flagger channels | DSA | Compatible; policy lists are a natural fit |
| Lawful data requests | Most | We hand over what exists — metadata, account data. For T1/T2 content, we cannot produce plaintext |
| Data subject access / erasure | GDPR | Design requirement; interacts awkwardly with immutable transcripts, see below |
| Data localization | Various | Self-hosting is the answer: run an instance in-jurisdiction |
| CSAM reporting | Many | Server-side hash matching on T3 and public surfaces; franking reports elsewhere |
| Age assurance | UK OSA, others | Open question, see below |

## What Cairn will not do

- **Key escrow or exceptional access.** Ever. It is a permanent target for compulsion and a
  standing vulnerability, and it would make every guarantee in the threat model false.
- **Mandatory client-side scanning.** See `04-safety-architecture.md` §3 — it is
  removable-by-recompile in an open-source client, so it would be security theatre *and* a
  betrayal of the user base.
- **Traceability mandates** requiring identification of a message's originator across the
  network (as proposed under India's IT Rules). This is incompatible with the design.
- **Silently weakening a tier** to satisfy a request. Tier immutability is absolute
  ([ADR-001](adr/001-tiered-encryption.md)).

If a jurisdiction requires any of these, Cairn does not operate there as an E2EE service.

## Self-hosting and liability

This needs to be unambiguous, because it is the question every prospective operator asks:

- **The operator of an instance is the service provider** for their instance and carries
  the corresponding obligations in their jurisdiction.
- **The Cairn project publishes software.** It does not operate third-party instances and
  cannot control them.
- **A flagship instance, if one exists, gets no protocol privileges** — but it does carry
  the operator obligations of wherever it is hosted.

Ship an **operator's guide** covering the obligations a self-hoster is taking on. Someone
running an instance for their friends may have no idea they have become a regulated
service provider in some readings. That guide is a safety feature.

## Export control

Cairn is cryptographic software, which brings export considerations (Wassenaar, US EAR).
Publicly available open-source encryption software is treated favourably in most regimes —
under the US EAR, published open-source encryption is generally not subject to the same
controls as proprietary crypto, subject to a notification requirement.

**Action item:** confirm the current notification requirement and file if applicable before
the first public release. This is cheap to do and awkward to fix retroactively.

## Age assurance — genuinely unresolved

The UK Online Safety Act and comparable regimes push toward age verification, and there is
a visible 2026 industry move in that direction. This is directly hostile to Cairn's other
commitments: robust age verification generally means collecting identity documents, which
is the opposite of a privacy-respecting product, and it is a honeypot besides.

**Current position, to be revisited:**

- Self-declared age at registration, with on-device filters defaulting on for minors
- No identity document collection on any instance the project operates
- Investigate privacy-preserving age attestation (zero-knowledge proofs of age) as the only
  approach compatible with both aims
- Operators in jurisdictions with stricter requirements must make their own call, and the
  operator's guide must tell them so

This is the least settled section of this document and the one most likely to force an
unpleasant decision.

## GDPR meets cryptographic transcripts

An erasure request against an immutable, hash-chained transcript is a genuine tension:

- Message content in T1/T2 is not held by the server, so there is little to erase there
- Franking evidence contains data about **both** parties by construction — erasing the
  sender's data may destroy a victim's evidence
- Metadata is server-held and is squarely in scope

**Needs a real answer before launch**, not after the first request arrives. Likely shape:
retention limits on franking evidence, and treating a report as a legitimate-interest
processing basis. Confirm with a lawyer.

## Sanctions

Instance operators may need to observe sanctions regimes. The project publishing open-source
software is a different question from an operator providing a service. Flag in the
operator's guide.

## Open questions

1. Which jurisdiction should the project entity sit in? It affects everything above.
2. Does a flagship instance exist at all? Not running one dramatically reduces exposure, at
   a real cost to adoption.
3. What is the retention policy for franking evidence — long enough to be useful, short
   enough to limit harm?
4. Who receives legal process, and is there a published transparency report and warrant
   canary?
5. Is there a plan for a jurisdiction that bans the software outright?

## Review

This document must be reviewed by a lawyer with technology and privacy experience before
any public launch, and re-reviewed whenever a major jurisdiction changes its rules. Nothing
in it should be relied on as legal advice in its current state.
