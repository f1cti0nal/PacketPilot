# DGA (domain-generation-algorithm) detection — design

Status: design · 2026-06-24 · Feature: detect hosts resolving algorithmically-generated C2 domains
(ATT&CK T1568.002, Dynamic Resolution: Domain Generation Algorithms).

## Problem

PacketPilot detects DNS *tunneling* (high-volume, high-entropy, long labels of a **single** domain —
data smuggled in DNS) but not **DGA** — malware that generates and resolves **many distinct**
pseudo-random *registered* domains, cycling through them to find its live C2 rendezvous (Conficker,
Cryptolocker, Necurs, …). Different signature (breadth of random registered domains, not depth of one
tunnel), different ATT&CK technique, a real flagship-NDR gap.

## Approach

A behavioral detector on the existing DNS observe path — engine-only, no new deps:
- **Per-source tracker** (`DgaStats`): the set of distinct DGA-suspect *registered* domains a host
  resolved (bounded at `MAX_DGA_SUSPECT = 256`).
- **Registered-label scoring** (`registered_domain`): score the registrable label (second-from-last,
  no PSL) — **not** subdomains. This is the central FP control: `d1a2b3.cloudfront.net` has a random
  *subdomain* but a wordlike *registered* label (`cloudfront`), so it is never suspect. Reverse-DNS
  `.arpa`, IP literals, and single-label names are skipped.
- **Per-label heuristic** (`is_dga_label`): a deliberately *loose* test — an 8–40-char LDH label with
  a low vowel ratio, a long consonant run, or heavy digit use. Per-label precision is not the point.
- **Source-level gate** (`detect_dga`): flag a source only when it resolved ≥ `min_distinct_domains`
  (default **10**) *distinct* suspect registered domains. This count — not any single random-looking
  name — is the load-bearing signal, so isolated false-positive labels never produce a finding.
  Medium severity, escalating to High at ≥ 25 distinct domains. Finding `Dga`, C2 kill-chain stage.

## FP/FN control (why it won't cry wolf)

- A lone CDN hash / random SaaS apex: scored at the *registered* label and gated by the distinct
  count → no finding.
- A real DGA bot: dozens–hundreds of distinct random registered domains → comfortably over the floor.
- **Aggregation point** (review-hardened): the tracker keys on source IP, so a capture taken upstream
  of a recursive resolver, or on the WAN side of a NAT/CGNAT box, collapses every client's lookups
  onto one apparent source — which would self-flag from the union of everyone's random-looking apexes.
  `DgaParams.ignore_src` exempts known resolvers / gateways / DNS appliances; it is the load-bearing
  control here (an external/internal gate cannot help — internal resolvers are internal).
- **Punycode** (review-hardened): IDN `xn--` registered labels are ASCII-encoded non-Latin text, not
  generated randomness; their consonant-heavy encoding artifact is exempted in `is_dga_label` so
  IDN-heavy (CJK / Cyrillic / Arabic) populations are not flagged.
- Known limitations (acceptable for v1, documented): multi-part public suffixes (`x.co.uk` →
  registered label approximated as `co`) and dictionary/pronounceable DGAs (wordlike labels) are
  under-detected; a no-PSL, single-feature heuristic trades recall for a near-zero benign FP rate.

## Invariants

Engine-only; no new deps (pure std). Bounded memory (per-source set capped; tracker honors
`max_tracked_keys`). Deterministic order. Never panics on malformed names.
