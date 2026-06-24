# Passive DNS (resolved-from domain) — design

Status: design · 2026-06-24 · Feature: parse DNS answer records so each resolved IP is attributed to
the domain it came from — passive DNS for IP attribution.

## Problem

PacketPilot parses DNS *question* names (for tunneling / DGA) but discarded DNS *answers*. So when an
analyst sees a flow to a suspicious IP, there was no way to learn *which domain* resolved to it — the
single most useful piece of attribution ("`93.184.216.34` ← `evil.example`"). The TLS side has SNI;
DNS answers were unused.

## Approach

Engine-only DNS answer parsing + a stats rollup + a dashboard panel, no new deps:
- `decode/mod.rs` (`sniff_dns_answers`): walk a DNS response's answer section — `dns_skip_name`
  handles label sequences and compression pointers (a `0xC0` pointer ends the name in 2 bytes; it is
  **not** followed, so there is no pointer-loop) — and extract the `A` (type 1) / `AAAA` (type 28)
  record IPs. Defensive throughout (every index bounds-checked, bounded by `MAX_ANSWERS`,
  question/answer counts capped) — the same never-panic discipline as `sniff_dns_qname`. Set on
  `PacketMeta.dns_answers` (paired with the response's `dns_qname`).
- `stats/mod.rs`: `observe_packet` maps each answer IP → the question domain (first domain wins, count
  bumped) in a `resolved` map bounded by `max_tracked_keys`. `finish` ranks it into
  `summary.resolved_ips` (`ResolvedDomain { ip, domain, resolutions }`, top-50). The field serializes
  via serde, so the UI receives it with no WASM API change.
- `cockpit/DnsResolutionsCard.tsx`: a "Passive DNS" panel listing `IP ← domain` mappings.

## Scope

In: `A`/`AAAA` answer IP → question-name mapping, ranked. Out: enriching the per-IP threat cards
inline (deferred), CNAME-chain resolution (the IP is attributed to the *queried* name, which is the
useful one), reverse-PTR.

## Invariants

Engine-only; no new deps. Panic-free, bounded DNS parse (every slice checked; compression pointers not
followed). Bounded rollup (`resolved` capped, output top-50). Deterministic order. Transient — only
the derived IP→domain mapping is kept, not the DNS payload.

Review-hardened: the question-skip **bails** (no mapping) above a small qdcount bound rather than
truncating — a truncated skip on an attacker-controlled payload could leave crafted question bytes to
be misread as a fake answer RR, injecting a wrong IP→domain attribution. (Real responses carry
qdcount == 1.)
