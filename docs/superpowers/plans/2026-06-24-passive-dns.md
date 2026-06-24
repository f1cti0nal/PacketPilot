# Passive DNS — implementation plan

Spec: [2026-06-24-passive-dns-design.md](../specs/2026-06-24-passive-dns-design.md)

Engine DNS-answer parser + a stats rollup + a dashboard panel. One PR (direct to main).

## Engine (`engine/crates/ppcap-core/src/`)

1. `decode/mod.rs`: `dns_skip_name` (compression-aware, panic-free) + `sniff_dns_answers` (A/AAAA IPs,
   bounded `MAX_ANSWERS`). `L7Hint::Dns { qname, answers }`; `l7_hint` fills answers; decode sets
   `meta.dns_answers`. `PacketMeta.dns_answers: Vec<IpAddr>` (+ all literal sites). Tests: extract
   A/AAAA + never-panic on arbitrary bytes.
2. `model/summary.rs`: `ResolvedDomain { ip, domain, resolutions }`; `Summary.resolved_ips`
   (serde-default) + `Summary::empty()`; `enrich/reputation.rs` literal.
3. `stats/mod.rs`: `resolved: HashMap<IpAddr, (String, u64)>` folded in `observe_packet` (answer IP →
   question domain, bounded); ranked into `resolved_ips` in `finish` (top-50). Test: rollup
   attribution.

## UI (`ui/src/`)

4. `types.ts`: `ResolvedDomain` + `resolved_ips` on the summary type. `cockpit/DnsResolutionsCard.tsx`
   (IP ← domain list), hidden when empty. `components/Dashboard.tsx`: import + render.
   `cockpit/DnsResolutionsCard.test.tsx`.

## Verify

Engine: full `cargo test -p ppcap-core` · `clippy`. UI: `test:coverage` · `build`. `build:wasm`
(serde carries the new summary field — no WASM code change). Focused review of the DNS parser
panic-safety + attribution. Then commit direct to `main`.
