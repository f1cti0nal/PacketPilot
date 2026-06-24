# L2 host identity — implementation plan

Spec: [2026-06-24-l2-host-identity-design.md](../specs/2026-06-24-l2-host-identity-design.md)

Engine stats rollup + a small OUI table + a dashboard panel. One PR (direct to main). Mirrors the
passive-DNS rollup-and-panel pattern.

## Engine (`engine/crates/ppcap-core/src/`)

1. `model/summary.rs`: `ArpHost { ip, mac }`; `Summary.arp_hosts` (serde-default) + `Summary::empty()`;
   `enrich/reputation.rs` literal.
2. `stats/mod.rs`: `arp_macs: HashMap<IpAddr, [u8;6]>` (+ `new()`); fold in `observe_packet` from
   `p.arp` **before** the non-IP early-return (first MAC per IP wins, bounded); `format_mac` helper;
   build `arp_hosts` in `finish` (top-64, by IP). Test: ARP claim → IP/MAC, first-MAC-wins.

## UI (`ui/src/`)

3. `types.ts`: `ArpHost` + `arp_hosts` on the summary type. `lib/oui.ts`: a curated high-confidence
   OUI → vendor table + `vendorForMac`. `cockpit/LocalHostsCard.tsx`: IP · MAC · vendor list, hidden
   when empty. `components/Dashboard.tsx`: import + render.
4. Tests: `lib/oui.test.ts` (known/unknown/malformed) + `cockpit/LocalHostsCard.test.tsx`.

## Verify

Engine: full `cargo test -p ppcap-core` · `clippy`. UI: `test:coverage` · `build`. `build:wasm`
(serde carries the field — no WASM code change). Then commit direct to `main`.
