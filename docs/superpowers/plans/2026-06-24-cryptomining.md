# Cryptomining (Stratum) detector — implementation plan

Spec: [2026-06-24-cryptomining-design.md](../specs/2026-06-24-cryptomining-design.md)

A payload-signature sniff + the established detector seam. Direct to main.

## Engine (`engine/crates/ppcap-core/src/`)

1. `model/packet.rs`: `StratumRole` enum (Miner/Pool) + `PacketMeta.stratum: Option<StratumRole>`
   (+ the 7 PacketMeta literal sites incl. `tests/flow_symmetry`).
2. `decode/mod.rs`: `sniff_stratum(transport, payload)` (TCP-only, bounded 512B peek, mining-method
   tokens via `find_ci`) → role; set `meta.stratum`; import `StratumRole`. Test: role classification
   + non-Stratum/non-TCP/empty → None.
3. `model/finding.rs`: `FindingKind::Cryptomining` + `as_str`. `report/mod.rs`: `kind_label`.
4. `detect/mod.rs`: `CryptominingCandidate` + `StratumStat { miner_msgs, pool_msgs }` tracker field
   (+ `new()`), `observe_stratum` (role→miner/pool, bounded via at-cap check then `entry().or_default()`),
   `cryptomining_candidates` (gate `pool_msgs>0` — pool confirmation required; review fix),
   `CryptominingParams` + Default,
   `detect_cryptomining` (High, T1496), incident arms (stage 6 / Impact / "mined cryptocurrency to a
   pool"); import `StratumRole`. Tests: confirmed channel + lone-probe-not-flagged + disabled.
5. `analyze/mod.rs`: `PipelineConfig.cryptomining` + Default + feed + `findings.extend`. `lib.rs`:
   re-export `CryptominingParams`.

## UI (`ui/src/`)

6. `types.ts` `FindingKind` union; `cockpit/IncidentHero.tsx` (KIND_META + KIND_STAGE + CONTACT_NOUN,
   `Pickaxe`); `components/triage/IncidentsPanel.tsx` KIND_META.

## Verify

Engine: full `cargo test -p ppcap-core` + `clippy`. UI: `test:coverage` + `build`. `build:wasm`.
Adversarial review (parser/signature · attribution+FP-gate · bounds+wiring). Commit direct to main.
