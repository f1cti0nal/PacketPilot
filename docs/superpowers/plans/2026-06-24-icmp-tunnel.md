# ICMP tunneling detector — implementation plan

Spec: [2026-06-24-icmp-tunnel-design.md](../specs/2026-06-24-icmp-tunnel-design.md)

One vertical PR (engine + UI). Surfaces via incidents like the other behavioral detectors — no new
panel.

## Engine (`engine/crates/ppcap-core/`)

1. `model/packet.rs`: add `icmp_type: Option<u8>` to `PacketMeta` (+ all struct-literal sites:
   decode constructor, 5 test literals, 1 integration-test literal).
2. `decode/mod.rs`: in the L4 dispatch, `Transport::Icmp | Transport::Icmpv6 => meta.icmp_type =
   l4.first().copied()`. Test: an ICMP echo frame sets `icmp_type` + `payload_len`.
3. `model/finding.rs`: `FindingKind::IcmpTunnel` + `as_str` `"icmp_tunnel"`.
4. `detect/mod.rs`: `IcmpStats` (echoes / data_bytes / max_data) + `observe_icmp_echo` (bounded);
   `IcmpTunnelCandidate` + `icmp_tunnel_candidates(min_echoes, min_large_data)` (gates on the
   sustained **mean**); `IcmpTunnelParams` (enabled / min_echoes 32 / min_large_data 512) +
   `detect_icmp_tunnel` (High, T1095 + T1048.003, **external-destination gate** like `detect_exfil`);
   `stage_ordinal` (5), `stage_label` ("Exfiltration"), `kind_phrase` ("tunneled data over ICMP").
5. `analyze/mod.rs`: `PipelineConfig.icmp_tunnel`; per-packet fold (echo request/reply →
   `observe_icmp_echo(src, dst, payload_len - 8)`); `detect_icmp_tunnel` call.
6. `report/mod.rs`: `kind_label`. `lib.rs`: export `IcmpTunnelParams`.
7. Tests: detector (sustained large echoes flagged; ordinary ping / low-volume / disabled not),
   decode (icmp_type + payload_len).

## UI (`ui/src/`)

8. `types.ts`: `"icmp_tunnel"` in the `FindingKind` union.
9. `IncidentsPanel` + `IncidentHero` `KIND_META` (label "ICMP Tunnel", `Waypoints`); IncidentHero
   `KIND_STAGE` ("Exfiltration").

## Gates

Engine: `fmt` · `clippy -D warnings` · `test` · C-free gate · `wasm32`. UI: `build:wasm` ·
`test:coverage` (80/70) · `build`. Then adversarial review, PR, watch CI, merge on local gates.
