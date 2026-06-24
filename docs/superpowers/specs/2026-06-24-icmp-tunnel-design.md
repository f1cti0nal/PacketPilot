# ICMP tunneling (covert-channel) detector — design

Status: design · 2026-06-24 · Feature: flag sustained, large-payload ICMP echo channels — the shape
of covert C2 / exfil over ICMP — as a new `icmp_tunnel` behavioral `Finding`.

## Problem

The engine's behavioral detectors (beacon, sweep, exfil, brute-force, lateral, DNS-tunnel, the TLS
detectors) all operate on TCP/UDP. **ICMP is a blind spot.** ICMP tunneling — smuggling data inside
the payload of ICMP echo request/reply messages — is a well-known covert-channel / exfil technique
(ptunnel, icmptunnel, Loki, the classic "ping tunnel"). A normal `ping` carries 32–56 bytes of
fixed filler at low volume; a tunnel carries large, variable payloads sustained over many messages.

## Approach

Two-part, reusing the existing per-packet fold pattern (the same shape as the DNS / cleartext-cred /
PII folds in the analysis loop):
1. **Decode**: capture the ICMP message **type** (first byte of the ICMP header) onto
   `PacketMeta.icmp_type` — previously the ICMP L4 arm was a no-op. `payload_len` is already seeded
   from the IP total length (the whole ICMP message), so the echo *data* size is `payload_len - 8`
   (the ICMP/ICMPv6 echo header is 8 bytes: type, code, checksum, id, seq).
2. **Detect**: per `(src, dst)`, accumulate echo count, total data bytes, and peak data
   (`BehaviorTracker.observe_icmp_echo`). A channel is flagged when it has **≥ `min_echoes`** echoes,
   a **mean data payload ≥ `min_large_data`** bytes, AND the destination is **external** (defaults
   32 / 512). Gating on the *mean* (not the peak) requires sustained large payloads; the external
   gate (mirroring `detect_exfil`) excludes intra-net diagnostics.

Only ICMP **echo request/reply** is counted (IPv4 types 8/0, IPv6 types 128/129) — error messages
and other ICMP are ignored.

## Severity & ATT&CK

- High severity (a covert C2 / exfil channel). Score 70.
- ATT&CK **T1095** (Non-Application Layer Protocol) + **T1048.003** (Exfiltration Over Unencrypted
  Non-C2 Protocol). Kill-chain stage **Exfiltration** (parallels the DNS-tunnel detector).
- Attributed to the echo `src` (consistent with the other behavioral detectors), so it correlates
  into the same per-host incident as a beacon/exfil from that host.

## False-positive control

Normal ping is **small** (32–56 B) and usually **low-volume**; requiring *all* of sustained volume
(≥32), large **mean** data (≥512 B), and an external destination excludes it. The mean gate (vs a
peak) means a single large PMTU/jumbo-frame probe among normal pings does not trip it; the external
gate excludes routine `ping -s`/monitoring to internal hosts (these are overwhelmingly diagnostics).
The external gate also resolves the bidirectional double-count: an echo *reply* travels external→
internal, whose destination is internal and is gated out, so only the outbound (client→external)
direction of a tunnel surfaces — one finding per channel. Thresholds are tunable via
`IcmpTunnelParams`. *(Calibration and the mean-vs-peak / external gate were tightened by the
adversarial review pass.)*

## Scope

In: IPv4 ICMP + IPv6 ICMPv6 echo; payload-free (only sizes, never the ICMP data content). Out:
deep payload inspection / entropy of ICMP data; non-echo ICMP covert channels (timestamp, address
mask); reassembling tunneled streams.

## Invariants

No new dependencies; C-free. Bounded memory: the `icmp` map is capped by `max_tracked_keys` like
every other per-key tracker map. No payload retained — only derived sizes/counts.
