# L2 host identity (MAC + OUI vendor) — design

Status: design · 2026-06-24 · Feature: surface the IP → MAC bindings observed via ARP, with a
best-effort device vendor from the MAC's OUI — local-segment asset identity.

## Problem

The ARP-spoofing detector already extracts every ARP sender's IP → MAC claim, but nothing *surfaced*
the MAC. A capture's local hosts had no L2 identity — yet "internal host `10.0.0.5` is a Raspberry Pi
/ an ESP IoT device / a VMware VM" is core asset-inventory value (spotting unmanaged/rogue devices,
VMs, IoT). All the data was already on the wire and decoded.

## Approach

An engine stats rollup + a small OUI vendor table + a dashboard panel — the proven passive-DNS
rollup-and-panel pattern, no new deps and **no large dataset**:
- `stats/mod.rs`: an `arp_macs: HashMap<IpAddr, [u8;6]>` map, folded in `observe_packet` from
  `PacketMeta.arp` **before** the IP-endpoint short-circuit (ARP frames carry no IP layer). First MAC
  per IP wins; bounded by `max_tracked_keys`. `finish` formats them into `summary.arp_hosts`
  (`ArpHost { ip, mac }`, top-64, ordered by IP). The field serializes via serde, so the UI receives
  it with no WASM API change.
- `lib/oui.ts`: a deliberately small, **high-confidence** OUI → vendor table (virtualization stacks,
  single-board / IoT silicon, a handful of rock-solid vendor prefixes). A match is reliable; an
  unmatched MAC shows bare — never a wrong guess.
- `cockpit/LocalHostsCard.tsx`: a "Local hosts" panel (IP · MAC · vendor chip). Hidden when no ARP.

## Scope

In: the IP ↔ MAC bindings + best-effort common-vendor labels. Out: the full IEEE OUI registry (a
large dataset — only common/identifiable prefixes are bundled), per-host fingerprint joining,
MAC-change/anomaly tracking (the ARP-spoof detector covers the multi-MAC case).

## Invariants

Engine-only stats addition; no new deps; no large dataset. Bounded (`arp_macs` capped, output
top-64). Deterministic order. The OUI table is conservative — only confidently-correct prefixes, so a
vendor label is reliable and absence is shown as the bare MAC.
