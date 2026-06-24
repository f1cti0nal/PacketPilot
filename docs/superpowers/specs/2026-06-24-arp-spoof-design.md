# ARP-spoofing detection — design

Status: design · 2026-06-24 · Feature: detect ARP cache poisoning — one IP claimed by multiple MAC
addresses (ATT&CK T1557.002, Adversary-in-the-Middle: ARP Cache Poisoning). The engine's **first L2
detector**.

## Problem

PacketPilot's detectors are all L3+ (IP flows). ARP — the L2 address-resolution protocol — was decoded
only enough to count frames ("counted, never flowed"). ARP cache poisoning is a classic local-segment
MITM: the attacker sends forged ARP replies binding a victim IP (often the gateway) to the attacker's
MAC, so traffic is redirected through them. The tell is simple and reliable: **one IP, multiple MACs**.

## Approach

A behavioral L2 detector, engine-only, no new deps:
- `decode/mod.rs` (`parse_arp`): in the existing ARP branch, parse the IPv4-over-Ethernet ARP packet's
  sender IP→MAC binding into `PacketMeta.arp` (a small `ArpClaim`). Bounded, panic-free, payload-free;
  skips the unspecified `0.0.0.0` sender (ARP probe / DHCP DAD) and — review-hardened — an all-zero /
  broadcast sender MAC (never a legitimate ARP sender), so a malformed frame can't supply a phantom
  second MAC.
- `detect/mod.rs`: `BehaviorTracker.arp: HashMap<IpAddr, HashSet<[u8;6]>>` folds each claim (per-IP set
  of MACs, bounded). `detect_arp_spoof` flags an IP claimed by ≥ `min_macs` (default **2**) distinct
  MACs. High severity, T1557.002, Collection kill-chain stage (MITM positioning).
- Keying per-IP→set-of-MACs means proxy-ARP (one MAC answering for many IPs) does **not** trigger —
  only the genuine poisoning shape (many MACs for one IP) does.

## FP control

The 2-MAC signal is the canonical detection, but legitimately mobile IPs exist (VRRP/HSRP/CARP
failover, NIC teaming, a DHCP-churned address, VM migration). An `ArpSpoofParams.ignore_ips` allowlist
exempts those virtual / migrating IPs (mirrors the lateral / DGA / port-scan allowlists).

## Scope

In: the per-IP distinct-MAC count with a min-macs floor + an ignore-ips allowlist. Out: ARP flood /
rate signals, gratuitous-ARP-storm detection, IPv6 NDP spoofing (a separate protocol).

## Invariants

Engine-only; no new deps. Bounded memory (per-IP MAC set + map both capped). Panic-free ARP parse.
Deterministic order. Payload-free (only the derived IP→MAC claim is kept).
