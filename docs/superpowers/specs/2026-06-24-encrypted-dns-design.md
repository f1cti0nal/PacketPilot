# Encrypted DNS (DoH/DoT) visibility — design

Status: design · 2026-06-24 · Feature: surface client hosts resolving via DNS-over-HTTPS or
DNS-over-TLS — the resolution passive DNS can't see.

## Problem

Passive DNS ([2026-... resolved_ips]) attributes plaintext DNS answers to domains. But DoH (DNS over
HTTPS) and DoT (DNS over TLS) encrypt the lookup, so that traffic is a **blind spot** — and a known
malware-evasion channel (C2 domain resolution hidden inside HTTPS to a public DoH resolver, bypassing
DNS-based monitoring/filtering). Nothing flagged which hosts use it.

## Approach

An engine stats rollup + a dashboard panel — the proven passive-DNS / L2 rollup-and-panel pattern, no
deps, no large dataset:
- `stats/mod.rs` (`observe_scored_flow`, where the SNI rollup already lives):
  - **DoH**: a TLS flow whose SNI is a known DoH resolver (`DOH_ENDPOINTS`, exact or proper-subdomain
    match with a dot boundary so `evil-dns.google` can't spoof it). The resolver listens on `:443`,
    so the *client* is the other endpoint (`client_endpoint(key, 443)`; `None` — not recorded — when
    neither side uses that port, so the role is never guessed wrong).
  - **DoT**: a flow to the IANA DoT port `:853`, attributed to the client the same way; the resolver
    is labelled by its IP.
  - Both fold into a bounded `(client, resolver) → flows` map → `summary.encrypted_dns`
    (`EncryptedDnsHost`, top-64). serde-default, so the UI gets it with no WASM API change.
- `cockpit/EncryptedDnsCard.tsx`: a "Encrypted DNS" panel (`host → resolver · ×flows`). Hidden when
  none seen.

## Scope

In: DoH-by-SNI + DoT-by-port visibility, client-attributed. Out: decrypting DoH (impossible —
ciphertext); per-query domains (encrypted); a `Finding` (legit DoH is common — this is informational
visibility, not an alert, mirroring the downloads overview).

## Invariants

Engine-only stats addition; no deps; no large dataset. Bounded + deterministic order. The DoH table
is curated/high-confidence (exact + dot-bounded subdomain match → no suffix spoofing). Client
attribution fails safe (records nothing when the server port is ambiguous).
