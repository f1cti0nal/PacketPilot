# Cryptomining (Stratum) detector — design

Status: design · 2026-06-24 · Feature: detect a host running the cleartext **Stratum** mining
protocol to a pool — cryptojacking / resource hijacking (T1496).

## Problem

A compromised host mining cryptocurrency (cryptojacking) is a top-impact outcome of an intrusion, yet
the engine had no signal for it. The Impact tactic was covered only by SYN-flood. Cleartext Stratum —
the dominant mining-pool protocol — carries unambiguous JSON-RPC method names on the wire, so it is
cheaply and reliably detectable without payload retention.

## Approach

A payload-signature sniff (like the cleartext-cred sniff) + the established detector seam — bounded,
**no deps, no dataset** (a protocol signature, not a pool-domain list that would go stale):
- `decode/mod.rs`: `sniff_stratum` matches the mining-specific JSON-RPC method tokens in a bounded
  TCP-payload peek and returns **which party sent it** — `StratumRole::Miner`
  (`mining.subscribe`/`authorize`/`submit`) or `Pool` (`mining.notify`/`set_difficulty`, which only a
  real pool sends). Only the role is derived; no payload retained. `PacketMeta.stratum`.
- `detect/mod.rs`: `observe_stratum` resolves `(miner, pool)` from the role + packet direction so
  both halves of one channel share a key (`StratumStat { miner_msgs, pool_msgs }`).
  `cryptomining_candidates` confirms a channel **only when a real pool responded** (`pool_msgs > 0` —
  a `mining.notify` that only an actual pool sends). This both filters scanner/probe traffic that
  merely emits Stratum tokens and *guarantees* the attribution (the pool is definitively the notify
  sender).
  `detect_cryptomining` → a **High** finding (T1496), miner-attributed. Incident stage 6 (Impact).
- `analyze/mod.rs`: feed the tracker per Stratum message. UI: `FindingKind` union + both `KIND_META`
  maps + `KIND_STAGE` + `CONTACT_NOUN` (a `Pickaxe` glyph).

## Scope / FP control

The Stratum method tokens are mining-specific (low signature FP). The candidate gate requires pool
confirmation (`pool_msgs > 0`), so scanner/probe traffic that only emits miner-side Stratum tokens —
or a one-sided capture — does not raise a finding (an acceptable miss vs a confident HIGH with
unverifiable attribution; this was an adversarial-review fix). Out:
TLS-wrapped Stratum (`stratum+ssl` — encrypted, invisible) and pool-domain reputation (a dataset).

## Invariants

No deps, no dataset. Payload-free (only the role enum retained). Bounded + deterministic. Parser
panic-free (length-guarded peek). Fills the Impact tactic alongside SYN-flood.
