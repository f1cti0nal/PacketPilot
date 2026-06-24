# TLS certificate-health detector — design

Status: design · 2026-06-23 · Feature: passive detection of self-signed / expired / name-mismatched
server TLS certificates, surfaced as a new behavioral `Finding`.

## Problem

PacketPilot already fingerprints the **client** side of TLS (SNI / JA3 / JA4 from the ClientHello)
but never looks at the **server's** certificate. A self-signed, expired, or hostname-mismatched
server certificate is a classic tell of C2 infrastructure, interception (AiTM), and misconfiguration
— and it is the last behavioral detection listed in PROJECT-SPEC §B ("self-signed/expired certs")
that the engine does not yet implement.

## Hard constraint that bounds the feature

The X.509 chain lives in the server's **Certificate** handshake message (handshake type 11), which
arrives **after ServerHello** in the server→client direction. The engine today does **no**
server-side TLS parsing and **no** TCP reassembly — it only sniffs the client's first-packet
ClientHello.

Critically, **TLS 1.3 encrypts the Certificate message** (it is sent under handshake keys). Passive
capture can therefore only read the certificate for **TLS 1.0–1.2**, where ServerHello → Certificate
is in cleartext. This is an inherent property of passive analysis, not a choice. v1 targets cleartext
certs; TLS 1.3 and QUIC (cert in 1-RTT) are out of scope and documented as such.

## Scope (v1)

In:
- Extract the **leaf** certificate (first entry) from the cleartext server Certificate message over
  **TCP** for **TLS ≤ 1.2**.
- A **bounded, in-order server-flight reassembler** (no full TCP stack): per-flow byte buffer capped
  at 16 KiB, a bounded set of watched server endpoints, in-order arrival assumed. Reordering / loss /
  truncation → no certificate parsed → no finding (safe-by-omission).
- A **hand-rolled minimal DER reader** + X.509 leaf field extraction (no new deps — same house style
  as the vendored MD5/SHA-256/AES): validity `notBefore`/`notAfter`, issuer DN, subject DN (+ CN),
  `subjectAltName` dNSNames.
- Health checks, evaluated against the **capture timestamp** (not wall-clock) and the flow's
  ClientHello **SNI**:
  - `expired` — `notAfter` < capture time
  - `not_yet_valid` — `notBefore` > capture time
  - `self_signed` — issuer DN == subject DN
  - `name_mismatch` — SNI present and matched by neither a SAN dNSName nor the CN (wildcard `*.`
    supported)
- New `FindingKind::TlsCertHealth`, **attributed to the client** (`src_ip` = client, `dst_ip` =
  server, `dst_port` = server port) so it correlates into the same per-host incident as a beacon /
  exfil to the same destination.
- UI: a dedicated **Cert Health** panel (mirrors `SignatureMatchesPanel`) + the finding flows
  through incidents, threat cards, HTML report, and STIX/CSV/MISP/CEF exports automatically.

Out (deferred):
- TLS 1.3 (encrypted cert), QUIC.
- Full chain / CA-trust validation, OCSP/CRL/CT, key-strength/weak-signature checks.
- Out-of-order TCP reassembly.
- Per-flow cert columns in the Parquet flow table / flows UI (finding is the surface in v1).

## Severity & ATT&CK

- Base severity by worst issue: `name_mismatch` → High; `self_signed` → Medium; `expired` /
  `not_yet_valid` → Low. Two or more issues escalate one band (e.g. self-signed **and** expired →
  High; self-signed **and** name_mismatch → High). Score sits in the band.
- ATT&CK: `T1573` (Encrypted Channel) for self-signed/expired anomalous TLS; add `T1557`
  (Adversary-in-the-Middle) when `name_mismatch` is present.
- Kill-chain stage: **Command & Control** (stage 4), alongside Beacon / RuleMatch.

## Data flow

```
ClientHello (client→server, existing sniff) ── records watched server (dst_ip,dst_port) + SNI
ServerHello+Certificate (server→client)     ── reassembler buffers server flight (bounded, in-order)
   └─ Certificate message (type 11) complete ─ extract leaf DER
        └─ minimal DER/X.509 walk ─ {not_before, not_after, issuer, subject, cn, sans}
             └─ check_cert_health(cert, sni, capture_ts) ─ Vec<CertIssue>
                  └─ BehaviorTracker.observe_tls_cert(client, server, port, issues, summary)
                       └─ detect_tls_cert_health(tracker, params) ─ Vec<Finding{TlsCertHealth}>
```

The reassembler is fed inside the existing single streaming pass in `analyze`, reusing the
`decode::l4_payload(&frame)` helper (already `pub(crate)`, used by drill-down) to read the raw TCP
payload + seq — **no change to the `decode_frame` signature**. `l4_payload` is only called for TCP
packets whose source matches a watched server endpoint (gated cheaply on a bounded set), so the
common path is untouched.

## Compile-enforced edit sites (closed matches on `FindingKind`)

Adding the variant forces arms in: `model/finding.rs` (`as_str`), `detect/mod.rs` (`stage_ordinal`,
`stage_label`, `kind_phrase`), `report/mod.rs` (`kind_label`). Exports (`export/mod.rs`) iterate
findings generically (via `as_str`/`attack`/`dst_ip`) → new kind works with no export change. UI:
`types.ts` union + `IncidentsPanel` `KIND_META` (has a fallback but we add an explicit entry).

## Invariants preserved

- **No payload retention beyond the bounded handshake buffer**, which is freed the moment the
  Certificate parses or the cap is hit. Only derived booleans/strings (issue kinds, subject CN, SNI)
  survive into the finding — never key material or full cert bytes.
- **C-free / no new deps**: DER/X.509 parsing is hand-rolled; date math uses the already-present
  pure-Rust `time` crate (UTC-from-unix only).
- **Bounded memory**: capped watched-endpoint set, capped concurrent buffers, 16 KiB/buffer cap.
- **Deterministic finding order** (sorted), matching the other detectors.
