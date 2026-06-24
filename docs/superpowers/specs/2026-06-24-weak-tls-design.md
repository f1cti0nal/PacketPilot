# Weak / deprecated TLS detector — design

Status: design · 2026-06-24 · Feature: flag servers that negotiate deprecated TLS versions or weak
cipher suites, as a new `weak_tls` behavioral `Finding`. Sibling of the cert-health detector
([2026-06-23-tls-cert-health-design.md](2026-06-23-tls-cert-health-design.md)).

## Problem

The cert-health detector reads the server's **Certificate** message. The same server flight begins
with a **ServerHello**, which carries the *negotiated* protocol version and cipher suite — both in
**cleartext for every TLS version** (the ServerHello itself is never encrypted, even in TLS 1.3,
where the real version moves into the `supported_versions` extension). Deprecated protocols
(SSL 3.0 / TLS 1.0 / 1.1) and weak ciphers (NULL / anonymous / EXPORT / RC4 / DES / 3DES) are a
direct, observable interception/compliance risk that the engine did not surface.

## Why this is a cheap, synergistic increment

The cert-health reassembler ([`crate::tls::TlsCertReassembler`]) already buffers the server flight
and gates buffer creation on a ServerHello. The negotiated version+cipher are in that very
ServerHello, so this detector reuses the existing reassembly with **no new parsing infrastructure
and no new dependencies** — it parses the ServerHello out of the same accumulated buffer.

## Scope

In:
- Parse `(version, cipher)` from the cleartext ServerHello (legacy_version, with the
  `supported_versions` extension taking precedence — the authoritative version in TLS 1.3).
- Flag **deprecated versions** (< TLS 1.2) and a curated table of **weak cipher suites** (NULL /
  anon / EXPORT / RC4 / single-DES / 3DES), with IANA names.
- New `FindingKind::WeakTls`, attributed to the **client** (`src` → server `dst:port`) — consistent
  with cert-health, so it correlates into the same per-host incident.
- Surfaced in the broadened "TLS issues" panel alongside cert-health, plus incidents / threat cards /
  report / exports automatically.

Out (deferred): QUIC; full cipher-suite registry (a missing weak suite is a false negative, not a
correctness bug); key-size / signature-algorithm grading; downgrade-attack correlation across the
ClientHello's offered list.

## Severity & ATT&CK

- Worst single reason drives severity: **High** = NULL / anonymous / EXPORT cipher or SSL 3.0;
  **Medium** = RC4 / single-DES; **Low** = 3DES or a deprecated-version-only TLS 1.0 / 1.1 (kept low
  to avoid flooding real captures, where legacy TLS 1.0/1.1 remains common).
- ATT&CK **T1040** (Network Sniffing) — weak/deprecated TLS leaves the session interceptable.
- Kill-chain stage: **Collection** (the weakness enables on-path data collection), consistent with
  the cleartext-PII detector's framing.

## Correctness notes

- The ServerHello carries version+cipher within its first ~43 bytes, normally inside the first TCP
  segment. To avoid a false negative under (adversarial) micro-segmentation, the parse is **retried
  on the reassembled buffer** after each segment and recorded once per flight (a `FlightBuf`
  `weak_parsed` flag) — the same reassembly discipline the certificate path uses. (Found by the
  adversarial review pass.)
- Bounded memory: shares the reassembler's capped flight buffers; the tracker's `weak_tls` map is
  bounded like every other per-key map.
- TLS 1.3 ServerHellos pin `legacy_version` to 0x0303 and put the true version in
  `supported_versions` — the parser reads the extension, so TLS 1.3 is **not** misflagged.
