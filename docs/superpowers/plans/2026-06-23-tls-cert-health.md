# TLS certificate-health detector — implementation plan

Spec: [2026-06-23-tls-cert-health-design.md](../specs/2026-06-23-tls-cert-health-design.md)

One vertical PR (engine + UI), mirroring the saved-filters / score-waterfall cadence.

## Step 1 — DER reader + X.509 leaf extraction (`engine/.../src/tls/der.rs`, `tls/cert.rs`)

- `der.rs`: a tiny bounds-checked DER walker in the house style (`.get(..)?`, `checked_add`,
  big-endian). Primitives:
  - `read_tlv(buf, pos) -> Option<(tag: u8, content: &[u8], next: usize)>` — short + long-form
    definite length (`0x80 | n`), bounds-checked, never panics.
  - helpers to iterate a SEQUENCE's children and to match an OID's raw bytes.
- `cert.rs`: `parse_leaf(der: &[u8]) -> Option<CertInfo>` walking
  `Certificate ::= SEQ { tbsCertificate SEQ {...}, sigAlg, sig }`:
  - skip optional `[0] version`, serial INTEGER, sigAlg SEQ;
  - `issuer` Name (RDNSequence) → canonical bytes for equality;
  - `validity` SEQ → `notBefore` / `notAfter` (UTCTime `YYMMDDhhmmssZ` → 20YY/19YY pivot at 50;
    GeneralizedTime `YYYYMMDDhhmmssZ`) → normalized `u64` `YYYYMMDDhhmmss`;
  - `subject` Name → canonical bytes (for self-signed) + extract CN (OID 2.5.4.3 = `55 04 03`);
  - `extensions [3]` → find SAN (OID 2.5.29.17 = `55 1D 11`), parse `GeneralNames`, collect
    `dNSName` (context tag `0x82`).
  - `CertInfo { not_before: u64, not_after: u64, issuer_raw: Vec<u8>, subject_raw: Vec<u8>,
    cn: Option<String>, sans: Vec<String> }`.
- Tests: hand-built DER fixtures (valid, self-signed, expired, multi-SAN, long-form length,
  truncated/malformed → None). Generate minimal DER inline in the test module.

## Step 2 — Health check + reassembler (`engine/.../src/tls/mod.rs`)

- `CertIssue` enum: `Expired | NotYetValid | SelfSigned | NameMismatch`; `as_str()` + `label()`.
- `check_cert_health(cert: &CertInfo, sni: Option<&str>, capture_yyyymmddhhmmss: u64) -> Vec<CertIssue>`
  - self-signed: `issuer_raw == subject_raw`.
  - expiry: compare normalized dates to capture time.
  - name match: SNI vs `sans` then `cn`, ASCII-lowercased, wildcard `*.x` matches one left label.
- `TlsCertReassembler`:
  - `watched: HashSet<(IpAddr,u16)>` (server endpoints, capped), `sni: HashMap<(IpAddr,u16,IpAddr,u16), String>`
    (client→server SNI, capped), `buffers: HashMap<(IpAddr,u16,IpAddr,u16), Vec<u8>>` (server→client
    flight, capped count, 16 KiB each), and accumulated `observations: Vec<CertObservation>`.
  - `observe(meta: &PacketMeta, frame: &RawFrame)`:
    1. ClientHello (`meta.app_proto == Tls`): insert watched `(dst_ip,dst_port)`; if `meta.sni`,
       record SNI for `(src,sport,dst,dport)`. (bounded inserts)
    2. else if TCP + `payload_len>0` + `(src_ip,src_port) ∈ watched`: `l4_payload(frame)` → append to
       the `(src,sport,dst,dport)` buffer (start a buffer only if payload begins a handshake record
       whose first message is ServerHello type 2; cap count + size). Try `find_certificate(buf)`;
       on success parse leaf, look up SNI by the reverse key, `check_cert_health`, push a
       `CertObservation { client, server, server_port, issues, subject_cn, sni, not_after }`, drop
       the buffer. On cap exceeded or a non-handshake record (appdata 23 / CCS 20) → drop buffer.
  - `find_certificate(buf) -> Option<&[u8]>`: walk TLS records (content_type 22), concatenate
    handshake bytes, locate handshake type 11, ensure its 3-byte length is fully present, return the
    first cert entry's DER (cert_list u24, then per-entry u24 len + der).
  - `into_observations(self) -> Vec<CertObservation>`.
- Bounds: `MAX_WATCHED = 4096`, `MAX_BUFFERS = 1024`, `MAX_BUF_BYTES = 16 * 1024`.
- Tests: feed synthetic ServerHello+Certificate byte streams (single- and multi-segment) and assert
  observations + issues; assert caps drop gracefully.

## Step 3 — Tracker + detector (`engine/.../src/detect/mod.rs`)

- `BehaviorTracker`: add `tls_certs: HashMap<(IpAddr,IpAddr,u16), TlsCertObservation>` keyed
  `(client, server, server_port)`; `observe_tls_cert(client, server, port, issues, summary)` (bounded
  insert, keep first/worst). `TlsCertCandidate` + `tls_cert_candidates(&self) -> Vec<..>` (sorted,
  deterministic).
- `TlsCertHealthParams { enabled: bool }` (Default `true`).
- `detect_tls_cert_health(tracker, params) -> Vec<Finding>`: one finding per candidate; severity via
  `worst issue → bump for ≥2`; `attack` = `["T1573"]` (+ `"T1557"` if name_mismatch); `evidence` =
  one bullet per issue + a remediation line; `title` = `TLS cert issue(s): <cn|server> -> server:port`.
- Add `FindingKind::TlsCertHealth` + `as_str()="tls_cert_health"` in `model/finding.rs`.
- Add arms to `stage_ordinal` (4), `stage_label` ("Command & Control"), `kind_phrase`
  ("presented a suspicious TLS certificate").
- Tests: tracker-fed candidates → assert finding fields, severity escalation, disabled switch.

## Step 4 — Wire into the pipeline (`engine/.../src/analyze/mod.rs`)

- `PipelineConfig`: add `tls_cert_health: TlsCertHealthParams` + Default.
- Construct a `TlsCertReassembler`; in the decode arm call `cert_reasm.observe(meta, &frame)` (frame
  still borrowed there). After drain: fold `cert_reasm.into_observations()` into the tracker, then
  `findings.extend(detect_tls_cert_health(&tracker, &cfg.tls_cert_health))`.
- Capture time for expiry = `max_seen_ts` (or the observation's own ts) → normalized `YYYYMMDDhhmmss`
  via `time::OffsetDateTime::from_unix_timestamp_nanos`.

## Step 5 — Report + lib exports (`engine/.../src/report/mod.rs`, `lib.rs`)

- `report::kind_label`: add `FindingKind::TlsCertHealth => "TLS Cert Health"`.
- `lib.rs`: `pub mod tls;` (and re-export the detector/params already via detect).
- Verify `export/mod.rs` needs no change (generic iteration) by building.

## Step 6 — UI (`ui/src/...`)

- `types.ts`: add `"tls_cert_health"` to the `FindingKind` union.
- `IncidentsPanel.tsx`: add `KIND_META["tls_cert_health"]` (label "TLS Cert", a `ShieldAlert`/`BadgeCheck`
  icon).
- New `components/triage/CertHealthPanel.tsx` mirroring `SignatureMatchesPanel`: filter
  `findings.filter(f => f.kind === "tls_cert_health")`, render a card per finding (title, severity
  chip, src→dst:port, issue evidence). Hidden when none.
- `Dashboard.tsx`: import + render `CertHealthPanel` near `SignatureMatchesPanel`.
- Tests: `CertHealthPanel.test.tsx` (renders findings, hidden when none) + a `tls_cert_health` finding
  in `test/fixtures.ts`.

## Step 7 — Verify gates, then PR

Engine: `cargo fmt`, `cargo clippy --all-targets -- -D warnings`, `cargo test --workspace` (from
`engine/`), C-gate (`cargo tree -p ppcap-core -e no-dev` — confirm no new C deps). UI: `npm run
build:wasm`, `npm run test:coverage` (80/70), `npm run build`. Then push branch
`feat/tls-cert-health`, open PR, watch CI green, merge (per the gh workflow: `--auto` does NOT wait
on this repo).
