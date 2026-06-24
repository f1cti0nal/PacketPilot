# HTTP request metadata (Host + User-Agent) — design

Status: design · 2026-06-24 · Feature: extract the HTTP request `Host` and `User-Agent` headers into
two per-flow columns — the HTTP analogue of the existing per-flow `sni` (TLS) column.

## Problem

PacketPilot surfaces the TLS `sni` per flow, but for plaintext HTTP the request `Host` and
`User-Agent` — two of the most-pivoted-on fields in any NDR — were dropped (the decode HTTP sniff set
only `app_proto = Http` and discarded the method). The `Host` reveals the virtual host actually
requested (vs the IP), and a malicious / scripted `User-Agent` (`sqlmap`, `curl`, `python-requests`,
beacon UAs) is a classic IOC.

## Approach

Engine-only header extraction (no new deps), reusing the decode L7 sniff + the existing header
helpers (`starts_with_ci` / `find_ci`, already used for cleartext-cred detection):
- `decode/mod.rs` (`http_header_value`): on an HTTP request (`sniff_http_method`), extract `Host` and
  `User-Agent`, anchored to the **start of a header line** and bounded to the header block (the
  request **body is never scanned** — truncated at the first blank line). The value is trimmed, kept
  to printable ASCII, and capped at `MAX_HTTP_HEADER` (256). Set on `PacketMeta.http_host` /
  `http_ua`.
- Threads through the per-flow-column pipeline like `sni`: sticky `FlowRecord.http_host` / `http_ua`
  → Arrow/Parquet columns 27/28 (`FLOW_PARQUET_VERSION` 8 → 9, 31 columns) → DuckDB view →
  `ppcap-wasm` `FlowDto` → UI (a Host chip in the flows table, Host + User-Agent fields in the drawer,
  the flows search index).

## Privacy

Consistent with the no-payload-retention contract and the `sni` precedent: only the derived `Host` +
`User-Agent` header *values* are kept (bounded, printable-only) — **never** the URI/query string
(which can carry tokens/PII), the request body, or any credential/cookie header (`Authorization` is
handled separately and yields only the *scheme*, never the secret).

## Scope

In: `Host` + `User-Agent` from a single-segment HTTP request. Out: method/URI/path columns (URI risks
query-param leakage), response headers, HTTP/2 (binary HPACK), cross-segment request reassembly.

## Invariants

Engine-only; no new deps. Bounded + panic-free header parse (every slice checked, 256-char cap).
Payload-free beyond the derived header values. Column shift to 31 with schema-drift / roundtrip /
threat_e2e positional readers updated in lockstep.
