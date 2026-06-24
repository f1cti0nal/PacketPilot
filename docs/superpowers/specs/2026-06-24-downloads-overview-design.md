# HTTP downloads overview — design

Status: design · 2026-06-24 · Feature: classify notable file downloads served over HTTP (executable /
script / installer / archive) from response headers, and surface them as an informational panel.

## Problem

The product had **no file-transfer awareness** — a capture full of HTTP traffic gave no signal about
*what files* moved across the network. Malware delivery (an executable, a PowerShell script, a macro
archive pulled over cleartext HTTP) is a top intrusion vector, yet nothing surfaced it. This is the
most self-contained slice of "file carving" — achievable **without TCP-stream reassembly or a YARA
dependency** (both of which conflict with the engine's invariants).

## Approach

Header-only classification + the proven stats rollup-and-panel pattern. No reassembly, no new deps:
- `decode/mod.rs`: `sniff_http_download` runs on the same bounded payload peek as the other L7 sniffs.
  It fires only on an HTTP **response** (`HTTP/` status-line prefix — a request line merely *contains*
  `HTTP/` later, so it is excluded), reads `Content-Type` + the `Content-Disposition` filename
  extension (reusing `http_header_value`, which already ASCII-filters + bounds the value), and maps
  them to a `DownloadKind` (Executable / Script / Installer / Archive) via curated MIME + extension
  tables. Extension match is **exact** (last-dot split) so `data.json` is never read as a `.js`
  script. The body is never read; only the *class* (an enum) is retained — no filename, no bytes.
- `stats/mod.rs`: a `(client, server, DownloadKind) → count` map, folded in `observe_packet`. A
  response travels server→client, so `dst_ip` is the client and `src_ip` the server. Bounded by
  `max_tracked_keys`; `finish` ranks by count → `summary.downloads` (top-64). serde → no WASM change.
- `cockpit/DownloadsCard.tsx`: a "Downloads" panel — `kind · client ← server (×count)`, the class
  colored by risk (executable loudest). Hidden when none seen.

## Scope

In: the notable-file-class overview from response headers. **Informational, not an alert** — so the
inherent false-positive problem of flagging every executable download (legit installers are common)
is avoided. Out: TCP-stream reassembly, body magic-byte verification (defeats Content-Type spoofing
but needs reassembly), file hashing, YARA (C dependency — conflicts with the C-free gate).

## Invariants

No new deps; no reassembly. Privacy: only `DownloadKind` is retained — never the filename or body.
Bounded + deterministic order. Parser operates on already-ASCII-filtered header values (no
char-boundary panic surface) and never reads the body.
