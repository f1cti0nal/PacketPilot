# Magic-byte file-type + disguised-download detector — design

Status: design · 2026-06-24 · Feature: identify the *true* downloaded-file type from response-body
magic bytes (defeating a spoofed `Content-Type`) and raise a finding when an executable is served
disguised behind a benign content type — malware-delivery evasion (T1036).

## Problem

The downloads overview classifies from the HTTP response *headers* (`Content-Type` /
`Content-Disposition`) — exactly what malware spoofs. A dropper commonly serves an `.exe` as
`image/jpeg` or `text/html` to slip past content-type filtering. Header-only classification both
*misses* such payloads and offers no evasion signal. The fix is content-based: read the file's actual
leading magic bytes.

## Approach

Hardens the existing classifier + adds a low-FP detector — bounded (peek the response body's first
bytes in the same ≤1024-byte L7 sniff window), **no TCP reassembly, no deps**:
- `decode/mod.rs`: `http_body_magic` matches the body's leading bytes (after the header CRLF
  separator) against a magic table — PE/ELF/Mach-O → Executable, shebang → Script, CAB/ar → Installer,
  ZIP/RAR/7z/gzip/xz/bzip2 → Archive. `sniff_http_download` now returns `(kind, disguised)` where
  `kind = magic.or(header)` (content wins over declaration) and `disguised` is true when the magic is
  a native **executable** but the declared `Content-Type` is specifically benign (`is_benign_content_type`).
  The PE `"MZ"` magic is two printable letters, so it is gated on `looks_binary` (a control/non-ASCII
  byte in the first 16) to avoid flagging a text file that merely starts "MZ". Only the *class* + a
  bool are retained — no body bytes.
- `model/packet.rs`: `PacketMeta.download_disguised: bool`.
- `detect/mod.rs`: `FindingKind::DisguisedDownload`; a `(client, server) → DisguisedDlStat` tracker,
  `observe_disguised_download`, and `detect_disguised_download` → a **High** finding (T1036 + T1105),
  client-attributed. Incident arms: stage 4 (C2 / payload delivery).
- `analyze/mod.rs`: feed the tracker per disguised response (client = `dst_ip`, server = `src_ip`).
- UI: `FindingKind` union + both `KIND_META` maps + `KIND_STAGE` + `CONTACT_NOUN` (a `VenetianMask`
  glyph).

## Scope / FP control

The masquerade finding fires only on executable magic vs a *specifically* benign declared type;
generic `octet-stream` / `application/x-*` / absent types are **not** a disguise (an unlabeled binary
download is ordinary). This keeps it low-FP and alert-worthy. Out: full body reassembly + hashing +
known-bad-hash IOC matching (the next, bigger increment); chunked / gzip-encoded / split-across-packet
bodies are a documented coverage limitation (falls back to header classification).

## Invariants

No new deps; no reassembly. Privacy: only the class enum + a bool are retained, never body bytes.
Bounded + deterministic. Parser is panic-free (length-guarded slices over the bounded peek).
