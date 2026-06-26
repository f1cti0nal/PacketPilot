# File carving — hash + known-bad IOC — design

Status: design · 2026-06-24 · Feature: carve cleartext HTTP file downloads, hash them, surface the
SHA-256 as an IOC, and raise a finding for any matching an embedded known-bad set. The headline
"file-level visibility" capability.

## Problem

The engine saw *that* files were downloaded (the downloads overview, from headers) and *what type*
(magic bytes), but never the file itself — so it could not produce the single most useful file IOC:
the **SHA-256**, which an analyst looks up in VirusTotal / a threat feed. And it could not confirm a
*known* malware download. That requires reassembling the response body, which the engine had no path
for (only a bounded TLS-handshake reassembler).

## Approach

A bounded, **streaming** HTTP-body carver (`carve/mod.rs`), fed every packet in the analysis pass
exactly like `TlsCertReassembler`, plus the `FindingKind` seam:
- **Streaming hash, no buffering** — the body is folded through the vendored streaming `Sha256` as
  bytes arrive, so memory is O(1) per flow regardless of file size. Only the small header prefix is
  held (transiently, until CRLFCRLF).
- **In-order via TCP seq** — `l4_payload` exposes the segment's sequence number. Bytes are placed by
  offset: a **gap aborts** the carve (never hash a wrong byte range), a pure retransmit is skipped, a
  partial overlap consumes only the fresh tail. Out-of-order / lossy captures simply yield no carve.
- **Length-delimited, uncompressed only** — `Content-Encoding` (compressed → hash ≠ file hash) and
  `Transfer-Encoding: chunked` (not de-chunked) abort rather than hashing wrong bytes. The common
  malware-delivery case (a plain `Content-Length` binary) is covered.
- **Known-bad set** — a tiny embedded SHA-256 set (the EICAR test file is the canonical, verifiable
  entry; deployments extend it). A match → `FindingKind::MalwareDownload` (Critical, T1105),
  client-attributed.
- At EOF: every carved file → `summary.carved_files` (the IOC list: client, server, sha256, size,
  known_bad); each known-bad → a finding (correlated into incidents).

## Scope

In: cleartext HTTP, `Content-Length`, uncompressed, in-order (gap/overlap/retransmit-aware). The
hash IOC for *every* carved download + a finding for known-bad. Out: chunked / compressed bodies
(documented misses, never wrong hashes), TLS-wrapped downloads (encrypted), a large bundled hash
feed (the set is curated/small), YARA (a C dep — conflicts with the no-C-deps invariant; hand-rolled
hash matching instead).

## Invariants

No new deps; no large dataset. O(1) memory per flow (streaming hash); bounded flow count + size cap
+ capped observation/IOC list. **Never surfaces a wrong hash** — any reassembly ambiguity aborts.
Only the hash + size + endpoints are retained — **no file bytes**. Client-attributed finding.

## Adversarial-review fixes (load-bearing)

The review caught two real defects, both fixed + regression-tested:
- **HIGH — mid-stream clobber.** `observe()` originally restarted a carve on *any* `HTTP/`-prefixed
  segment, so a body segment beginning `HTTP/` (sender-controlled TCP segmentation → attacker can
  suppress the true hash / poison the IOC list, and benign `.http`/WARC files trip it) reset the
  in-flight carve. Fix: only (re)start when **no carve is in flight** for the key — body bytes that
  begin `HTTP/` fall through to the hasher as ordinary content.
- **MEDIUM — table never evicted.** The 256-flow cap was consumed by the *cumulative* count of HTTP
  flows (carving silently died after 256 downloads on busy traffic). Fix: **reclaim a slot the
  instant a carve completes/aborts**, plus **idle eviction** under cap pressure so stalled responses
  can't exhaust it.
Also bounded the observation Vec + the `carved_files` list (known-bad first) for the memory invariant.
