# gzip capture ingest — Design Spec

**Status:** approved design, pre-plan
**Date:** 2026-06-23
**Branch:** `feat/gzip-ingest`

## Goal

Load `.pcap.gz` / `.pcapng.gz` (gzip-compressed) captures directly — completing the documented gzip scaffold so compressed captures "just work" on the CLI, desktop, and browser.

## Architecture

Wire a **pure-Rust** inflate backend into the existing `reader/gzip.rs` scaffold and restore the `Magic::Gzip` dispatch in `reader::open_reader`. A gzip member is inflated with `flate2::read::MultiGzDecoder` (handles the multi-member case); the **decompressed** stream is then re-sniffed and dispatched to the classic-pcap or pcapng source — implemented as a recursion through the format-detection with a small depth guard against gzip-nested-in-gzip. Because every surface funnels through `open_reader` (CLI `open`, WASM `analyze`/`extract_packets`/`carve_pcap`, Tauri `analyze_capture`), gzip support flows everywhere automatically; the only extra UI work is offering `.gz` in the file picker.

The engine stays C-compiler-free: `flate2` is added with `default-features = false, features = ["rust_backend"]` (the pure-Rust **miniz_oxide** backend), NOT the default zlib/`zlib-sys` C backend.

**Tech stack:** Rust (`ppcap-core` reader; `engine/Cargo.toml` workspace dep); minor TS (the load dialog filters). No engine logic beyond the reader.

## Global Constraints

- **C-compiler-free gate stays green.** The CI gate (`.github/workflows/ci.yml`) runs `cargo tree -p ppcap-core -e no-dev | grep -Ei "zstd-sys|lz4-sys|cc |cmake|bzip2-sys|openssl-sys|zlib-sys"` and FAILS on any match. `flate2` MUST use `default-features = false, features = ["rust_backend"]` so it pulls `miniz_oxide` (pure Rust) + `crc32fast` (pure Rust) and NOT `zlib-sys`/`cc`.
- **Pure-Rust only, as the scaffold mandates** (`reader/gzip.rs` NOTE TO INTEGRATOR). The `flate2` `MultiGzDecoder` snippet is the documented drop-in.
- **Bounded, panic-free, streaming.** No full-file buffering — the gzip inflates lazily through the existing 64 KiB streaming refill, so a gzip bomb is bounded by the same per-capture analysis caps (max flows/packets) as any large capture. A corrupt/truncated gzip surfaces a typed `PpError` (the inflate `io::Error` maps to an engine error), never a panic.
- **Depth guard:** gzip-nested-in-gzip is rejected with a clear error (a single decompression level; the realistic `.pcap.gz` is one level). This bounds the open-time recursion.
- **Public surface unchanged.** `open`/`open_reader` signatures, `GunzipReader`'s public type, and every downstream caller (WASM/Tauri/CLI) are untouched — gzip flows through the existing path. No new WASM export or Tauri command.
- **wasm32 builds.** `flate2 rust_backend` (miniz_oxide) compiles on `wasm32` (ppcap-wasm builds ppcap-core); `build:wasm` must succeed. ppcap-core already uses `{ workspace = true }` deps that ppcap-wasm builds — `flate2` follows that proven pattern.
- Engine gates: fmt, clippy `-D warnings`, `test --workspace`, `--features online`, the C-free gate. UI gate under the locked toolchain (vitest 1.6.1; 80/70) incl. `build:wasm`. Stage specific files.

## Reference: the seams (verified)

```rust
// reader/gzip.rs  GunzipReader<R> shell (read() returns ErrorKind::Unsupported today); the module
//   doc comments give the EXACT MultiGzDecoder<R> replacement snippet to drop in.
// reader/mod.rs:122 enum Magic { …, Gzip }  ; :132 Magic::sniff (0x1f 0x8b -> Gzip)
// reader/mod.rs:235 pub fn open_reader<R: Read + 'static>(reader, size_hint) -> Result<Box<dyn PacketSource>>
//   :252 match Magic::sniff(&head) { Some(Magic::Gzip) => Err(UnknownFormat(…)) /* REJECT today */,
//         PcapLeUs/.. => LegacyPcapSource::new(prefixed, …).prime(), PcapNg => PcapNgSource::new(prefixed).prime(), None => UnknownFormat }
//   peek4 + PrefixReader re-emit the sniffed 4 bytes; `prefixed` is the un-peeked stream.
// reader/mod.rs:222 pub fn open(path) — File -> open_reader(file, size_hint)
// engine/Cargo.toml:12 [workspace.dependencies]  (add flate2 here; ppcap-core refs `{ workspace = true }`)
// .github/workflows/ci.yml:46-51 the C-free gate grep (lists zlib-sys — must NOT appear)
// ui/src/components/layout/LoadCaptureDialog.tsx:169  accept=".pcap,.pcapng,.cap,.json,.parquet,application/json"
// ui/src/lib/platform.ts:40-43  Tauri open({ filters: [{ name:"Captures", extensions:["pcap","pcapng","cap"] }] })
```

## Components

### 1. Dependency — `engine/Cargo.toml` + `ppcap-core/Cargo.toml`
Add to `[workspace.dependencies]`:
```toml
flate2 = { version = "1", default-features = false, features = ["rust_backend"] }
```
and to `ppcap-core`'s `[dependencies]`: `flate2 = { workspace = true }`.

### 2. `reader/gzip.rs` — real `GunzipReader`
Replace the pass-through shell with the scaffold's documented `MultiGzDecoder<R>` wrapper:
```rust
pub struct GunzipReader<R: std::io::Read> { inner: flate2::read::MultiGzDecoder<R> }
impl<R: std::io::Read> GunzipReader<R> {
    pub fn new(inner: R) -> Self { Self { inner: flate2::read::MultiGzDecoder::new(inner) } }
}
impl<R: std::io::Read> std::io::Read for GunzipReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> { self.inner.read(buf) }
}
```
Drop the `#[allow(dead_code)]` shells; update the module doc to reflect "now functional". Keep/adapt the existing construction test + add a real round-trip test (gzip → inflate → bytes).

### 3. `reader/mod.rs` — `Magic::Gzip` dispatch + depth guard
Refactor `open_reader` to delegate to a private `open_reader_depth<R>(reader, size_hint, gzip_depth: u8)`; the public `open_reader` calls it with `gzip_depth = 0`. The `Magic::Gzip` arm:
```rust
Some(Magic::Gzip) => {
    if gzip_depth >= 1 {
        return Err(PpError::UnknownFormat("nested gzip is not supported".to_string()));
    }
    let inflated = gzip::GunzipReader::new(prefixed);
    open_reader_depth(inflated, None, gzip_depth + 1) // re-sniff the decompressed stream
}
```
(The decompressed `size_hint` is unknown → `None`. The other arms are unchanged.)

### 4. UI — accept `.gz` in the picker
- `ui/src/components/layout/LoadCaptureDialog.tsx`: add `.gz` to the drop-zone `accept` (the attribute matches the final extension, so `.gz` covers `.pcap.gz`/`.pcapng.gz`); update the helper copy to mention `.pcap.gz`.
- `ui/src/lib/platform.ts`: add `"gz"` (and optionally `"pcap.gz"`, `"pcapng.gz"`) to the Tauri open-dialog `extensions`. The dropped/opened bytes flow through the existing analyze path unchanged.

## Data flow & error handling

`.pcap.gz` → `open_reader` peeks `1f 8b` → `MultiGzDecoder` inflates lazily → the inner stream is re-sniffed (pcap/pcapng) → the normal streaming pipeline (bounded 64 KiB refill; no whole-file buffer). A corrupt/truncated gzip → `MultiGzDecoder::read` returns an `io::Error` → surfaced as a `PpError::io`/parse error at analyze time (never a panic). A gzip wrapping a non-capture / unknown inner format → the existing `UnknownFormat`. A gzip-of-gzip → the depth-guard `UnknownFormat`.

## Testing

- **Engine:** gzip a synthetic capture (the `gen` module emits pcap bytes; compress them in-test with `flate2::write::GzEncoder` under `#[cfg(test)]`) → `open_reader` yields the SAME frames (count, ts, data) as the uncompressed capture; a multi-member gzip (two concatenated members) decodes fully; a truncated/corrupt gzip → a typed error, no panic; a doubly-gzipped capture → the depth-guard error; a `.gz` of a pcapng works too. Keep `reader/gzip.rs`'s construction-doesn't-panic intent.
- **C-free gate:** assert (in the plan's verification) `cargo tree -p ppcap-core -e no-dev` shows `miniz_oxide`/`crc32fast` and NO `zlib-sys`/`cc`.
- **UI:** the picker offers `.gz` (a small assertion or manual check); existing load tests stay green.
- Engine gates + `build:wasm` (flate2 compiles on wasm32) + the UI coverage gate stay green.

## Out of scope

- zstd / lz4 / bzip2 compression; `.gz` *writing*; per-gzip-member metadata; a progress bar tuned to the decompressed size.

## File manifest

**Engine — modify:** `engine/Cargo.toml` (workspace dep), `engine/crates/ppcap-core/Cargo.toml` (crate dep), `engine/crates/ppcap-core/src/reader/gzip.rs` (real `GunzipReader`), `engine/crates/ppcap-core/src/reader/mod.rs` (`Magic::Gzip` dispatch + depth guard).
**UI — modify:** `ui/src/components/layout/LoadCaptureDialog.tsx` (accept `.gz` + copy), `ui/src/lib/platform.ts` (Tauri open extensions).
**No WASM/Tauri command change, no new engine logic beyond the reader.**
