# gzip capture ingest — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Load `.pcap.gz` / `.pcapng.gz` captures directly — complete the documented gzip scaffold so compressed captures work on CLI, desktop, and browser.

**Architecture:** Add a pure-Rust inflate (`flate2 rust_backend`/miniz_oxide — no C), replace the `reader/gzip.rs` `GunzipReader` shell with `MultiGzDecoder`, and restore the `Magic::Gzip` dispatch in `open_reader` (inflate → re-sniff the decompressed pcap/pcapng stream, depth-guarded). Every surface funnels through `open_reader`, so gzip flows everywhere; a small UI touch offers `.gz` in the picker.

**Tech Stack:** Rust (`ppcap-core` reader); minor TS (load dialog filters).

## Global Constraints

- **C-free gate stays green.** CI runs `cargo tree -p ppcap-core -e no-dev | grep -Ei "zstd-sys|lz4-sys|cc |cmake|bzip2-sys|openssl-sys|zlib-sys"` and fails on any match. `flate2` MUST be `default-features = false, features = ["rust_backend"]` (miniz_oxide, pure Rust) — the default backend would pull `zlib-sys` and FAIL the gate.
- **Streaming, bounded, panic-free.** No whole-file buffering (gzip inflates lazily through the existing 64 KiB refill). Corrupt/truncated gzip → a typed `PpError` at read time, never a panic. Nested gzip → a clear depth-guard error.
- **Public surface unchanged** — `open`/`open_reader` signatures + every WASM/Tauri/CLI caller untouched. No new command/export.
- **wasm32 builds** (`build:wasm`); `flate2 rust_backend` compiles on wasm32 (ppcap-core uses `{ workspace = true }` deps that ppcap-wasm already builds).
- Engine gates: fmt, clippy `-D warnings`, `test --workspace`, `--features online`, C-free. UI gate under the locked toolchain (vitest 1.6.1; 80/70) incl. `build:wasm`. Stage specific files.
- **TOOLCHAIN:** cargo `/c/Users/ravid/.cargo/bin` (from `engine/`), MinGW `/c/Users/ravid/opt/mingw64/bin` (online/src-tauri), node `/c/Program Files/nodejs`. `cargo fmt` before each engine commit; do NOT `npm install`.

## Reference: the seams (verbatim, verified)

```rust
// reader/gzip.rs — GunzipReader<R> shell (read() -> ErrorKind::Unsupported today). The module doc
//   gives the EXACT MultiGzDecoder<R> replacement. Has a #[cfg(test)] construction test.
// reader/mod.rs:122 enum Magic { …, Gzip } ; :132 sniff: head[0]==0x1f && head[1]==0x8b -> Some(Gzip)
// reader/mod.rs:235 pub fn open_reader<R: std::io::Read + 'static>(reader, size_hint:Option<u64>) -> Result<Box<dyn PacketSource>>
//   :239 let (head, filled, prefixed) = peek4(reader)? ; if filled<4 { Truncated }
//   :252 match Magic::sniff(&head) {
//     Some(Magic::Gzip) => { let _ = prefixed; Err(PpError::UnknownFormat("gzip … not yet supported …")) }   // REJECT today
//     Some(m @ (PcapLeUs|PcapBeUs|PcapLeNs|PcapBeNs)) => { let mut s = pcap::LegacyPcapSource::new(prefixed, LinkType::Unsupported(0), m.is_nanos(), size_hint); s.prime()?; Ok(Box::new(s)) }
//     Some(Magic::PcapNg) => { let mut s = pcapng::PcapNgSource::new(prefixed, size_hint); s.prime()?; Ok(Box::new(s)) }
//     None => Err(UnknownFormat(format!("0x{:02x}{:02x}{:02x}{:02x}", …))) }
// reader/mod.rs:222 pub fn open(path) -> open_reader(File, size_hint)
// engine/Cargo.toml:12 [workspace.dependencies] pcap-parser="=0.17.0" …  (add flate2 here)
// ui/src/components/layout/LoadCaptureDialog.tsx:169 accept=".pcap,.pcapng,.cap,.json,.parquet,application/json"
// ui/src/lib/platform.ts:40-43 open({ multiple:false, filters:[{ name:"Captures", extensions:["pcap","pcapng","cap"] }] })
```

---

### Task 1: Engine — wire gzip inflate + restore the dispatch

**Files:**
- Modify: `engine/Cargo.toml` (workspace dep), `engine/crates/ppcap-core/Cargo.toml` (crate dep), `engine/crates/ppcap-core/src/reader/gzip.rs` (real `GunzipReader`), `engine/crates/ppcap-core/src/reader/mod.rs` (`Magic::Gzip` dispatch + depth guard)
- Test: `reader/mod.rs` (round-trip via the gen module) + `reader/gzip.rs` (inflate)

**Interfaces:**
- Produces: a functional `gzip::GunzipReader<R>` (MultiGzDecoder) + the `Magic::Gzip` dispatch in `open_reader` (inflate → recurse, depth ≤ 1).

- [ ] **Step 1: Write the failing test** — add to `reader/mod.rs` tests. Build a synthetic capture (reuse the `gen`/existing reader-test helper that produces pcap bytes), gzip it in-test, and assert `open_reader` yields the same frames:

```rust
#[test]
fn open_reader_transparently_inflates_a_gzipped_pcap() {
    use std::io::Write;
    let raw: Vec<u8> = synth_pcap_bytes(); // reuse the existing helper that builds a small pcap with N frames
    // count frames from the raw capture:
    let n_raw = count_frames(&raw);
    // gzip it:
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(&raw).unwrap();
    let gz = enc.finish().unwrap();
    // open the gzipped bytes and count frames — must match:
    let mut src = open_reader(std::io::Cursor::new(gz.clone()), Some(gz.len() as u64)).unwrap();
    let mut n_gz = 0u64;
    while src.next_frame().unwrap().is_some() { n_gz += 1; }
    assert_eq!(n_gz, n_raw);
    assert!(n_gz > 0);
}

#[test]
fn open_reader_rejects_nested_gzip() {
    use std::io::Write;
    let raw = synth_pcap_bytes();
    let gz1 = { let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default()); e.write_all(&raw).unwrap(); e.finish().unwrap() };
    let gz2 = { let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default()); e.write_all(&gz1).unwrap(); e.finish().unwrap() };
    let err = open_reader(std::io::Cursor::new(gz2), None).unwrap_err();
    assert!(matches!(err, PpError::UnknownFormat(_)));
}

#[test]
fn open_reader_corrupt_gzip_errors_without_panic() {
    // 0x1f 0x8b header then garbage → inflate fails at read time → a typed error, no panic
    let bad = vec![0x1f, 0x8b, 0x08, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x01, 0x02];
    let res = (|| -> Result<()> {
        let mut src = open_reader(std::io::Cursor::new(bad), None)?;
        while src.next_frame()?.is_some() {}
        Ok(())
    })();
    assert!(res.is_err());
}
```

And to `reader/gzip.rs` tests, replace/extend the existing construction test with a real inflate round-trip:
```rust
#[test]
fn gunzip_reader_inflates() {
    use std::io::{Read, Write};
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(b"hello pcap world").unwrap();
    let gz = enc.finish().unwrap();
    let mut g = GunzipReader::new(std::io::Cursor::new(gz));
    let mut out = String::new();
    g.read_to_string(&mut out).unwrap();
    assert_eq!(out, "hello pcap world");
}
```

> NOTE: reuse the REAL synthetic-pcap helper + frame-counter the existing `reader/mod.rs` tests use (search the test module — there are tests that build pcap/pcapng bytes and iterate `next_frame`). The names `synth_pcap_bytes`/`count_frames` are placeholders for those real helpers. `flate2` is a normal dep so it's usable in `#[cfg(test)]`.

- [ ] **Step 2: Run it to verify it fails** — `cd engine && cargo test -p ppcap-core open_reader_transparently_inflates` → FAIL (gzip rejected / flate2 absent).

- [ ] **Step 3: Implement** —
(a) `engine/Cargo.toml` `[workspace.dependencies]`: add
```toml
flate2 = { version = "1", default-features = false, features = ["rust_backend"] }
```
(b) `engine/crates/ppcap-core/Cargo.toml` `[dependencies]`: add `flate2 = { workspace = true }`.
(c) `reader/gzip.rs`: replace the `GunzipReader` shell (and drop the `#[allow(dead_code)]` + the `Unsupported`-error `read`) with:
```rust
/// A streaming gzip-inflating reader: wraps an underlying `Read` and yields the decompressed
/// byte stream incrementally (no full-file buffering). Handles multi-member gzip.
pub struct GunzipReader<R: std::io::Read> {
    inner: flate2::read::MultiGzDecoder<R>,
}

impl<R: std::io::Read> GunzipReader<R> {
    /// Wrap `inner` (a gzip member stream). The gzip magic was already validated by the sniffer
    /// in [`crate::reader::open_reader`]; inflate errors surface from [`std::io::Read::read`].
    pub fn new(inner: R) -> Self {
        GunzipReader { inner: flate2::read::MultiGzDecoder::new(inner) }
    }
}

impl<R: std::io::Read> std::io::Read for GunzipReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read(buf)
    }
}
```
Update the module-level doc (drop "NOT functional"; say it inflates via MultiGzDecoder).

(d) `reader/mod.rs`: thread a depth through `open_reader`. Rename the body to a private `open_reader_depth<R: std::io::Read + 'static>(reader: R, size_hint: Option<u64>, gzip_depth: u8) -> Result<Box<dyn PacketSource>>` and make the public fn delegate:
```rust
pub fn open_reader<R: std::io::Read + 'static>(reader: R, size_hint: Option<u64>) -> Result<Box<dyn PacketSource>> {
    open_reader_depth(reader, size_hint, 0)
}
```
Replace the `Some(Magic::Gzip)` arm with:
```rust
        Some(Magic::Gzip) => {
            if gzip_depth >= 1 {
                return Err(PpError::UnknownFormat("nested gzip is not supported".to_string()));
            }
            // Inflate, then re-sniff the decompressed stream (a .pcap.gz unwraps to a pcap/pcapng).
            let inflated = gzip::GunzipReader::new(prefixed);
            open_reader_depth(inflated, None, gzip_depth + 1)
        }
```
(The other arms move into `open_reader_depth` unchanged.)

> NOTE: confirm `gzip` is reachable in `reader/mod.rs` (it's a sibling module — `mod gzip;` should already exist; if it's `#[cfg(test)] mod gzip` or private, make it `mod gzip;` so `open_reader` can use `gzip::GunzipReader`). `PpError`/`PacketSource` are already in scope.

- [ ] **Step 4: Run it to verify it passes** — `cd engine && cargo test -p ppcap-core reader` → PASS (the gzip round-trip + nested + corrupt + inflate + every existing reader test). `cargo fmt && cargo clippy -p ppcap-core --all-targets -- -D warnings` → clean.

- [ ] **Step 5: C-free check** — `export PATH="/c/Users/ravid/.cargo/bin:$PATH" && cd engine && cargo tree -p ppcap-core -e no-dev | grep -Ei "zstd-sys|lz4-sys|cc |cmake|bzip2-sys|openssl-sys|zlib-sys" && echo "GATE FAIL" || echo "C-free OK"` → must print `C-free OK` (flate2 rust_backend pulls miniz_oxide/crc32fast, no `-sys`).

- [ ] **Step 6: Commit**

```bash
cd engine && cargo fmt
git add engine/Cargo.toml engine/crates/ppcap-core/Cargo.toml engine/crates/ppcap-core/src/reader/gzip.rs engine/crates/ppcap-core/src/reader/mod.rs
# (Cargo.lock may update — stage it too if changed: git add engine/Cargo.lock)
git commit -m "feat(engine): ingest gzip-compressed captures (pure-Rust inflate)"
```

> NOTE: if `engine/Cargo.lock` changed (new flate2/miniz_oxide entries), stage it in the same commit.

---

### Task 2: UI — accept `.gz` in the capture picker

**Files:**
- Modify: `ui/src/components/layout/LoadCaptureDialog.tsx` (drop-zone `accept` + copy), `ui/src/lib/platform.ts` (Tauri open extensions)
- Test: the LoadCaptureDialog test (if present) — else a small assertion

**Interfaces:**
- Consumes: the engine gzip support (T1) — the picker just needs to offer `.gz`; the bytes flow through the existing analyze path.

- [ ] **Step 1: Write the failing test** — if a `LoadCaptureDialog` test exists, add an assertion that the file input's `accept` includes `.gz`:
```tsx
it("accepts .gz compressed captures", () => {
  render(<LoadCaptureDialog {/* existing required props */} />);
  const input = screen.getByTestId("capture-file-input"); // or container.querySelector('input[type=file]')
  expect(input.getAttribute("accept")).toContain(".gz");
});
```
> NOTE: if no LoadCaptureDialog test or testid exists, query the file input via `container.querySelector('input[type="file"]')` and assert its `accept`. If testing the dialog is impractical, make this a manual check and rely on the gate — but prefer a small DOM assertion.

- [ ] **Step 2: Run it to verify it fails** — `cd ui && npx vitest run src/components/layout/LoadCaptureDialog.test.tsx` (or wherever) → FAIL.

- [ ] **Step 3: Implement** —
(a) `LoadCaptureDialog.tsx:169`: change `accept=".pcap,.pcapng,.cap,.json,.parquet,application/json"` → add `.gz`: `accept=".pcap,.pcapng,.cap,.gz,.json,.parquet,application/json"`. Update the helper copy (lines ~61, ~158-159) to mention `.pcap.gz` (e.g. "Drop a .pcap/.pcapng capture (.gz ok), …").
(b) `platform.ts:43`: change `extensions: ["pcap", "pcapng", "cap"]` → `extensions: ["pcap", "pcapng", "cap", "gz"]` (Tauri matches the final extension, so `gz` covers `.pcap.gz`/`.pcapng.gz`).

- [ ] **Step 4: Run it to verify it passes** — `cd ui && npx vitest run src/components/layout/LoadCaptureDialog.test.tsx` → PASS. `npx tsc --noEmit 2>&1 | grep -v "FlowsView.test"` → no new errors.

- [ ] **Step 5: Commit**

```bash
git add ui/src/components/layout/LoadCaptureDialog.tsx ui/src/lib/platform.ts
# + the test file if you added/edited one
git commit -m "feat(ui): offer .gz compressed captures in the load picker"
```

---

### Task 3: Full gate

- [ ] **Step 1: Engine gate** — `export PATH="/c/Users/ravid/opt/mingw64/bin:/c/Users/ravid/.cargo/bin:$PATH"`, from `engine/`:
```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo test -p ppcap-core --features online
cargo tree -p ppcap-core -e no-dev | grep -Ei "zstd-sys|lz4-sys|cc |cmake|bzip2-sys|openssl-sys|zlib-sys" && echo "C-FREE FAIL" || echo "C-free OK"
```
All green; the C-free line prints `C-free OK`.

- [ ] **Step 2: UI gate** — `cd ui && export PATH="/c/Program Files/nodejs:/c/Users/ravid/.cargo/bin:$PATH"`:
```bash
git diff --stat package.json package-lock.json
git checkout -- package.json package-lock.json 2>/dev/null || true
npm ci
node -p "require('./node_modules/vitest/package.json').version"   # 1.6.1
npm run build:wasm    # flate2 rust_backend must compile on wasm32
npm run build; echo "build EXIT: $?"          # EXIT 0
npm run test:coverage; echo "cov EXIT: $?"    # EXIT 0; All files >= 80/70 — paste it
```
Do NOT `npm install`. If `build:wasm` fails to compile flate2 on wasm32, that's a real blocker — report it (it should compile; miniz_oxide is wasm-friendly).

- [ ] **Step 3: Fill any gap** — if a metric dips, add a focused test and re-run.

- [ ] **Step 4: Commit** (if tests added)

```bash
git add ui/src/<new/updated tests>
git commit -m "test: hold the gate for gzip ingest"
```

---

## Self-Review

**1. Spec coverage:** the dep + real GunzipReader + Magic::Gzip dispatch + depth guard (T1) → spec §1-3; the picker `.gz` (T2) → §4; the gate incl. C-free + build:wasm (T3) → constraints/testing. Pure-Rust rust_backend (C-free), streaming/bounded/panic-free, depth guard, unchanged public surface, no new command — all covered. zstd/lz4/writing out of scope. ✓

**2. Placeholder scan:** complete code for the GunzipReader, the dispatch, the Cargo additions, the picker edits. The NOTEs (reuse the real synth-pcap/frame-count test helpers; confirm `mod gzip;` visibility; stage Cargo.lock; the file-input query) are concrete in-repo verifications. ✓

**3. Type/consistency:** `open_reader` keeps its `<R: Read + 'static>(reader, size_hint)` signature (public surface unchanged); the new `open_reader_depth(reader, size_hint, gzip_depth)` is private. `GunzipReader::new(prefixed)` wraps the un-peeked stream; the recursion re-sniffs. `flate2 = { workspace = true }` references the workspace dep. The C-free gate string matches CI's grep exactly. ✓
