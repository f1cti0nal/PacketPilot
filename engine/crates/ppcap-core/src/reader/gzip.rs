//! Gzip un-wrapping scaffold for `.gz`-compressed captures.
//!
//! STATUS: gzip support is NOT currently functional. No pure-Rust inflate backend is wired
//! in (see the NOTE TO INTEGRATOR below), so [`crate::reader::open_reader`] rejects gzip
//! inputs up front with a clear `UnknownFormat` error rather than dispatching to this reader.
//! The types below are kept as the documented drop-in integration point: once an inflate
//! dependency is added, restore the `Magic::Gzip` dispatch in `open_reader` and replace the
//! `GunzipReader` body per the snippet below to make `.gz` captures work transparently.
//!
//! IMPORTANT (R3/R4 build constraint): the engine is C-compiler-free. This wrapper must
//! use a **pure-Rust** inflate implementation — do NOT pull `flate2`'s zlib-ng/zlib-sys
//! C backend. Acceptable options: `flate2` with the `rust_backend` (miniz_oxide) feature,
//! or a direct `miniz_oxide` streaming inflate. Whichever is chosen must be added to the
//! workspace deps as pure-Rust and pass the §0 `cargo tree` purity gate.
//!
//! NOTE TO INTEGRATOR: no inflate crate is currently declared in
//! `crates/ppcap-core/Cargo.toml` (neither `flate2` nor `miniz_oxide`), and this task is
//! scoped to NOT edit any `Cargo.toml`. The streaming-inflate machinery therefore cannot be
//! wired up here without first adding one of those dependencies. To keep the engine's
//! no-panic contract, `GunzipReader` is implemented as a structurally-complete pass-through
//! shell: construction always succeeds and `Read::read` returns a typed
//! `io::ErrorKind::Unsupported` error rather than panicking or silently corrupting data.
//!
//! To finish the feature, add (in the workspace + crate `Cargo.toml`):
//!
//! ```toml
//! flate2 = { version = "1", default-features = false, features = ["rust_backend"] }
//! ```
//!
//! then replace the body of [`GunzipReader::new`] / [`GunzipReader::read`] with a
//! `flate2::read::MultiGzDecoder<R>` (handles the multi-member case automatically), keeping
//! the existing public types and the `reader::open_reader` gzip dispatch untouched:
//!
//! ```ignore
//! pub struct GunzipReader<R: std::io::Read> { inner: flate2::read::MultiGzDecoder<R> }
//! impl<R: std::io::Read> GunzipReader<R> {
//!     pub fn new(inner: R) -> Self { Self { inner: flate2::read::MultiGzDecoder::new(inner) } }
//! }
//! impl<R: std::io::Read> std::io::Read for GunzipReader<R> {
//!     fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> { self.inner.read(buf) }
//! }
//! ```

/// A streaming gzip-inflating reader. Wraps an underlying `Read` and (once an inflate
/// backend is wired in — see the module-level NOTE TO INTEGRATOR) yields the decompressed
/// byte stream incrementally with no full-file buffering.
///
/// Retained as the integration shell while gzip is rejected at sniff time, so it is only
/// exercised by this module's own tests today.
#[allow(dead_code)]
pub struct GunzipReader<R: std::io::Read> {
    /// The compressed source is retained so the real implementation can be dropped in
    /// without changing the public surface or the `open_reader` call site.
    inner: R,
}

#[allow(dead_code)] // integration shell: `new` is reached only from this module's tests until a real inflate backend is wired in
impl<R: std::io::Read> GunzipReader<R> {
    /// Wrap `inner`. The gzip magic was already validated by the sniffer in
    /// [`crate::reader::open_reader`]; full validation happens once a real inflate backend is
    /// present. Construction is infallible and never panics.
    pub fn new(inner: R) -> Self {
        GunzipReader { inner }
    }
}

impl<R: std::io::Read> std::io::Read for GunzipReader<R> {
    fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
        // Touch `inner` so the field is not flagged as dead before the real backend lands.
        let _ = &mut self.inner;
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "gzip-compressed captures require a pure-Rust inflate dependency (flate2 \
             rust_backend / miniz_oxide) that is not yet declared in Cargo.toml; see the \
             NOTE TO INTEGRATOR in reader/gzip.rs",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn construction_does_not_panic_and_read_is_typed_error() {
        // A minimal gzip header prefix; construction must succeed regardless.
        let compressed: &[u8] = &[0x1f, 0x8b, 0x08, 0x00];
        let mut g = GunzipReader::new(compressed);
        let mut out = [0u8; 16];
        let err = g.read(&mut out).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
    }
}
