//! Gzip un-wrapping for `.gz`-compressed captures.
//!
//! Inflates via [`flate2::read::MultiGzDecoder`] (pure-Rust miniz_oxide backend — no C
//! compiler required). The decoder handles single-member and multi-member `.gz` files
//! transparently; inflate errors surface from [`std::io::Read::read`] as typed
//! `io::Error`s, never panics.
//!
//! ## C-free constraint (R3/R4)
//!
//! `flate2` is declared with `default-features = false, features = ["rust_backend"]` in
//! the workspace `Cargo.toml`. This pulls `miniz_oxide` + `crc32fast`, both pure Rust, and
//! avoids `zlib-sys` / any `-sys` C build-script crate. The §0 `cargo tree` purity gate
//! (`grep -Ei "zlib-sys|lz4-sys|cc |cmake|bzip2-sys|openssl-sys"`) must print nothing.

/// A streaming gzip-inflating reader: wraps an underlying `Read` and yields the decompressed
/// byte stream incrementally (no full-file buffering). Handles multi-member gzip.
pub struct GunzipReader<R: std::io::Read> {
    inner: flate2::read::MultiGzDecoder<R>,
}

impl<R: std::io::Read> GunzipReader<R> {
    /// Wrap `inner` (a gzip member stream). The gzip magic was already validated by the
    /// sniffer in [`crate::reader::open_reader`]; inflate errors surface from
    /// [`std::io::Read::read`].
    pub fn new(inner: R) -> Self {
        GunzipReader {
            inner: flate2::read::MultiGzDecoder::new(inner),
        }
    }
}

impl<R: std::io::Read> std::io::Read for GunzipReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    #[test]
    fn gunzip_reader_inflates() {
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(b"hello pcap world").unwrap();
        let gz = enc.finish().unwrap();
        let mut g = GunzipReader::new(std::io::Cursor::new(gz));
        let mut out = String::new();
        g.read_to_string(&mut out).unwrap();
        assert_eq!(out, "hello pcap world");
    }

    #[test]
    fn gunzip_reader_multi_member() {
        // Two concatenated gzip members must both be decompressed.
        let mut m1 = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        m1.write_all(b"part1").unwrap();
        let mut bytes = m1.finish().unwrap();
        let mut m2 = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        m2.write_all(b"part2").unwrap();
        bytes.extend(m2.finish().unwrap());

        let mut g = GunzipReader::new(std::io::Cursor::new(bytes));
        let mut out = String::new();
        g.read_to_string(&mut out).unwrap();
        assert_eq!(out, "part1part2");
    }

    #[test]
    fn gunzip_reader_corrupt_returns_error_not_panic() {
        // Valid gzip header then garbage — inflate must error, not panic.
        let bad = vec![
            0x1f, 0x8b, 0x08, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x01, 0x02, 0x03,
        ];
        let mut g = GunzipReader::new(std::io::Cursor::new(bad));
        let mut out = Vec::new();
        let res = g.read_to_end(&mut out);
        assert!(res.is_err());
    }
}
