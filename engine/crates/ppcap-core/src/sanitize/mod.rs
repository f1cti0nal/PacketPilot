//! Safe Share — streaming pcap/pcapng sanitization for safe capture sharing.
//!
//! One bounded-memory pass: read frames through the existing container readers
//! (pcap / pcapng / gzip-wrapped), pseudonymize addresses and redact sensitive
//! L7 fields **in place** (never changing a length), recompute checksums, and
//! write a valid pcap or pcapng through the `gen::container` writers. A JSON
//! **manifest** records what was transformed — counts, options, and input/output
//! SHA-256 — without ever containing an original value or the mapping key.
//!
//! Privacy model (documented for users in `docs/sharing-captures-safely.md`):
//! - The per-run key exists only in memory; no reverse mapping is ever exported.
//! - Same value → same pseudonym *within* a run; across runs mappings differ.
//! - Default (`PayloadMode::Scrub`) zeroes every application payload byte, so
//!   only structure (headers, sizes, timing) leaves the machine.
//! - `PayloadMode::Keep` retains payloads for deeper downstream analysis and
//!   redacts DNS names, HTTP host/target/credential headers, TLS SNI, and
//!   cleartext credentials with stable same-length tokens. Anything the L7
//!   parsers don't recognize is kept verbatim — Keep is for captures you'd
//!   share with a trusted party anyway.

pub(crate) mod anon;
pub(crate) mod checksum;
pub(crate) mod l7;
pub(crate) mod packet;

use std::collections::HashMap;
use std::io::Write;
// `Path` is only used by the native-only `sanitize_file`; keep the import gated so
// the wasm build (which excludes that fn) stays warning-clean.
#[cfg(not(target_arch = "wasm32"))]
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::analyze::{hex_of, Sha256};
use crate::gen::container;
use crate::reader::{LinkType, PacketSource};
use crate::{PpError, Result};

#[cfg(not(target_arch = "wasm32"))]
pub use anon::fresh_key;
pub use anon::Anonymizer;

/// What happens to application payload bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PayloadMode {
    /// Zero every payload byte (optionally keeping the first N). The default —
    /// only structure leaves the machine.
    Scrub,
    /// Keep payloads, redacting known-sensitive L7 fields with stable tokens.
    Keep,
}

/// Output container format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SanitizeFormat {
    /// Classic pcap (µs timestamps, single link type).
    Pcap,
    /// pcapng (ns timestamps, multi-interface).
    PcapNg,
}

/// Sanitization options. `Default` is the privacy-safest configuration; every
/// field is optional on deserialization (missing fields take the default).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SanitizeOptions {
    /// Payload policy (default: scrub everything).
    pub payload: PayloadMode,
    /// In `Scrub` mode, retain this many leading payload bytes per packet for
    /// protocol identification (default 0). Retained bytes still get L7 redaction.
    pub keep_first: usize,
    /// Preserve shared-prefix relationships between addresses (Crypto-PAn
    /// semantics). Off = flat per-block permutation, no subnet structure.
    pub preserve_prefix: bool,
    /// Keep the vendor OUI (first 3 bytes) of pseudonymized MACs.
    pub preserve_oui: bool,
    /// Redact DNS names / HTTP fields / TLS SNI / cleartext credentials in any
    /// payload bytes that remain (default on).
    pub redact_l7: bool,
    /// Constant shift applied to every timestamp, in seconds (blunts timing
    /// correlation against external logs while keeping relative timing intact).
    pub time_shift_secs: i64,
    /// Output container format.
    pub format: SanitizeFormat,
}

impl Default for SanitizeOptions {
    fn default() -> Self {
        SanitizeOptions {
            payload: PayloadMode::Scrub,
            keep_first: 0,
            preserve_prefix: true,
            preserve_oui: false,
            redact_l7: true,
            time_shift_secs: 0,
            format: SanitizeFormat::Pcap,
        }
    }
}

/// Everything the run transformed, by category. All counters are occurrences
/// except the `unique_*` fields (distinct values, floor if the memo caps out).
#[derive(Debug, Default, Clone, Serialize)]
pub struct SanitizeCounts {
    pub packets_read: u64,
    pub packets_written: u64,
    /// Frames copied verbatim because their link/L3 layout wasn't recognized.
    pub passthrough_frames: u64,
    /// Unknown-ethertype frames whose body was scrubbed under the opaque policy.
    pub opaque_l3_scrubbed: u64,
    pub ipv4_rewritten: u64,
    pub ipv6_rewritten: u64,
    pub macs_rewritten: u64,
    pub arp_rewritten: u64,
    pub unique_ipv4: u64,
    pub unique_ipv6: u64,
    pub unique_macs: u64,
    pub dns_names_redacted: u64,
    pub http_fields_redacted: u64,
    pub tls_snis_redacted: u64,
    pub credentials_redacted: u64,
    /// A/AAAA rdata addresses rewritten inside DNS answers.
    pub rdata_addrs_rewritten: u64,
    /// IP headers embedded in ICMP error bodies that were rewritten.
    pub embedded_headers_rewritten: u64,
    pub payload_bytes_scrubbed: u64,
    pub l3_checksums_recomputed: u64,
    pub l4_checksums_recomputed: u64,
    /// Checksums zeroed because snaplen truncation made recomputation impossible.
    pub l4_checksums_zeroed: u64,
}

/// The chain-of-custody sidecar written next to the sanitized capture. Contains
/// no original values and no key material — only what categories of data were
/// transformed, under which options, and the hashes tying it to its files.
#[derive(Debug, Clone, Serialize)]
pub struct SanitizeManifest {
    pub tool: &'static str,
    pub tool_version: &'static str,
    /// Unix seconds; 0 when the caller has no clock (deterministic contexts).
    pub created_unix_secs: i64,
    pub options: SanitizeOptions,
    pub input_sha256: String,
    pub output_sha256: String,
    pub counts: SanitizeCounts,
}

impl SanitizeManifest {
    pub fn to_json_pretty(&self) -> Result<String> {
        serde_json::to_string_pretty(self).map_err(PpError::Json)
    }
}

/// A `Write` adapter that folds every byte into a SHA-256 as it passes through.
struct HashingWriter<W: Write> {
    inner: W,
    sha: Sha256,
    written: u64,
}

impl<W: Write> HashingWriter<W> {
    fn new(inner: W) -> Self {
        HashingWriter {
            inner,
            sha: Sha256::new(),
            written: 0,
        }
    }
}

impl<W: Write> Write for HashingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.sha.update(&buf[..n]);
        self.written += n as u64;
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// Sanitize every frame from `source` into `out`. The caller supplies the key
/// (use [`fresh_key`] on native; browsers pass `crypto.getRandomValues` bytes)
/// and receives the transform counts and the output SHA-256.
///
/// Single pass, bounded memory: one reusable frame buffer plus the memo caches.
/// Progress is `(packets, bytes_processed, size_hint)`, same shape as `analyze`.
pub fn sanitize_stream(
    mut source: Box<dyn PacketSource + '_>,
    out: &mut dyn Write,
    key: [u8; 32],
    opts: &SanitizeOptions,
    mut progress: impl FnMut(u64, u64, Option<u64>),
) -> Result<(SanitizeCounts, String)> {
    let mut anon = Anonymizer::from_key(key, opts.preserve_prefix, opts.preserve_oui);
    let mut counts = SanitizeCounts::default();
    let mut w = HashingWriter::new(out);
    let size_hint = source.size_hint();
    let shift_ns = opts.time_shift_secs.saturating_mul(1_000_000_000);

    // Classic pcap can only describe one link type; remember the first and fail
    // clearly on a mismatch. pcapng maps source interfaces to output IDBs lazily.
    let mut pcap_link: Option<LinkType> = None;
    let mut ng_ifaces: HashMap<u32, u32> = HashMap::new();
    let mut ng_shb_written = false;

    let mut buf: Vec<u8> = Vec::with_capacity(2048);
    let mut bytes_seen: u64 = 0;

    loop {
        let (ts_ns, wire_len, cap_len, iface_id, link) = {
            let frame = match source.next_frame()? {
                Some(f) => f,
                None => break,
            };
            buf.clear();
            buf.extend_from_slice(frame.data);
            (
                frame.ts_ns,
                frame.wire_len,
                frame.cap_len,
                frame.iface_id,
                frame.link_type,
            )
        };
        counts.packets_read += 1;
        bytes_seen += cap_len as u64;

        packet::sanitize_frame(&mut buf, link, wire_len, &mut anon, opts, &mut counts);

        let ts_out = ts_ns.saturating_add(shift_ns);
        match opts.format {
            SanitizeFormat::Pcap => {
                match pcap_link {
                    None => {
                        pcap_link = Some(link);
                        container::write_pcap_header(&mut w, link)?;
                    }
                    Some(l) if l != link => {
                        return Err(PpError::Config(format!(
                            "capture mixes link types ({} and {}); classic pcap cannot \
                             represent that — write a .pcapng output instead",
                            l.as_str(),
                            link.as_str()
                        )));
                    }
                    Some(_) => {}
                }
                container::write_legacy_record(&mut w, ts_out, buf.len() as u32, wire_len)?;
                w.write_all(&buf)
                    .map_err(|e| PpError::io("write sanitized frame", e))?;
            }
            SanitizeFormat::PcapNg => {
                if !ng_shb_written {
                    container::write_pcapng_shb(&mut w)?;
                    ng_shb_written = true;
                }
                let next_id = ng_ifaces.len() as u32;
                let out_iface = *ng_ifaces.entry(iface_id).or_insert(next_id);
                if out_iface == next_id && ng_ifaces.len() as u32 == next_id + 1 {
                    // First frame from this source interface: emit its IDB now
                    // (valid pcapng — an IDB must only precede its first use).
                    container::write_pcapng_idb(&mut w, link)?;
                }
                container::write_epb(&mut w, out_iface, ts_out, buf.len() as u32, wire_len, &buf)?;
            }
        }
        counts.packets_written += 1;
        progress(counts.packets_read, bytes_seen, size_hint);
    }

    // Empty capture: still emit a valid, loadable container header.
    if counts.packets_written == 0 {
        match opts.format {
            SanitizeFormat::Pcap => {
                container::write_pcap_header(&mut w, LinkType::Ethernet)?;
            }
            SanitizeFormat::PcapNg => {
                container::write_pcapng_shb(&mut w)?;
                container::write_pcapng_idb(&mut w, LinkType::Ethernet)?;
            }
        }
    }

    w.flush()
        .map_err(|e| PpError::io("flush sanitized output", e))?;
    let (u4, u6, um) = anon.unique_counts();
    counts.unique_ipv4 = u4;
    counts.unique_ipv6 = u6;
    counts.unique_macs = um;
    let digest = hex_of(&w.sha.finalize_bytes());
    Ok((counts, digest))
}

/// File-to-file sanitize for native callers (CLI / desktop): fresh in-memory key,
/// input hashed for provenance, output + manifest written, manifest returned.
///
/// `manifest_path` `None` defaults to `<output>.manifest.json`.
#[cfg(not(target_arch = "wasm32"))]
pub fn sanitize_file(
    input: &Path,
    output: &Path,
    manifest_path: Option<&Path>,
    opts: &SanitizeOptions,
    created_unix_secs: i64,
    progress: impl FnMut(u64, u64, Option<u64>),
) -> Result<SanitizeManifest> {
    let input_sha256 = crate::analyze::hash_file_sha256(input)?;
    let source = crate::reader::open(input)?;
    let file = std::fs::File::create(output)
        .map_err(|e| PpError::io(format!("create {}", output.display()), e))?;
    let mut out = std::io::BufWriter::new(file);
    let run = sanitize_stream(source, &mut out, fresh_key(), opts, progress);
    let (counts, output_sha256) = match run {
        Ok(v) => v,
        Err(e) => {
            // Don't leave a half-written capture behind on failure.
            drop(out);
            let _ = std::fs::remove_file(output);
            return Err(e);
        }
    };
    out.into_inner()
        .map_err(|e| PpError::io("flush sanitized capture", e.into_error()))?;

    let manifest = SanitizeManifest {
        tool: "packetpilot",
        tool_version: env!("CARGO_PKG_VERSION"),
        created_unix_secs,
        options: opts.clone(),
        input_sha256,
        output_sha256,
        counts,
    };
    let default_path = {
        let mut s = output.as_os_str().to_os_string();
        s.push(".manifest.json");
        std::path::PathBuf::from(s)
    };
    let mpath = manifest_path.unwrap_or(&default_path);
    std::fs::write(mpath, manifest.to_json_pretty()?)
        .map_err(|e| PpError::io(format!("write manifest {}", mpath.display()), e))?;
    Ok(manifest)
}

/// In-memory sanitize for the wasm binding: capture bytes in, sanitized capture
/// bytes + manifest out. The browser supplies the key (`crypto.getRandomValues`).
pub fn sanitize_bytes(
    bytes: &[u8],
    key: [u8; 32],
    opts: &SanitizeOptions,
    created_unix_secs: i64,
) -> Result<(Vec<u8>, SanitizeManifest)> {
    let input_sha256 = crate::analyze::sha256_hex(bytes);
    let source = crate::reader::open_reader(std::io::Cursor::new(bytes), Some(bytes.len() as u64))?;
    let mut out = Vec::with_capacity(bytes.len());
    let (counts, output_sha256) = sanitize_stream(source, &mut out, key, opts, |_, _, _| {})?;
    let manifest = SanitizeManifest {
        tool: "packetpilot",
        tool_version: env!("CARGO_PKG_VERSION"),
        created_unix_secs,
        options: opts.clone(),
        input_sha256,
        output_sha256,
        counts,
    };
    Ok((out, manifest))
}
