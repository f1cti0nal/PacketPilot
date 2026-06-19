//! Typed error surface for the engine.
//!
//! [`PpError`] is the single error type returned by every fallible `ppcap-core` API.
//! Arrow/Parquet errors are folded into the stringly [`PpError::Columnar`] variant so
//! that those crate types never leak into the public surface. There is deliberately
//! **no** blanket `From<std::io::Error>`: every IO site must attach context via
//! [`PpError::io`] so error messages name the operation that failed.

/// Crate-wide result alias.
pub type Result<T> = std::result::Result<T, PpError>;

/// The one engine error type. `#[non_exhaustive]` is intentionally NOT used so that
/// downstream exhaustive matches stay stable across the Phase-0 contract.
#[derive(Debug, thiserror::Error)]
pub enum PpError {
    /// An IO failure, annotated with the operation context (e.g. "open capture.pcap").
    #[error("io error at {context}: {source}")]
    Io {
        context: String,
        #[source]
        source: std::io::Error,
    },

    /// The input did not match any recognized container magic.
    #[error("unsupported file format: {0}")]
    UnknownFormat(String),

    /// The input ended before a structure could be fully read.
    #[error("truncated input: needed {needed} bytes, had {had} (offset {offset})")]
    Truncated {
        needed: usize,
        had: usize,
        offset: u64,
    },

    /// A layer header could not be parsed for a specific packet.
    #[error("malformed {layer} header at packet #{packet_index}: {detail}")]
    MalformedHeader {
        layer: &'static str,
        packet_index: u64,
        detail: String,
    },

    /// The capture's link-layer type is not handled by the engine.
    #[error("unsupported link type: {0} (datalink {1})")]
    UnsupportedLinkType(&'static str, u32),

    /// A recorded snap length exceeded the configured ceiling (anti-DoS).
    #[error("snap length {snaplen} exceeds configured max {max}")]
    SnapLenExceeded { snaplen: u32, max: u32 },

    /// A pcapng block could not be interpreted.
    #[error("pcapng block error: {0}")]
    PcapNg(String),

    /// An Arrow or Parquet operation failed (kept stringly to hide those types).
    #[error("arrow/parquet error: {0}")]
    Columnar(String),

    /// JSON (de)serialization failed.
    #[error("json serialization error: {0}")]
    Json(#[from] serde_json::Error),

    /// A configuration value was invalid.
    #[error("invalid configuration: {0}")]
    Config(String),

    /// The synthetic generator failed.
    #[error("generator error: {0}")]
    Gen(String),
}

impl PpError {
    /// Construct an [`PpError::Io`] with context. Use this at every IO site instead of
    /// relying on a blanket `From<std::io::Error>` (which is intentionally absent).
    pub fn io(context: impl Into<String>, source: std::io::Error) -> Self {
        PpError::Io {
            context: context.into(),
            source,
        }
    }

    /// Whether this error should abort the whole analysis (fatal) or can be counted and
    /// skipped on a per-packet basis.
    ///
    /// Fatal: `UnknownFormat`, `UnsupportedLinkType`, `Config`, `PcapNg`, `Columnar`,
    /// `Io`, `Json`, `Gen`, `SnapLenExceeded`.
    /// Skippable: `Truncated`, `MalformedHeader` (one bad packet does not poison the run,
    /// unless the pipeline runs in strict mode).
    pub fn is_fatal(&self) -> bool {
        !matches!(
            self,
            PpError::Truncated { .. } | PpError::MalformedHeader { .. }
        )
    }
}

impl From<arrow_schema::ArrowError> for PpError {
    fn from(e: arrow_schema::ArrowError) -> Self {
        PpError::Columnar(e.to_string())
    }
}

impl From<parquet::errors::ParquetError> for PpError {
    fn from(e: parquet::errors::ParquetError) -> Self {
        PpError::Columnar(e.to_string())
    }
}
