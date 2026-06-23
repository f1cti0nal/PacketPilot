//! QUIC protocol support.
//!
//! This module provides cryptographic primitives and protocol dissection
//! for QUIC (RFC 9000) and QUIC-TLS (RFC 9001), enabling SNI extraction
//! from QUIC Initial packets without a full TLS stack.
//!
//! ## Sub-modules
//!
//! - [`crypto`] — vendored HMAC-SHA256, HKDF-Extract, HKDF-Expand, and
//!   HKDF-Expand-Label (RFC 8446 §7.1). Pure compute; wasm-safe (no std::{fs,net,time}).

pub(crate) mod crypto;
