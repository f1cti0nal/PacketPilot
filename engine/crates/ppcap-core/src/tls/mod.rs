//! Passive TLS **server certificate** health analysis.
//!
//! The engine fingerprints the client side of TLS (SNI / JA3 / JA4 from the ClientHello) in
//! [`crate::fingerprint`]. This module adds the missing server side: it reassembles the server's
//! cleartext **Certificate** handshake message (TLS ≤ 1.2 — TLS 1.3 encrypts it, so it is invisible
//! to passive capture and out of scope), parses the leaf certificate with a tiny hand-rolled DER
//! reader ([`der`] / [`cert`], no new deps), and flags self-signed / expired / not-yet-valid /
//! hostname-mismatched certificates — classic tells of C2 infrastructure, interception, and
//! misconfiguration.
//!
//! Memory stays bounded: only the in-flight server handshake bytes are buffered (capped count and
//! size), and they are freed the moment the certificate parses or the cap is hit. Nothing but
//! derived booleans/strings (issue kinds, subject CN, the requested SNI) survives into a finding —
//! never key material or the raw certificate.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use crate::model::packet::{AppProto, PacketMeta, Transport};

mod cert;
mod der;

/// A health problem found on a server's leaf certificate. Carries just enough context to render
/// an explainable evidence bullet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertIssue {
    /// Issuer DN equals subject DN — the certificate is not chained to a trusted CA.
    SelfSigned,
    /// `notAfter` is before the capture time.
    Expired { not_after: u64, observed: u64 },
    /// `notBefore` is after the capture time.
    NotYetValid { not_before: u64, observed: u64 },
    /// The requested host (ClientHello SNI) matches neither a SAN dNSName nor the subject CN.
    NameMismatch { sni: String },
}

impl CertIssue {
    /// Stable kebab-case token for the issue kind (ignores the carried data).
    pub fn kind_str(&self) -> &'static str {
        match self {
            CertIssue::SelfSigned => "self-signed",
            CertIssue::Expired { .. } => "expired",
            CertIssue::NotYetValid { .. } => "not-yet-valid",
            CertIssue::NameMismatch { .. } => "name-mismatch",
        }
    }

    /// Relative seriousness of a single issue (higher = worse). Drives the finding severity.
    pub fn severity_rank(&self) -> u8 {
        match self {
            CertIssue::NameMismatch { .. } => 3, // impersonation / AiTM signal
            CertIssue::SelfSigned => 2,
            CertIssue::Expired { .. } | CertIssue::NotYetValid { .. } => 1,
        }
    }

    /// Deterministic display order within a finding's evidence.
    fn order_key(&self) -> u8 {
        match self {
            CertIssue::SelfSigned => 0,
            CertIssue::Expired { .. } => 1,
            CertIssue::NotYetValid { .. } => 2,
            CertIssue::NameMismatch { .. } => 3,
        }
    }

    /// One explainable evidence bullet for this issue.
    pub fn evidence(&self) -> String {
        match self {
            CertIssue::SelfSigned => {
                "self-signed certificate (issuer matches subject — not chained to a trusted CA)"
                    .to_string()
            }
            CertIssue::Expired {
                not_after,
                observed,
            } => format!(
                "certificate expired: notAfter {} is before the capture date {}",
                fmt_date(*not_after),
                fmt_date(*observed)
            ),
            CertIssue::NotYetValid {
                not_before,
                observed,
            } => format!(
                "certificate not yet valid: notBefore {} is after the capture date {}",
                fmt_date(*not_before),
                fmt_date(*observed)
            ),
            CertIssue::NameMismatch { sni } => {
                format!("certificate does not match the requested host \"{sni}\" (no SAN/CN match)")
            }
        }
    }
}

/// Evaluate a parsed leaf certificate against the requested host (`sni`) and the capture time
/// (`observed`, a `YYYYMMDDhhmmss` integer from [`capture_stamp`]). Returns the issues found, in a
/// deterministic order.
pub(crate) fn check_cert_health(
    cert: &cert::CertInfo,
    sni: Option<&str>,
    observed: u64,
) -> Vec<CertIssue> {
    let mut issues = Vec::new();
    if cert.issuer_raw == cert.subject_raw {
        issues.push(CertIssue::SelfSigned);
    }
    if cert.not_after != u64::MAX && observed != 0 && observed > cert.not_after {
        issues.push(CertIssue::Expired {
            not_after: cert.not_after,
            observed,
        });
    }
    if cert.not_before != 0 && observed != 0 && observed < cert.not_before {
        issues.push(CertIssue::NotYetValid {
            not_before: cert.not_before,
            observed,
        });
    }
    if let Some(sni) = sni {
        if !sni.is_empty() && !name_matches_cert(cert, sni) {
            issues.push(CertIssue::NameMismatch {
                sni: sni.to_string(),
            });
        }
    }
    issues.sort_by_key(|i| i.order_key());
    issues
}

/// True if `sni` is covered by the certificate's SANs (preferred) or, absent any SAN, its CN.
/// When the certificate carries neither a SAN nor a CN there is nothing to contradict, so we do
/// not claim a mismatch (avoids a false positive).
fn name_matches_cert(cert: &cert::CertInfo, sni: &str) -> bool {
    let host = sni.trim_end_matches('.').to_ascii_lowercase();
    if !cert.sans.is_empty() {
        return cert.sans.iter().any(|p| host_matches(p, &host));
    }
    match &cert.cn {
        Some(cn) => host_matches(cn, &host),
        None => true,
    }
}

/// RFC 6125-style host match: case-insensitive, with a leading `*.` wildcard matching exactly one
/// left-most label.
fn host_matches(pattern: &str, host: &str) -> bool {
    let pat = pattern.trim_end_matches('.').to_ascii_lowercase();
    if let Some(rest) = pat.strip_prefix("*.") {
        return match host.split_once('.') {
            Some((_, tail)) => tail == rest,
            None => false,
        };
    }
    pat == host
}

/// Render a `YYYYMMDDhhmmss` stamp as `YYYY-MM-DD`; "unknown" for the sentinel values.
fn fmt_date(v: u64) -> String {
    if v == 0 || v == u64::MAX {
        return "unknown".to_string();
    }
    let date = v / 1_000_000; // YYYYMMDD
    format!(
        "{:04}-{:02}-{:02}",
        date / 10_000,
        (date / 100) % 100,
        date % 100
    )
}

/// Convert a capture timestamp (`i64` nanoseconds since the Unix epoch, UTC) into the comparable
/// `YYYYMMDDhhmmss` integer the certificate dates use. Returns `0` (the "unknown" sentinel) if the
/// timestamp is out of range.
pub fn capture_stamp(ts_ns: i64) -> u64 {
    use time::OffsetDateTime;
    match OffsetDateTime::from_unix_timestamp_nanos(ts_ns as i128) {
        Ok(dt) => {
            (dt.year().max(0) as u64) * 10_000_000_000
                + u8::from(dt.month()) as u64 * 100_000_000
                + dt.day() as u64 * 1_000_000
                + dt.hour() as u64 * 10_000
                + dt.minute() as u64 * 100
                + dt.second() as u64
        }
        Err(_) => 0,
    }
}

// ---------------------------------------------------------------------------------------------
// Bounded server-flight reassembler
// ---------------------------------------------------------------------------------------------

/// Cap on distinct server endpoints (a ClientHello's `dst`) remembered as TLS servers.
const MAX_WATCHED: usize = 4096;
/// Cap on distinct `(client, server)` SNI mappings retained for name-mismatch checks.
const MAX_SNI: usize = 4096;
/// Cap on concurrently-buffered server handshake flights.
const MAX_BUFFERS: usize = 512;
/// Cap on bytes buffered for one server flight before we give up on it.
const MAX_BUF_BYTES: usize = 16 * 1024;

/// A completed certificate observation: which client reached which server, and what was wrong with
/// the leaf certificate it presented.
pub(crate) struct CertObservation {
    pub client: IpAddr,
    pub server: IpAddr,
    pub server_port: u16,
    pub issues: Vec<CertIssue>,
    pub subject_cn: Option<String>,
    pub sni: Option<String>,
}

/// Streaming, bounded reassembler for server TLS handshake flights. Fed every decoded packet
/// during the single analysis pass; it watches for ClientHellos (to learn the server endpoint and
/// the requested SNI), then reassembles the matching server's Certificate message in arrival order
/// and records any health issues. Out-of-order / lossy captures simply fail to parse → no finding.
pub(crate) struct TlsCertReassembler {
    /// Server endpoints `(ip, port)` seen as the destination of a ClientHello.
    watched: HashSet<(IpAddr, u16)>,
    /// `(client, client_port, server, server_port)` -> requested SNI.
    sni: HashMap<(IpAddr, u16, IpAddr, u16), String>,
    /// `(server, server_port, client, client_port)` -> in-flight server handshake bytes.
    buffers: HashMap<(IpAddr, u16, IpAddr, u16), Vec<u8>>,
    observations: Vec<CertObservation>,
}

impl TlsCertReassembler {
    pub(crate) fn new() -> TlsCertReassembler {
        TlsCertReassembler {
            watched: HashSet::new(),
            sni: HashMap::new(),
            buffers: HashMap::new(),
            observations: Vec::new(),
        }
    }

    /// Fold one decoded packet. Cheap on the common path (returns immediately unless this is a
    /// ClientHello or a TCP segment from a watched server).
    pub(crate) fn observe(&mut self, meta: &PacketMeta, frame: &crate::reader::RawFrame) {
        let (src, sport, dst, dport) = match meta.endpoints() {
            Some(e) => e,
            None => return,
        };

        // A ClientHello (the only thing decode tags `AppProto::Tls`): learn the server endpoint
        // and, if present, the requested host for the later name-mismatch check.
        if meta.app_proto == AppProto::Tls {
            self.note_client_hello(src, sport, dst, dport, meta.sni.as_deref());
            return;
        }

        // Otherwise we only care about TCP payload coming *from* a known TLS server.
        if meta.transport != Transport::Tcp || meta.payload_len == 0 {
            return;
        }
        if !self.watched.contains(&(src, sport)) {
            return;
        }
        let info = match crate::decode::l4_payload(frame) {
            Some(i) if !i.payload.is_empty() => i,
            _ => return,
        };
        let observed = capture_stamp(meta.ts_ns);
        self.feed_server(src, sport, dst, dport, info.payload, observed);
    }

    /// Register a ClientHello's server endpoint + requested SNI (bounded inserts).
    fn note_client_hello(
        &mut self,
        client: IpAddr,
        client_port: u16,
        server: IpAddr,
        server_port: u16,
        sni: Option<&str>,
    ) {
        if self.watched.len() < MAX_WATCHED {
            self.watched.insert((server, server_port));
        }
        if let Some(sni) = sni {
            if !sni.is_empty() && self.sni.len() < MAX_SNI {
                self.sni
                    .entry((client, client_port, server, server_port))
                    .or_insert_with(|| sni.to_string());
            }
        }
    }

    /// Buffer server→client handshake bytes and, once the Certificate message is complete, parse
    /// the leaf certificate and record its health issues.
    fn feed_server(
        &mut self,
        server: IpAddr,
        server_port: u16,
        client: IpAddr,
        client_port: u16,
        payload: &[u8],
        observed: u64,
    ) {
        let key = (server, server_port, client, client_port);
        if !self.buffers.contains_key(&key) {
            // Only start buffering at the head of the server's flight (a ServerHello record).
            if !starts_with_server_hello(payload) || self.buffers.len() >= MAX_BUFFERS {
                return;
            }
            self.buffers.insert(key, Vec::new());
        }

        {
            let buf = self.buffers.get_mut(&key).expect("buffer present");
            let room = MAX_BUF_BYTES.saturating_sub(buf.len());
            if room == 0 {
                self.buffers.remove(&key);
                return;
            }
            let take = payload.len().min(room);
            buf.extend_from_slice(&payload[..take]);
        }

        enum Action {
            Found(Vec<u8>),
            Remove,
            Keep,
        }
        let action = {
            let buf = self.buffers.get(&key).expect("buffer present");
            match find_leaf_certificate(buf) {
                CertSearch::Found(der) => Action::Found(der),
                CertSearch::Abort => Action::Remove,
                CertSearch::NeedMore if buf.len() >= MAX_BUF_BYTES => Action::Remove,
                CertSearch::NeedMore => Action::Keep,
            }
        };

        match action {
            Action::Keep => {}
            Action::Remove => {
                self.buffers.remove(&key);
            }
            Action::Found(der) => {
                self.buffers.remove(&key);
                if let Some(cert) = cert::parse_leaf(&der) {
                    let sni = self
                        .sni
                        .get(&(client, client_port, server, server_port))
                        .cloned();
                    let issues = check_cert_health(&cert, sni.as_deref(), observed);
                    if !issues.is_empty() {
                        self.observations.push(CertObservation {
                            client,
                            server,
                            server_port,
                            issues,
                            subject_cn: cert.cn,
                            sni,
                        });
                    }
                }
            }
        }
    }

    /// Drain every completed certificate observation.
    pub(crate) fn into_observations(self) -> Vec<CertObservation> {
        self.observations
    }
}

/// True if `payload` begins a TLS handshake record whose first message is a ServerHello.
fn starts_with_server_hello(payload: &[u8]) -> bool {
    // record: content_type(22) version(2) length(2) ; body[0] = handshake type (2 = ServerHello)
    payload.len() >= 6 && payload[0] == 22 && payload[5] == 2
}

/// Result of scanning a server handshake buffer for the leaf certificate.
enum CertSearch {
    /// The leaf certificate's DER bytes.
    Found(Vec<u8>),
    /// The Certificate message has not arrived in full yet.
    NeedMore,
    /// The handshake stream ended (non-handshake record) without a Certificate.
    Abort,
}

/// Reassemble the handshake-message stream from consecutive TLS handshake records in `buf` and
/// return the first (leaf) certificate's DER once the Certificate message (type 11) is complete.
fn find_leaf_certificate(buf: &[u8]) -> CertSearch {
    // 1. Concatenate the bodies of consecutive handshake records (content_type 22).
    let mut hs: Vec<u8> = Vec::new();
    let mut pos = 0usize;
    while pos + 5 <= buf.len() {
        let content_type = buf[pos];
        if content_type != 22 {
            // ChangeCipherSpec / Alert / ApplicationData: the cleartext handshake is over.
            return CertSearch::Abort;
        }
        let rec_len = ((buf[pos + 3] as usize) << 8) | buf[pos + 4] as usize;
        let body_start = pos + 5;
        let body_end = match body_start.checked_add(rec_len) {
            Some(e) => e,
            None => return CertSearch::Abort,
        };
        if body_end > buf.len() {
            break; // record continues in a not-yet-arrived segment
        }
        hs.extend_from_slice(&buf[body_start..body_end]);
        pos = body_end;
    }

    // 2. Walk handshake messages within the reassembled stream for the Certificate (type 11).
    let mut hpos = 0usize;
    while hpos + 4 <= hs.len() {
        let msg_type = hs[hpos];
        let msg_len = ((hs[hpos + 1] as usize) << 16)
            | ((hs[hpos + 2] as usize) << 8)
            | hs[hpos + 3] as usize;
        let msg_start = hpos + 4;
        let msg_end = match msg_start.checked_add(msg_len) {
            Some(e) => e,
            None => return CertSearch::Abort,
        };
        if msg_type == 11 {
            if msg_end > hs.len() {
                return CertSearch::NeedMore;
            }
            return extract_first_cert(&hs[msg_start..msg_end]);
        }
        if msg_end > hs.len() {
            return CertSearch::NeedMore;
        }
        hpos = msg_end;
    }
    CertSearch::NeedMore
}

/// Extract the first certificate's DER from a TLS 1.2 Certificate message body:
/// `certificate_list<0..2^24-1>`, each entry a `u24` length + ASN.1 cert.
fn extract_first_cert(cert_msg: &[u8]) -> CertSearch {
    let list = match cert_msg.get(0..3) {
        Some(l) => {
            let list_len = ((l[0] as usize) << 16) | ((l[1] as usize) << 8) | l[2] as usize;
            match cert_msg.get(3..3 + list_len) {
                Some(b) => b,
                None => return CertSearch::Abort,
            }
        }
        None => return CertSearch::Abort,
    };
    let entry = match list.get(0..3) {
        Some(e) => {
            let cert_len = ((e[0] as usize) << 16) | ((e[1] as usize) << 8) | e[2] as usize;
            match list.get(3..3 + cert_len) {
                Some(d) => d,
                None => return CertSearch::Abort,
            }
        }
        None => return CertSearch::Abort,
    };
    CertSearch::Found(entry.to_vec())
}

// ---------------------------------------------------------------------------------------------
// Test helpers: hand-built DER certificates and TLS server flights.
// ---------------------------------------------------------------------------------------------

#[cfg(test)]
pub(crate) mod testcert {
    /// Encode one DER TLV (short- or long-form length).
    fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        let len = content.len();
        if len < 0x80 {
            out.push(len as u8);
        } else {
            let mut lb = Vec::new();
            let mut l = len;
            while l > 0 {
                lb.insert(0, (l & 0xff) as u8);
                l >>= 8;
            }
            out.push(0x80 | lb.len() as u8);
            out.extend_from_slice(&lb);
        }
        out.extend_from_slice(content);
        out
    }

    fn seq(children: &[Vec<u8>]) -> Vec<u8> {
        tlv(0x30, &children.concat())
    }
    fn set(children: &[Vec<u8>]) -> Vec<u8> {
        tlv(0x31, &children.concat())
    }
    fn name_cn(cn: &str) -> Vec<u8> {
        // RDNSequence { SET { SEQ { OID 2.5.4.3, UTF8String cn } } }
        seq(&[set(&[seq(&[
            tlv(0x06, &[0x55, 0x04, 0x03]),
            tlv(0x0C, cn.as_bytes()),
        ])])])
    }
    fn time_tlv(s: &str) -> Vec<u8> {
        let tag = if s.len() == 13 { 0x17 } else { 0x18 };
        tlv(tag, s.as_bytes())
    }

    /// Inputs for a synthetic leaf certificate.
    pub(crate) struct Spec<'a> {
        pub subject_cn: &'a str,
        pub issuer_cn: &'a str,
        /// `YYMMDDhhmmssZ` (UTCTime) or `YYYYMMDDhhmmssZ` (GeneralizedTime).
        pub not_before: &'a str,
        pub not_after: &'a str,
        pub sans: &'a [&'a str],
    }

    /// Build a structurally-valid DER X.509 certificate carrying the requested fields.
    pub(crate) fn build(spec: Spec) -> Vec<u8> {
        let sha256_rsa = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B];
        let rsa_enc = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];

        let version = tlv(0xA0, &tlv(0x02, &[0x02])); // [0] { INTEGER 2 (v3) }
        let serial = tlv(0x02, &[0x01]);
        let sig_alg = seq(&[tlv(0x06, &sha256_rsa)]);
        let issuer = name_cn(spec.issuer_cn);
        let validity = seq(&[time_tlv(spec.not_before), time_tlv(spec.not_after)]);
        let subject = name_cn(spec.subject_cn);
        let spki = seq(&[
            seq(&[tlv(0x06, &rsa_enc), tlv(0x05, &[])]),
            tlv(0x03, &[0x00, 0x01]),
        ]);

        let mut tbs_children = vec![version, serial, sig_alg, issuer, validity, subject, spki];
        if !spec.sans.is_empty() {
            let gnames: Vec<Vec<u8>> = spec.sans.iter().map(|s| tlv(0x82, s.as_bytes())).collect();
            let san_ext = seq(&[tlv(0x06, &[0x55, 0x1D, 0x11]), tlv(0x04, &seq(&gnames))]);
            tbs_children.push(tlv(0xA3, &seq(&[san_ext])));
        }
        let tbs = seq(&tbs_children);
        seq(&[
            tbs,
            seq(&[tlv(0x06, &sha256_rsa)]),
            tlv(0x03, &[0x00, 0xAB, 0xCD]),
        ])
    }

    fn hs_msg(t: u8, body: &[u8]) -> Vec<u8> {
        let l = body.len();
        let mut m = vec![t, (l >> 16) as u8, (l >> 8) as u8, l as u8];
        m.extend_from_slice(body);
        m
    }
    fn tls_record(body: &[u8]) -> Vec<u8> {
        let l = body.len();
        let mut r = vec![22, 0x03, 0x03, (l >> 8) as u8, l as u8];
        r.extend_from_slice(body);
        r
    }

    /// A server flight: a ServerHello record followed by a Certificate record wrapping `cert_der`.
    pub(crate) fn server_flight(cert_der: &[u8]) -> Vec<u8> {
        let mut sh_body = vec![0x03, 0x03];
        sh_body.extend_from_slice(&[0u8; 32]); // random
        sh_body.push(0x00); // session_id length
        sh_body.extend_from_slice(&[0x00, 0x2F]); // cipher suite
        sh_body.push(0x00); // compression
        let server_hello = hs_msg(2, &sh_body);

        let mut cert_msg = Vec::new();
        let entry_len = cert_der.len();
        let list_len = entry_len + 3;
        cert_msg.extend_from_slice(&[
            (list_len >> 16) as u8,
            (list_len >> 8) as u8,
            list_len as u8,
        ]);
        cert_msg.extend_from_slice(&[
            (entry_len >> 16) as u8,
            (entry_len >> 8) as u8,
            entry_len as u8,
        ]);
        cert_msg.extend_from_slice(cert_der);
        let certificate = hs_msg(11, &cert_msg);

        let mut out = tls_record(&server_hello);
        out.extend(tls_record(&certificate));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cert(spec_cn: &str, issuer: &str, nb: &str, na: &str, sans: &[&str]) -> cert::CertInfo {
        let der = testcert::build(testcert::Spec {
            subject_cn: spec_cn,
            issuer_cn: issuer,
            not_before: nb,
            not_after: na,
            sans,
        });
        cert::parse_leaf(&der).expect("parse")
    }

    #[test]
    fn flags_self_signed() {
        let c = cert("c2.evil", "c2.evil", "200101000000Z", "300101000000Z", &[]);
        let issues = check_cert_health(&c, None, 20_250_101_000_000);
        assert_eq!(issues, vec![CertIssue::SelfSigned]);
    }

    #[test]
    fn flags_expired_against_capture_time() {
        let c = cert(
            "host.example",
            "Real CA",
            "180101000000Z",
            "190101000000Z",
            &["host.example"],
        );
        // capture in 2025 -> expired (notAfter 2019).
        let issues = check_cert_health(&c, Some("host.example"), 20_250_101_000_000);
        assert!(issues
            .iter()
            .any(|i| matches!(i, CertIssue::Expired { .. })));
        // The same cert observed in 2018 is NOT expired.
        let ok = check_cert_health(&c, Some("host.example"), 20_180_601_000_000);
        assert!(!ok.iter().any(|i| matches!(i, CertIssue::Expired { .. })));
    }

    #[test]
    fn flags_name_mismatch_with_wildcard_support() {
        let c = cert(
            "*.example.com",
            "Real CA",
            "200101000000Z",
            "300101000000Z",
            &["*.example.com"],
        );
        // www.example.com matches the wildcard -> no mismatch.
        assert!(check_cert_health(&c, Some("www.example.com"), 20_250_101_000_000).is_empty());
        // a.b.example.com does NOT (wildcard is one label) -> mismatch.
        let issues = check_cert_health(&c, Some("a.b.example.com"), 20_250_101_000_000);
        assert!(issues
            .iter()
            .any(|i| matches!(i, CertIssue::NameMismatch { .. })));
        // evil.test is unrelated -> mismatch.
        let issues = check_cert_health(&c, Some("evil.test"), 20_250_101_000_000);
        assert!(issues
            .iter()
            .any(|i| matches!(i, CertIssue::NameMismatch { .. })));
    }

    #[test]
    fn san_takes_precedence_over_cn() {
        // CN says one host, SAN lists another; SNI matching the SAN must NOT mismatch.
        let c = cert(
            "legacy-cn.example",
            "Real CA",
            "200101000000Z",
            "300101000000Z",
            &["real.example"],
        );
        assert!(check_cert_health(&c, Some("real.example"), 20_250_101_000_000).is_empty());
    }

    #[test]
    fn reassembler_extracts_and_flags_a_single_segment_flight() {
        let der = testcert::build(testcert::Spec {
            subject_cn: "c2.evil",
            issuer_cn: "c2.evil",
            not_before: "200101000000Z",
            not_after: "300101000000Z",
            sans: &[],
        });
        let flight = testcert::server_flight(&der);

        let mut r = TlsCertReassembler::new();
        let client: IpAddr = "10.0.0.5".parse().unwrap();
        let server: IpAddr = "203.0.113.9".parse().unwrap();
        r.note_client_hello(client, 51000, server, 443, Some("good.example"));
        r.feed_server(server, 443, client, 51000, &flight, 20_250_101_000_000);

        let obs = r.into_observations();
        assert_eq!(obs.len(), 1);
        assert_eq!(obs[0].client, client);
        assert_eq!(obs[0].server, server);
        assert_eq!(obs[0].server_port, 443);
        // Self-signed AND name-mismatch (CN c2.evil vs SNI good.example).
        assert!(obs[0]
            .issues
            .iter()
            .any(|i| matches!(i, CertIssue::SelfSigned)));
        assert!(obs[0]
            .issues
            .iter()
            .any(|i| matches!(i, CertIssue::NameMismatch { .. })));
    }

    #[test]
    fn reassembler_handles_multi_segment_flight() {
        let der = testcert::build(testcert::Spec {
            subject_cn: "split.example",
            issuer_cn: "split.example",
            not_before: "200101000000Z",
            not_after: "300101000000Z",
            sans: &[],
        });
        let flight = testcert::server_flight(&der);
        let (a, b) = flight.split_at(flight.len() / 2);

        let mut r = TlsCertReassembler::new();
        let client: IpAddr = "10.0.0.5".parse().unwrap();
        let server: IpAddr = "203.0.113.9".parse().unwrap();
        r.note_client_hello(client, 51000, server, 443, None);
        r.feed_server(server, 443, client, 51000, a, 20_250_101_000_000);
        assert!(
            r.observations.is_empty(),
            "incomplete flight yields nothing yet"
        );
        r.feed_server(server, 443, client, 51000, b, 20_250_101_000_000);
        assert_eq!(r.observations.len(), 1);
        assert!(r.observations[0]
            .issues
            .iter()
            .any(|i| matches!(i, CertIssue::SelfSigned)));
    }

    #[test]
    fn reassembler_ignores_non_serverhello_start() {
        let mut r = TlsCertReassembler::new();
        let client: IpAddr = "10.0.0.5".parse().unwrap();
        let server: IpAddr = "203.0.113.9".parse().unwrap();
        r.note_client_hello(client, 51000, server, 443, None);
        // Application-data-looking bytes (content_type 23) must not start a buffer.
        r.feed_server(
            server,
            443,
            client,
            51000,
            &[23, 3, 3, 0, 5, 1, 2, 3, 4, 5],
            20_250_101_000_000,
        );
        assert!(r.buffers.is_empty());
        assert!(r.observations.is_empty());
    }

    #[test]
    fn capture_stamp_is_comparable_to_cert_dates() {
        // 2025-06-23T12:00:00Z
        let ns: i64 = 1_750_680_000_000_000_000;
        let stamp = capture_stamp(ns);
        assert_eq!(stamp / 1_000_000, 20_250_623); // YYYYMMDD
    }

    /// Build a complete Ethernet/IPv4/TCP frame carrying `payload`.
    fn tcp_eth(
        src: std::net::Ipv4Addr,
        dst: std::net::Ipv4Addr,
        sp: u16,
        dp: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        use crate::gen::frames::{
            build_ethernet, build_ipv4, build_tcp, ETHERTYPE_IPV4, IP_PROTO_TCP, TCP_ACK, TCP_PSH,
        };
        let tcp = build_tcp(src, dst, sp, dp, TCP_PSH | TCP_ACK, payload);
        let ip = build_ipv4(src, dst, IP_PROTO_TCP, 64, tcp.len());
        let mut eth = build_ethernet([2, 0, 0, 0, 0, 1], [2, 0, 0, 0, 0, 2], ETHERTYPE_IPV4);
        eth.extend_from_slice(&ip);
        eth.extend_from_slice(&tcp);
        eth
    }

    fn eth_frame(buf: &[u8], ts_ns: i64, index: u64) -> crate::reader::RawFrame<'_> {
        crate::reader::RawFrame {
            index,
            ts_ns,
            iface_id: 0,
            wire_len: buf.len() as u32,
            cap_len: buf.len() as u32,
            link_type: crate::reader::LinkType::Ethernet,
            data: buf,
        }
    }

    /// End-to-end wiring: real frames through `decode_frame` then `observe`. Exercises the
    /// ClientHello tagging, the watched-server gate, and the `l4_payload` extraction that the
    /// lower-level reassembler tests bypass.
    #[test]
    fn observe_detects_cert_issues_from_real_frames() {
        let client = std::net::Ipv4Addr::new(10, 0, 0, 5);
        let server = std::net::Ipv4Addr::new(203, 0, 113, 9);
        let ts0: i64 = 1_750_680_000_000_000_000; // 2025-06-23T12:00:00Z

        let der = testcert::build(testcert::Spec {
            subject_cn: "c2.evil",
            issuer_cn: "c2.evil",
            not_before: "200101000000Z",
            not_after: "300101000000Z",
            sans: &[],
        });
        let flight = testcert::server_flight(&der);
        let client_hello = crate::gen::frames::tls_client_hello_payload("good.example");

        let ch_bytes = tcp_eth(client, server, 51000, 443, &client_hello);
        let sv_bytes = tcp_eth(server, client, 443, 51000, &flight);

        let mut r = TlsCertReassembler::new();
        {
            let frame = eth_frame(&ch_bytes, ts0, 0);
            let meta = crate::decode::decode_frame(&frame).expect("decode client hello");
            assert_eq!(
                meta.app_proto,
                AppProto::Tls,
                "ClientHello must be tagged TLS"
            );
            r.observe(&meta, &frame);
        }
        assert!(
            r.watched.contains(&(IpAddr::V4(server), 443)),
            "server endpoint watched"
        );
        {
            let frame = eth_frame(&sv_bytes, ts0 + 1, 1);
            let meta = crate::decode::decode_frame(&frame).expect("decode server flight");
            r.observe(&meta, &frame);
        }

        let obs = r.into_observations();
        assert_eq!(
            obs.len(),
            1,
            "expected one cert observation: {:?}",
            obs.len()
        );
        assert_eq!(obs[0].server, IpAddr::V4(server));
        assert_eq!(obs[0].client, IpAddr::V4(client));
        assert_eq!(obs[0].server_port, 443);
        assert!(obs[0]
            .issues
            .iter()
            .any(|i| matches!(i, CertIssue::SelfSigned)));
        // SNI good.example vs CN c2.evil -> mismatch.
        assert!(obs[0]
            .issues
            .iter()
            .any(|i| matches!(i, CertIssue::NameMismatch { .. })));
    }
}
