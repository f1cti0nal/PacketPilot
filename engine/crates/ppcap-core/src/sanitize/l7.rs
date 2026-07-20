//! Selective L7 field redaction for kept payloads.
//!
//! Every redaction here is a **same-length, in-place substitution**, so TCP
//! sequence numbers, IP total lengths, DNS compression offsets, and TLS record
//! lengths all stay valid without any rewriting. Tokens are stable within a run
//! (same keyed PRF as the address mapping), and hostname labels share one token
//! domain across DNS, TLS SNI, and HTTP Host — one real name maps to one
//! pseudonymous name everywhere it appears.
//!
//! All parsers are bounds-checked best-effort: on anything unexpected they stop
//! and leave the remaining bytes alone (the payload-mode scrubbing, not this
//! module, is the privacy backstop). None of them can panic.

use super::anon::Anonymizer;

/// Per-packet redaction tallies, merged into the run manifest by the caller.
#[derive(Default)]
pub(crate) struct RedactionCounts {
    pub dns_names: u64,
    pub http_fields: u64,
    pub tls_snis: u64,
    pub credentials: u64,
    pub rdata_addrs: u64,
}

// ---------------------------------------------------------------------------
// Hostname helpers
// ---------------------------------------------------------------------------

/// Replace each dot-separated label of `host` in place with its stable token.
/// Dots (and anything non-label like a trailing root dot) are preserved, so the
/// string length and shape are unchanged.
pub(crate) fn redact_hostname_in_place(anon: &Anonymizer, host: &mut [u8]) {
    let mut start = 0usize;
    for i in 0..=host.len() {
        if i == host.len() || host[i] == b'.' {
            if i > start {
                let label = host[start..i].to_vec();
                anon.name_label_token(&label, &mut host[start..i]);
            }
            start = i + 1;
        }
    }
}

// ---------------------------------------------------------------------------
// DNS
// ---------------------------------------------------------------------------

/// Redact a DNS message in place (UDP payload, or TCP payload after the caller
/// strips the 2-byte length prefix). Walks question and resource-record names,
/// replaces every label with a stable token, pseudonymizes A/AAAA rdata with the
/// same address mapping as the packet headers, and walks the name-bearing rdata
/// of NS/CNAME/SOA/PTR/MX records. Returns `true` if the payload parsed as DNS.
pub(crate) fn redact_dns(
    anon: &mut Anonymizer,
    msg: &mut [u8],
    counts: &mut RedactionCounts,
) -> bool {
    if msg.len() < 12 {
        return false;
    }
    let qd = u16::from_be_bytes([msg[4], msg[5]]) as usize;
    let an = u16::from_be_bytes([msg[6], msg[7]]) as usize;
    let ns = u16::from_be_bytes([msg[8], msg[9]]) as usize;
    let ar = u16::from_be_bytes([msg[10], msg[11]]) as usize;
    // Sanity gate so random payloads on port 53 don't send us walking garbage.
    if qd > 64 || an > 512 || ns > 512 || ar > 512 || qd + an + ns + ar == 0 {
        return false;
    }

    let mut pos = 12usize;
    for _ in 0..qd {
        pos = match redact_name(anon, msg, pos, counts) {
            Some(p) => p,
            None => return true, // partially redacted; stop cleanly
        };
        pos += 4; // QTYPE + QCLASS
        if pos > msg.len() {
            return true;
        }
    }
    for _ in 0..(an + ns + ar) {
        pos = match redact_name(anon, msg, pos, counts) {
            Some(p) => p,
            None => return true,
        };
        if pos + 10 > msg.len() {
            return true;
        }
        let rtype = u16::from_be_bytes([msg[pos], msg[pos + 1]]);
        let rdlen = u16::from_be_bytes([msg[pos + 8], msg[pos + 9]]) as usize;
        let rdata = pos + 10;
        let rdend = rdata + rdlen;
        if rdend > msg.len() {
            return true;
        }
        match rtype {
            1 if rdlen == 4 => {
                // A record: map the address with the packet-header mapping.
                let ip = std::net::Ipv4Addr::new(
                    msg[rdata],
                    msg[rdata + 1],
                    msg[rdata + 2],
                    msg[rdata + 3],
                );
                msg[rdata..rdata + 4].copy_from_slice(&anon.ipv4(ip).octets());
                counts.rdata_addrs += 1;
            }
            28 if rdlen == 16 => {
                let mut b = [0u8; 16];
                b.copy_from_slice(&msg[rdata..rdata + 16]);
                let out = anon.ipv6(std::net::Ipv6Addr::from(b));
                msg[rdata..rdata + 16].copy_from_slice(&out.octets());
                counts.rdata_addrs += 1;
            }
            2 | 5 | 12 => {
                // NS / CNAME / PTR: rdata is one name.
                let _ = redact_name_bounded(anon, msg, rdata, rdend, counts);
            }
            15 if rdlen > 2 => {
                // MX: preference(2) then a name.
                let _ = redact_name_bounded(anon, msg, rdata + 2, rdend, counts);
            }
            6 => {
                // SOA: MNAME then RNAME, then fixed fields we leave alone.
                if let Some(p) = redact_name_bounded(anon, msg, rdata, rdend, counts) {
                    let _ = redact_name_bounded(anon, msg, p, rdend, counts);
                }
            }
            _ => {}
        }
        pos = rdend;
    }
    true
}

/// Redact one wire-format name starting at `pos`; returns the offset just past
/// it (past the terminating zero byte or the 2-byte compression pointer), or
/// `None` if the message is truncated/malformed at this point.
fn redact_name(
    anon: &Anonymizer,
    msg: &mut [u8],
    pos: usize,
    counts: &mut RedactionCounts,
) -> Option<usize> {
    redact_name_bounded(anon, msg, pos, msg.len(), counts)
}

fn redact_name_bounded(
    anon: &Anonymizer,
    msg: &mut [u8],
    mut pos: usize,
    end: usize,
    counts: &mut RedactionCounts,
) -> Option<usize> {
    let mut labels = 0u32;
    let mut redacted_any = false;
    loop {
        if pos >= end || pos >= msg.len() {
            return None;
        }
        let len = msg[pos] as usize;
        if len == 0 {
            if redacted_any {
                counts.dns_names += 1;
            }
            return Some(pos + 1);
        }
        if len & 0xC0 == 0xC0 {
            // Compression pointer: 2 bytes. Its target labels are (per spec) an
            // earlier occurrence that this walk already redacted in place.
            if redacted_any {
                counts.dns_names += 1;
            }
            return if pos + 2 <= end { Some(pos + 2) } else { None };
        }
        if len > 63 || pos + 1 + len > end.min(msg.len()) {
            return None;
        }
        let label = msg[pos + 1..pos + 1 + len].to_vec();
        anon.name_label_token(&label, &mut msg[pos + 1..pos + 1 + len]);
        redacted_any = true;
        pos += 1 + len;
        labels += 1;
        if labels > 128 {
            return None; // no legal name has this many labels
        }
    }
}

// ---------------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------------

const HTTP_METHODS: [&[u8]; 8] = [
    b"GET ",
    b"POST ",
    b"PUT ",
    b"HEAD ",
    b"DELETE ",
    b"OPTIONS ",
    b"PATCH ",
    b"CONNECT ",
];

/// Headers whose entire value is replaced with an opaque stable token.
const SENSITIVE_HEADERS: [&[u8]; 7] = [
    b"authorization",
    b"proxy-authorization",
    b"cookie",
    b"set-cookie",
    b"x-api-key",
    b"x-auth-token",
    b"www-authenticate",
];

/// Redact a cleartext HTTP/1.x segment in place: the request-target in the
/// request line, the Host header (hostname-label tokens, port kept), and
/// credential-bearing headers. Returns `true` if the payload looked like HTTP.
pub(crate) fn redact_http(
    anon: &Anonymizer,
    payload: &mut [u8],
    counts: &mut RedactionCounts,
) -> bool {
    let is_request = HTTP_METHODS.iter().any(|m| payload.starts_with(m));
    let is_response = payload.starts_with(b"HTTP/1.");
    if !is_request && !is_response {
        return false;
    }
    // Only the header block is structured; stop at the blank line (or segment end).
    let header_end = find_subslice(payload, b"\r\n\r\n").map_or(payload.len(), |i| i + 2);

    let mut line_start = 0usize;
    let mut first_line = true;
    while line_start < header_end {
        let line_end = find_subslice(&payload[line_start..header_end], b"\r\n")
            .map_or(header_end, |i| line_start + i);
        if first_line {
            if is_request {
                // METHOD SP request-target SP HTTP/x — tokenize the target after
                // its first character (keeps a leading '/' so it still reads as a path).
                let line = &payload[line_start..line_end];
                if let Some(sp1) = line.iter().position(|&b| b == b' ') {
                    let rest = &line[sp1 + 1..];
                    let target_len = rest.iter().position(|&b| b == b' ').unwrap_or(rest.len());
                    if target_len > 1 {
                        let abs = line_start + sp1 + 1;
                        let value = payload[abs..abs + target_len].to_vec();
                        anon.value_token(&value[1..], &mut payload[abs + 1..abs + target_len]);
                        counts.http_fields += 1;
                    }
                }
            }
            first_line = false;
        } else if let Some(colon) = payload[line_start..line_end]
            .iter()
            .position(|&b| b == b':')
        {
            let name: Vec<u8> = payload[line_start..line_start + colon]
                .iter()
                .map(|b| b.to_ascii_lowercase())
                .collect();
            // Value starts after ':' and any leading spaces.
            let mut vstart = line_start + colon + 1;
            while vstart < line_end && payload[vstart] == b' ' {
                vstart += 1;
            }
            if vstart < line_end {
                if name == b"host" {
                    // host[:port] — tokenize hostname labels, keep any port.
                    let vend = payload[vstart..line_end]
                        .iter()
                        .position(|&b| b == b':')
                        .map_or(line_end, |i| vstart + i);
                    redact_hostname_in_place(anon, &mut payload[vstart..vend]);
                    counts.http_fields += 1;
                } else if SENSITIVE_HEADERS.contains(&name.as_slice()) {
                    let value = payload[vstart..line_end].to_vec();
                    anon.value_token(&value, &mut payload[vstart..line_end]);
                    counts.http_fields += 1;
                } else if name == b"referer" || name == b"origin" || name == b"location" {
                    redact_url_in_place(anon, &mut payload[vstart..line_end]);
                    counts.http_fields += 1;
                }
            }
        }
        line_start = line_end + 2;
    }
    true
}

/// Tokenize a URL value while keeping its scheme prefix readable
/// (`https://a1b2c3...`). Falls back to whole-value tokenization without one.
fn redact_url_in_place(anon: &Anonymizer, value: &mut [u8]) {
    let keep = if value.starts_with(b"https://") {
        8
    } else if value.starts_with(b"http://") {
        7
    } else {
        0
    };
    if value.len() > keep {
        let tail = value[keep..].to_vec();
        anon.value_token(&tail, &mut value[keep..]);
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

// ---------------------------------------------------------------------------
// TLS ClientHello SNI
// ---------------------------------------------------------------------------

/// Redact the SNI hostname inside a TLS ClientHello in place (label tokens, same
/// mapping as DNS/Host). Only fires when the segment starts with a handshake
/// record carrying a ClientHello; fragmented hellos are left to payload scrubbing.
/// Returns `true` if an SNI value was redacted.
pub(crate) fn redact_tls_sni(
    anon: &Anonymizer,
    payload: &mut [u8],
    counts: &mut RedactionCounts,
) -> bool {
    // TLS record: type 22 (handshake), version 0x03xx; handshake type 1 at offset 5.
    if payload.len() < 44 || payload[0] != 22 || payload[1] != 3 || payload[5] != 1 {
        return false;
    }
    let mut pos = 5 + 4 + 2 + 32; // record hdr + handshake hdr + client_version + random
                                  // session_id
    if pos >= payload.len() {
        return false;
    }
    pos += 1 + payload[pos] as usize;
    // cipher_suites
    if pos + 2 > payload.len() {
        return false;
    }
    pos += 2 + u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;
    // compression_methods
    if pos + 1 > payload.len() {
        return false;
    }
    pos += 1 + payload[pos] as usize;
    // extensions
    if pos + 2 > payload.len() {
        return false;
    }
    let ext_end = (pos + 2 + u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize)
        .min(payload.len());
    pos += 2;
    while pos + 4 <= ext_end {
        let etype = u16::from_be_bytes([payload[pos], payload[pos + 1]]);
        let elen = u16::from_be_bytes([payload[pos + 2], payload[pos + 3]]) as usize;
        let ebody = pos + 4;
        if ebody + elen > ext_end {
            return false;
        }
        if etype == 0 && elen >= 5 {
            // server_name list: list_len(2) type(1)=0 name_len(2) name…
            let nlen = u16::from_be_bytes([payload[ebody + 3], payload[ebody + 4]]) as usize;
            let nstart = ebody + 5;
            if payload[ebody + 2] == 0 && nstart + nlen <= ebody + elen {
                redact_hostname_in_place(anon, &mut payload[nstart..nstart + nlen]);
                counts.tls_snis += 1;
                return true;
            }
            return false;
        }
        pos = ebody + elen;
    }
    false
}

// ---------------------------------------------------------------------------
// Cleartext credentials (FTP / POP3 / IMAP / SMTP / Telnet-adjacent lines)
// ---------------------------------------------------------------------------

/// Ports where line-based cleartext authentication commands are expected.
pub(crate) fn is_cred_port(port: u16) -> bool {
    matches!(port, 21 | 23 | 25 | 110 | 143 | 587)
}

/// Redact `USER` / `PASS` / `LOGIN` / `AUTH` command arguments in a line-based
/// cleartext protocol segment. Arguments are replaced with same-length tokens.
pub(crate) fn redact_cleartext_creds(
    anon: &Anonymizer,
    payload: &mut [u8],
    counts: &mut RedactionCounts,
) {
    let mut line_start = 0usize;
    while line_start < payload.len() {
        let rel_end = payload[line_start..]
            .iter()
            .position(|&b| b == b'\n')
            .map_or(payload.len() - line_start, |i| i);
        let mut line_end = line_start + rel_end;
        if line_end > line_start && payload[line_end - 1] == b'\r' {
            line_end -= 1;
        }
        redact_cred_line(anon, payload, line_start, line_end, counts);
        line_start += rel_end + 1;
    }
}

fn redact_cred_line(
    anon: &Anonymizer,
    payload: &mut [u8],
    start: usize,
    end: usize,
    counts: &mut RedactionCounts,
) {
    // Tokenize the line; if any token is USER/PASS/LOGIN/AUTH (case-insensitive),
    // redact everything after that keyword (covers `PASS x`, `a1 LOGIN u p`,
    // `AUTH PLAIN <b64>`).
    let mut pos = start;
    while pos < end {
        // skip spaces
        while pos < end && payload[pos] == b' ' {
            pos += 1;
        }
        let tok_start = pos;
        while pos < end && payload[pos] != b' ' {
            pos += 1;
        }
        if tok_start == pos {
            break;
        }
        let tok: Vec<u8> = payload[tok_start..pos]
            .iter()
            .map(|b| b.to_ascii_uppercase())
            .collect();
        if matches!(tok.as_slice(), b"USER" | b"PASS" | b"LOGIN" | b"AUTH") {
            // Redact the remainder of the line after the keyword + one space.
            let arg_start = (pos + 1).min(end);
            if arg_start < end {
                let value = payload[arg_start..end].to_vec();
                anon.value_token(&value, &mut payload[arg_start..end]);
                counts.credentials += 1;
            }
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn anon() -> Anonymizer {
        Anonymizer::from_key([9u8; 32], true, false)
    }

    /// Build a minimal DNS query for `name` (labels already split).
    fn dns_query(labels: &[&[u8]]) -> Vec<u8> {
        let mut m = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        for l in labels {
            m.push(l.len() as u8);
            m.extend_from_slice(l);
        }
        m.push(0);
        m.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // A IN
        m
    }

    #[test]
    fn dns_query_name_is_redacted_same_length() {
        let mut a = anon();
        let mut c = RedactionCounts::default();
        let mut msg = dns_query(&[b"secret", b"example", b"com"]);
        let before = msg.clone();
        assert!(redact_dns(&mut a, &mut msg, &mut c));
        assert_eq!(msg.len(), before.len());
        // Header + structure preserved…
        assert_eq!(&msg[..12], &before[..12]);
        assert_eq!(msg[12], 6, "label length bytes unchanged");
        // …but label bytes replaced.
        assert_ne!(&msg[13..19], b"secret");
        assert_eq!(c.dns_names, 1);
        // No original label text survives anywhere.
        assert!(find_subslice(&msg, b"secret").is_none());
        assert!(find_subslice(&msg, b"example").is_none());
    }

    #[test]
    fn dns_a_answer_rdata_is_pseudonymized_consistently() {
        let mut a = anon();
        let mut c = RedactionCounts::default();
        // Query + one A answer (name compressed via pointer to offset 12).
        let mut msg = dns_query(&[b"host", b"tld"]);
        msg[7] = 1; // ancount = 1
        msg.extend_from_slice(&[0xC0, 0x0C]); // pointer to the question name
        msg.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // A IN
        msg.extend_from_slice(&[0, 0, 0, 60]); // TTL
        msg.extend_from_slice(&[0x00, 0x04, 203, 0, 113, 7]); // rdlen 4 + address
        assert!(redact_dns(&mut a, &mut msg, &mut c));
        let n = msg.len();
        let got = std::net::Ipv4Addr::new(msg[n - 4], msg[n - 3], msg[n - 2], msg[n - 1]);
        // Must equal the header-level mapping of the same address.
        assert_eq!(got, a.ipv4("203.0.113.7".parse().unwrap()));
        assert_eq!(c.rdata_addrs, 1);
    }

    #[test]
    fn dns_rejects_non_dns_noise() {
        let mut a = anon();
        let mut c = RedactionCounts::default();
        let mut junk = vec![0xFFu8; 64]; // counts fields absurd → gate rejects
        assert!(!redact_dns(&mut a, &mut junk, &mut c));
        let mut short = vec![0u8; 4];
        assert!(!redact_dns(&mut a, &mut short, &mut c));
    }

    #[test]
    fn http_request_line_host_and_auth_are_redacted() {
        let a = anon();
        let mut c = RedactionCounts::default();
        let mut req = b"GET /accounts/alice?token=xyz HTTP/1.1\r\nHost: intra.corp.example:8080\r\nAuthorization: Basic QWxhZGRpbg==\r\nUser-Agent: curl/8.0\r\n\r\nBODY".to_vec();
        let before_len = req.len();
        assert!(redact_http(&a, &mut req, &mut c));
        assert_eq!(req.len(), before_len);
        let s = String::from_utf8_lossy(&req);
        assert!(s.starts_with("GET /"), "method + leading slash kept");
        assert!(!s.contains("accounts/alice"), "URI redacted");
        assert!(!s.contains("intra"), "host labels redacted");
        assert!(s.contains(":8080"), "port kept");
        assert!(!s.contains("QWxhZGRpbg"), "authorization redacted");
        assert!(s.contains("curl/8.0"), "user-agent kept");
        assert!(s.contains("BODY"), "body untouched by header redaction");
        assert_eq!(c.http_fields, 3);
    }

    #[test]
    fn http_detection_rejects_binary() {
        let a = anon();
        let mut c = RedactionCounts::default();
        let mut bin = vec![0x16u8, 0x03, 0x01, 0x00];
        assert!(!redact_http(&a, &mut bin, &mut c));
    }

    /// Minimal ClientHello with an SNI extension for `host`.
    fn client_hello(host: &[u8]) -> Vec<u8> {
        let sni_name = host.to_vec();
        let mut ext = Vec::new();
        ext.extend_from_slice(&0u16.to_be_bytes()); // extension type 0 = server_name
        let list_len = (sni_name.len() + 3) as u16;
        let ext_len = list_len + 2;
        ext.extend_from_slice(&ext_len.to_be_bytes());
        ext.extend_from_slice(&list_len.to_be_bytes());
        ext.push(0); // name_type host_name
        ext.extend_from_slice(&(sni_name.len() as u16).to_be_bytes());
        ext.extend_from_slice(&sni_name);

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // client_version
        body.extend_from_slice(&[0xAA; 32]); // random
        body.push(0); // session_id len
        body.extend_from_slice(&2u16.to_be_bytes()); // cipher_suites len
        body.extend_from_slice(&[0x13, 0x01]);
        body.push(1); // compression methods len
        body.push(0);
        body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext);

        let mut hs = vec![1u8]; // ClientHello
        let l = (body.len() as u32).to_be_bytes();
        hs.extend_from_slice(&l[1..4]);
        hs.extend_from_slice(&body);

        let mut rec = vec![22u8, 3, 1];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    #[test]
    fn tls_sni_is_redacted_and_consistent_with_dns_labels() {
        let a = anon();
        let mut c = RedactionCounts::default();
        let mut hello = client_hello(b"login.bank.example");
        let before_len = hello.len();
        assert!(redact_tls_sni(&a, &mut hello, &mut c));
        assert_eq!(hello.len(), before_len);
        assert!(find_subslice(&hello, b"bank").is_none());
        assert_eq!(c.tls_snis, 1);
        // Cross-protocol consistency: the label token equals the DNS-label token.
        let mut expect = [0u8; 4];
        a.name_label_token(b"bank", &mut expect);
        assert!(find_subslice(&hello, &expect).is_some());
    }

    #[test]
    fn tls_parser_survives_garbage() {
        let a = anon();
        let mut c = RedactionCounts::default();
        // Truncated / hostile inputs must neither panic nor redact.
        for n in 0..64 {
            let mut junk = vec![22u8, 3, 1];
            junk.extend(std::iter::repeat_n(0xFF, n));
            let _ = redact_tls_sni(&a, &mut junk, &mut c);
        }
    }

    #[test]
    fn cleartext_creds_are_redacted() {
        let a = anon();
        let mut c = RedactionCounts::default();
        let mut ftp = b"USER alice\r\nPASS hunter2\r\nCWD /files\r\n".to_vec();
        redact_cleartext_creds(&a, &mut ftp, &mut c);
        let s = String::from_utf8_lossy(&ftp);
        assert!(!s.contains("alice"));
        assert!(!s.contains("hunter2"));
        assert!(s.contains("CWD /files"), "non-auth lines untouched");
        assert_eq!(c.credentials, 2);

        let mut imap = b"a1 LOGIN bob sekrit\r\n".to_vec();
        redact_cleartext_creds(&a, &mut imap, &mut c);
        let s2 = String::from_utf8_lossy(&imap);
        assert!(!s2.contains("bob"));
        assert!(!s2.contains("sekrit"));
        assert!(s2.starts_with("a1 LOGIN "), "tag and keyword kept");
    }

    #[test]
    fn hostname_redaction_preserves_shape() {
        let a = anon();
        let mut host = b"api.internal.example.com".to_vec();
        redact_hostname_in_place(&a, &mut host);
        let s = String::from_utf8(host).unwrap();
        assert_eq!(s.len(), "api.internal.example.com".len());
        assert_eq!(s.matches('.').count(), 3);
        assert!(!s.contains("internal"));
    }
}
