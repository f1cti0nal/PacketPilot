//! Best-effort HTTP/1.1 view over a decrypted TLS flow's two plaintext directions.
//!
//! After key-log decryption ([`super::decrypt`]) reassembles each direction's application data,
//! this surfaces the requests (client→server) and responses (server→client) that were hidden inside
//! HTTPS — method / target / host and status / content-type / length. HTTP/1.1 only; HTTP/2's
//! HPACK-compressed binary framing is detected (so the UI can explain) but not decoded here.
//! Best-effort and bounded — never panics on arbitrary bytes.

use serde::Serialize;

/// Cap on parsed transactions surfaced.
const MAX_TXN: usize = 256;

/// HTTP/1.1 request methods, each with a trailing space so a method-prefix test can't false-match a
/// longer token.
const METHODS: &[&[u8]] = &[
    b"GET ",
    b"POST ",
    b"PUT ",
    b"HEAD ",
    b"DELETE ",
    b"OPTIONS ",
    b"PATCH ",
    b"CONNECT ",
    b"TRACE ",
];

/// One reconstructed HTTP/1.1 transaction (the request paired with the response at the same
/// position in the stream — correct for the common non-pipelined keep-alive case).
#[derive(Debug, Clone, Serialize)]
pub struct HttpTxn {
    pub method: String,
    pub target: String,
    pub host: String,
    /// Response status code; `0` when no matching response was parsed.
    pub status: u16,
    pub content_type: String,
    pub resp_bytes: u64,
}

/// The application protocol of a decrypted client→server stream, so the UI can explain when no
/// HTTP transactions are surfaced.
pub(crate) fn detect_proto(c2s: &[u8]) -> &'static str {
    if c2s.is_empty() {
        "none"
    } else if c2s.starts_with(b"PRI * HTTP/2.0") {
        "http/2"
    } else if METHODS.iter().any(|m| c2s.starts_with(m)) {
        "http/1.1"
    } else {
        "unknown"
    }
}

struct Req {
    method: String,
    target: String,
    host: String,
}
struct Resp {
    status: u16,
    content_type: String,
    content_len: u64,
}

/// Index of the `\r\n\r\n` header terminator (the first `\r`).
fn crlfcrlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// Trim leading/trailing ASCII whitespace.
fn trim(v: &[u8]) -> &[u8] {
    let s = v
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .unwrap_or(v.len());
    let e = v[s..]
        .iter()
        .rposition(|b| !b.is_ascii_whitespace())
        .map(|p| s + p + 1)
        .unwrap_or(s);
    &v[s..e]
}

/// Case-insensitive header value (trimmed) from a header block.
fn header<'a>(head: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    for line in head.split(|&b| b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.len() >= name.len() && line[..name.len()].eq_ignore_ascii_case(name) {
            return Some(trim(&line[name.len()..]));
        }
    }
    None
}

fn content_len(head: &[u8]) -> u64 {
    header(head, b"content-length:")
        .and_then(|v| std::str::from_utf8(v).ok())
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

fn first_line(head: &[u8]) -> &[u8] {
    let end = head
        .iter()
        .position(|&b| b == b'\r' || b == b'\n')
        .unwrap_or(head.len());
    &head[..end]
}

fn lossy(v: &[u8]) -> String {
    String::from_utf8_lossy(v).into_owned()
}

fn parse_requests(c2s: &[u8]) -> Vec<Req> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos < c2s.len() && out.len() < MAX_TXN {
        let rest = &c2s[pos..];
        if !METHODS.iter().any(|m| rest.starts_with(m)) {
            break; // not (or no longer) at a request line
        }
        let hdr_end = match crlfcrlf(rest) {
            Some(p) => p,
            None => break,
        };
        let head = &rest[..hdr_end];
        let mut parts = first_line(head).split(|&b| b == b' ');
        let method = lossy(parts.next().unwrap_or(b""));
        let target = lossy(parts.next().unwrap_or(b""));
        let host = header(head, b"host:").map(lossy).unwrap_or_default();
        out.push(Req {
            method,
            target,
            host,
        });
        // Advance past this request's headers + (POST) body. A Content-Length larger than what
        // remains is clamped to the stream (the body is the rest), so the u64→usize cast + the add
        // can never overflow on a hostile header; `hdr_end + 4 > 0` guarantees forward progress.
        let body = content_len(head).min(c2s.len() as u64) as usize;
        pos = pos
            .saturating_add(hdr_end)
            .saturating_add(4)
            .saturating_add(body);
    }
    out
}

fn parse_responses(s2c: &[u8]) -> Vec<Resp> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos < s2c.len() && out.len() < MAX_TXN {
        let rel = match s2c[pos..].windows(5).position(|w| w == b"HTTP/") {
            Some(r) => r,
            None => break,
        };
        let start = pos + rel;
        let rest = &s2c[start..];
        let hdr_end = match crlfcrlf(rest) {
            Some(p) => p,
            None => break,
        };
        let head = &rest[..hdr_end];
        let status = first_line(head)
            .split(|&b| b == b' ')
            .nth(1)
            .and_then(|c| std::str::from_utf8(c).ok())
            .and_then(|c| c.parse().ok())
            .unwrap_or(0);
        let content_type = header(head, b"content-type:")
            .map(lossy)
            .unwrap_or_default();
        let has_len = header(head, b"content-length:").is_some();
        let clen = content_len(head);
        out.push(Resp {
            status,
            content_type,
            content_len: clen,
        });
        if !has_len {
            break; // chunked / connection-close — can't reliably resync the next response
        }
        // Clamp the body to the remaining stream + use saturating arithmetic so a hostile
        // Content-Length can't overflow `pos`. `start >= pos` and `+4` guarantee forward progress.
        let body = clen.min(s2c.len() as u64) as usize;
        pos = start
            .saturating_add(hdr_end)
            .saturating_add(4)
            .saturating_add(body);
    }
    out
}

/// Parse the HTTP/1.1 transactions over a decrypted flow's two directions (best-effort, bounded).
pub(crate) fn parse_transactions(c2s: &[u8], s2c: &[u8]) -> Vec<HttpTxn> {
    let reqs = parse_requests(c2s);
    let resps = parse_responses(s2c);
    let n = reqs.len().max(resps.len()).min(MAX_TXN);
    (0..n)
        .map(|i| {
            let r = reqs.get(i);
            let resp = resps.get(i);
            HttpTxn {
                method: r.map(|r| r.method.clone()).unwrap_or_default(),
                target: r.map(|r| r.target.clone()).unwrap_or_default(),
                host: r.map(|r| r.host.clone()).unwrap_or_default(),
                status: resp.map(|r| r.status).unwrap_or(0),
                content_type: resp.map(|r| r.content_type.clone()).unwrap_or_default(),
                resp_bytes: resp.map(|r| r.content_len).unwrap_or(0),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_protocol() {
        assert_eq!(detect_proto(b""), "none");
        assert_eq!(detect_proto(b"GET / HTTP/1.1\r\n"), "http/1.1");
        assert_eq!(detect_proto(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"), "http/2");
        assert_eq!(detect_proto(b"\x16\x03\x03 random binary"), "unknown");
    }

    #[test]
    fn pairs_request_and_response() {
        let c2s = b"GET /malware.exe HTTP/1.1\r\nHost: evil.example\r\nUser-Agent: x\r\n\r\n";
        let s2c =
            b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: 4\r\n\r\nMZ\x90\x00";
        let txns = parse_transactions(c2s, s2c);
        assert_eq!(txns.len(), 1);
        assert_eq!(txns[0].method, "GET");
        assert_eq!(txns[0].target, "/malware.exe");
        assert_eq!(txns[0].host, "evil.example");
        assert_eq!(txns[0].status, 200);
        assert_eq!(txns[0].content_type, "application/octet-stream");
        assert_eq!(txns[0].resp_bytes, 4);
    }

    #[test]
    fn walks_keep_alive_requests() {
        let c2s = b"GET /a HTTP/1.1\r\nHost: h\r\n\r\nGET /b HTTP/1.1\r\nHost: h\r\n\r\n";
        let reqs = parse_requests(c2s);
        assert_eq!(reqs.len(), 2);
        assert_eq!(reqs[0].target, "/a");
        assert_eq!(reqs[1].target, "/b");
    }

    /// A hostile `Content-Length` (u64::MAX) must not overflow the position cursor (the body is
    /// clamped to the remaining stream); the parser terminates instead of panicking.
    #[test]
    fn huge_content_length_does_not_overflow() {
        let req = b"GET / HTTP/1.1\r\nHost: x\r\nContent-Length: 18446744073709551615\r\n\r\n";
        let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 18446744073709551615\r\n\r\nX";
        let txns = parse_transactions(req, resp);
        assert_eq!(txns.len(), 1);
        assert_eq!(txns[0].method, "GET");
        assert_eq!(txns[0].status, 200);
    }

    #[test]
    fn never_panics_on_garbage() {
        for seed in 0u16..200 {
            let junk: Vec<u8> = (0..seed).map(|i| (i.wrapping_mul(37)) as u8).collect();
            let _ = parse_transactions(&junk, &junk);
            let _ = detect_proto(&junk);
        }
    }
}
