//! SSH fingerprinting (HASSH / HASSHServer) — the SSH analogue of JA3 / JA3S.
//!
//! HASSH fingerprints an SSH *client* from the algorithm name-lists it offers in its `SSH_MSG_KEXINIT`
//! (sent in the clear, before key exchange): `MD5("kex;enc_c2s;mac_c2s;comp_c2s")`. HASSHServer is the
//! *server*'s counterpart over its KEXINIT's server→client lists: `MD5("kex;enc_s2c;mac_s2c;comp_s2c")`.
//! Distinct SSH stacks (OpenSSH, PuTTY, libssh, paramiko, Go x/crypto/ssh, scanners) produce distinct
//! HASSHes, so they surface scripted/automated SSH clients and identify server builds — a useful
//! companion to the brute-force detector. Payload-free: only the derived fingerprint is kept, never
//! the handshake bytes.
//!
//! The same cleartext handshake also carries the module's second product: [`SshIssue`], a *posture*
//! verdict (SSH-1 support, a deprecated host key, a CBC/`none` cipher). Same keyless principle —
//! everything read here precedes key exchange, so no decryption is involved.

use crate::fingerprint::md5_hex;
use crate::model::packet::Transport;

const SSH_MSG_KEXINIT: u8 = 20;

/// Longest identification line retained. RFC 4253 §4.2 caps the line at 255 bytes including CRLF.
const MAX_BANNER_LEN: usize = 255;

// ---------------------------------------------------------------------------------------------
// SSH posture
// ---------------------------------------------------------------------------------------------

/// A weakness visible in the cleartext SSH handshake — the SSH counterpart to
/// [`crate::tls::WeakTlsReason`], and deliberately the same shape: a closed enum whose variants
/// each know their own token, rank, and evidence line.
///
/// Conservative by construction: only *known-bad* algorithms are named. An unrecognized algorithm
/// is never flagged, so a modern or vendor-specific stack cannot false-positive.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SshIssue {
    /// The identification line advertises SSH protocol 1.x (including the `1.99` dual-stack
    /// banner, which means SSH-1 is *accepted*). SSH-1 is cryptographically broken.
    Ssh1Supported { banner: String },
    /// A host-key algorithm relying on SHA-1 or DSA was offered.
    WeakHostKey { algo: String },
    /// A CBC-mode or `none` cipher was offered (CBC in SSH is the plaintext-recovery attack of
    /// CVE-2008-5161; `none` is no encryption at all).
    WeakCipher { algo: String },
}

impl SshIssue {
    /// Stable kebab-case token.
    pub(crate) fn kind_str(&self) -> &'static str {
        match self {
            SshIssue::Ssh1Supported { .. } => "ssh1-supported",
            SshIssue::WeakHostKey { .. } => "weak-host-key",
            SshIssue::WeakCipher { .. } => "weak-cipher",
        }
    }

    /// Severity rank: 3 = broken protocol, 2 = weak/absent encryption, 1 = deprecated signature.
    pub(crate) fn severity_rank(&self) -> u8 {
        match self {
            SshIssue::Ssh1Supported { .. } => 3,
            SshIssue::WeakCipher { .. } => 2,
            SshIssue::WeakHostKey { .. } => 1,
        }
    }

    /// Deterministic ordering key so evidence lists are stable across runs. Worst-first (the tag
    /// mirrors [`SshIssue::severity_rank`] inverted), then by algorithm name, so the bullet an
    /// operator should act on leads the list.
    pub(crate) fn order_key(&self) -> (u8, &str) {
        match self {
            SshIssue::Ssh1Supported { banner } => (0, banner.as_str()),
            SshIssue::WeakCipher { algo } => (1, algo.as_str()),
            SshIssue::WeakHostKey { algo } => (2, algo.as_str()),
        }
    }

    /// One human-readable evidence bullet.
    pub(crate) fn evidence(&self) -> String {
        match self {
            SshIssue::Ssh1Supported { banner } => format!(
                "identification line advertises SSH-1 support ({banner}) — SSH-1 is cryptographically broken"
            ),
            SshIssue::WeakHostKey { algo } => format!(
                "host-key algorithm {algo} offered — SHA-1/DSA signatures are deprecated"
            ),
            SshIssue::WeakCipher { algo } => {
                format!("cipher {algo} offered — CBC-mode/none encryption is unsafe (CVE-2008-5161)")
            }
        }
    }
}

/// Host-key algorithms an analyst should be told about: SHA-1-based RSA and DSA.
///
/// `ssh-rsa` is the *SHA-1* RSA signature algorithm — distinct from `rsa-sha2-256`/`rsa-sha2-512`,
/// which are fine. Matching is exact, so the modern names are never caught by this list.
const WEAK_HOST_KEYS: &[&str] = &["ssh-dss", "ssh-rsa", "ssh-dss-cert-v01@openssh.com"];

/// Cipher names that are CBC-mode or no encryption at all. Exact matches only.
#[rustfmt::skip]
const WEAK_CIPHERS: &[&str] = &[
    "none",
    "3des-cbc", "blowfish-cbc", "cast128-cbc", "arcfour", "arcfour128", "arcfour256",
    "aes128-cbc", "aes192-cbc", "aes256-cbc", "rijndael-cbc@lysator.liu.se",
];

/// Sniff the SSH identification line ("SSH-2.0-OpenSSH_9.6") from a payload that begins with one.
///
/// Retained because it is the single most useful SSH triage datum and is pure cleartext: it names
/// the software and version on both ends. Separate from the KEXINIT sniff because the banner very
/// often arrives in its own segment, ahead of any KEXINIT.
///
/// Bounded (RFC 4253 §4.2 caps the line at 255 bytes) and ASCII-gated, so a coincidental payload
/// beginning `SSH-` cannot inject arbitrary bytes into the summary.
pub(crate) fn sniff_ssh_banner(transport: Transport, payload: &[u8]) -> Option<String> {
    if transport != Transport::Tcp || !payload.starts_with(b"SSH-") {
        return None;
    }
    let end = payload
        .iter()
        .take(MAX_BANNER_LEN)
        .position(|&b| b == b'\r' || b == b'\n')?;
    let line = payload.get(..end)?;
    // Printable ASCII only — the version string is defined as such, and this keeps control bytes
    // out of the summary/report surface.
    if line.len() < 5 || !line.iter().all(|b| (0x20..0x7f).contains(b)) {
        return None;
    }
    Some(String::from_utf8_lossy(line).into_owned())
}

/// Derive the posture issues visible in a cleartext SSH handshake segment.
///
/// Reads the identification line (SSH-1 support) and, when the segment also carries a KEXINIT, the
/// offered host-key and cipher algorithm lists. Returns an empty vec for healthy handshakes and
/// for non-SSH payloads, so the caller can store it unconditionally.
pub(crate) fn sniff_ssh_issues(transport: Transport, payload: &[u8]) -> Vec<SshIssue> {
    if transport != Transport::Tcp {
        return Vec::new();
    }
    let mut issues = Vec::new();

    if let Some(banner) = sniff_ssh_banner(transport, payload) {
        // "SSH-1.x" is SSH-1 only; "SSH-1.99" is the dual-stack banner meaning SSH-1 is accepted.
        let proto = banner.strip_prefix("SSH-").unwrap_or("");
        if proto.starts_with("1.") {
            issues.push(SshIssue::Ssh1Supported { banner });
        }
    }

    if let Some(k) = parse_kexinit(payload) {
        for algo in WEAK_HOST_KEYS {
            if list_contains(&k.host_key, algo) {
                issues.push(SshIssue::WeakHostKey {
                    algo: (*algo).to_string(),
                });
            }
        }
        for algo in WEAK_CIPHERS {
            if list_contains(&k.enc_c2s, algo) || list_contains(&k.enc_s2c, algo) {
                issues.push(SshIssue::WeakCipher {
                    algo: (*algo).to_string(),
                });
            }
        }
    }

    issues.sort_by(|a, b| a.order_key().cmp(&b.order_key()));
    issues.dedup();
    issues
}

/// Exact membership test over an SSH comma-separated name-list (so `ssh-rsa` never matches
/// `rsa-sha2-512`, and `arcfour` never matches `arcfour128`).
fn list_contains(list: &str, needle: &str) -> bool {
    list.split(',').any(|n| n.trim() == needle)
}

/// Sniff a client HASSH from an L4 payload that begins (after an optional identification line) with
/// an SSH KEXINIT. Returns the MD5 HASSH of the client's offered algorithm lists, or `None` when the
/// payload is not a *client*-side SSH KEXINIT.
///
/// SSH is TCP-only, so non-TCP payloads are rejected outright (mirrors the cleartext-cred / PII
/// sniffers). HASSH is the client's fingerprint, so server KEXINITs are skipped. Without flow state,
/// orientation is by port: the server listens on the lower / well-known port, so a client→server
/// KEXINIT travels toward a *strictly* lower port (`dst_port < src_port`) — strict, so a symmetric
/// `src==dst` flow drops rather than mislabeling either side. A single-segment KEXINIT is required
/// (reassembly is out of scope); split handshakes simply yield no fingerprint.
///
/// Residual limitation (port-only, no flow state): an SSH server on a port *higher* than the client's
/// source port (e.g. server :2222, client bound low) inverts the heuristic and would fingerprint the
/// server's KEXINIT as the client's (and vice-versa for the server sniff).
pub(crate) fn sniff_client_hassh(
    transport: Transport,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Option<String> {
    if transport != Transport::Tcp {
        return None;
    }
    // Only the client side carries the HASSH (client→server travels toward the lower/server port).
    if dst_port >= src_port {
        return None;
    }
    let k = parse_kexinit(payload)?;
    let s = format!("{};{};{};{}", k.kex, k.enc_c2s, k.mac_c2s, k.comp_c2s);
    Some(md5_hex(s.as_bytes()))
}

/// Sniff a server HASSHServer from an L4 payload that begins (after an optional identification line)
/// with an SSH KEXINIT. Returns `MD5("kex;enc_s2c;mac_s2c;comp_s2c")` over the *server*'s KEXINIT, or
/// `None` when the payload is not a *server*-side SSH KEXINIT. The mirror of [`sniff_client_hassh`]:
/// TCP-only, and the server's KEXINIT travels *from* the lower / listening port (`src_port < dst_port`,
/// strict so symmetric `src==dst` drops rather than mislabeling).
pub(crate) fn sniff_server_hassh(
    transport: Transport,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Option<String> {
    if transport != Transport::Tcp {
        return None;
    }
    // The server's KEXINIT travels from the lower/listening port toward the client's ephemeral port.
    if src_port >= dst_port {
        return None;
    }
    let k = parse_kexinit(payload)?;
    let s = format!("{};{};{};{}", k.kex, k.enc_s2c, k.mac_s2c, k.comp_s2c);
    Some(md5_hex(s.as_bytes()))
}

/// The KEXINIT name-lists HASSH / HASSHServer are computed from (the kex list plus each direction's
/// encryption / MAC / compression lists).
struct KexInit {
    kex: String,
    /// `server_host_key_algorithms` — read but discarded before F2; now feeds the posture check.
    host_key: String,
    enc_c2s: String,
    mac_c2s: String,
    comp_c2s: String,
    enc_s2c: String,
    mac_s2c: String,
    comp_s2c: String,
}

/// Parse an SSH KEXINIT, skipping a leading `SSH-…` identification line if the segment carries one.
/// Bounded and allocation-light; returns `None` on any structural mismatch or truncation, so a
/// non-SSH payload is rejected rather than fingerprinted.
fn parse_kexinit(payload: &[u8]) -> Option<KexInit> {
    let mut p = payload;
    // An optional identification line ("SSH-2.0-…\r\n") may precede the first binary packet.
    if p.starts_with(b"SSH-") {
        let nl = p.iter().position(|&b| b == b'\n')?;
        p = p.get(nl + 1..)?;
    }
    // Binary packet: uint32 packet_length, byte padding_length, byte[] payload, byte[] padding.
    if p.len() < 6 {
        return None;
    }
    let packet_len = u32::from_be_bytes([p[0], p[1], p[2], p[3]]) as usize;
    let pad_len = p[4] as usize;
    // A KEXINIT is small; bound the length so arbitrary TCP data is not mistaken for SSH.
    if !(12..=35_000).contains(&packet_len) {
        return None;
    }
    // Message bytes = packet_length - padding_length - 1 (the padding_length byte itself).
    let msg_len = packet_len.checked_sub(pad_len + 1)?;
    // Require the whole message present in this segment (no cross-segment reassembly here).
    let msg = p.get(5..5usize.checked_add(msg_len)?)?;
    // payload[0] = message number; cookie = next 16 bytes; then the 10 name-lists.
    if msg.first().copied()? != SSH_MSG_KEXINIT {
        return None;
    }
    let mut r = NameListReader {
        buf: msg.get(17..)?,
    };
    let kex = r.next()?; // kex_algorithms
    let host_key = r.next()?; // server_host_key_algorithms
    let enc_c2s = r.next()?; // encryption_algorithms_client_to_server
    let enc_s2c = r.next()?; // encryption_algorithms_server_to_client
    let mac_c2s = r.next()?; // mac_algorithms_client_to_server
    let mac_s2c = r.next()?; // mac_algorithms_server_to_client
    let comp_c2s = r.next()?; // compression_algorithms_client_to_server
    let comp_s2c = r.next()?; // compression_algorithms_server_to_client
                              // SSH algorithm lists are ASCII; a non-empty ASCII kex list is a strong SSH-ness gate that
                              // keeps a structurally-coincidental non-SSH payload from producing a bogus fingerprint.
    if kex.is_empty() || !kex.is_ascii() || !enc_c2s.is_ascii() {
        return None;
    }
    Some(KexInit {
        kex,
        host_key,
        enc_c2s,
        mac_c2s,
        comp_c2s,
        enc_s2c,
        mac_s2c,
        comp_s2c,
    })
}

/// Reads consecutive SSH `name-list`s (uint32 length + that many ASCII bytes) from a buffer.
struct NameListReader<'a> {
    buf: &'a [u8],
}

impl NameListReader<'_> {
    /// Read one name-list and advance past it; `None` on truncation or an implausibly long list.
    fn next(&mut self) -> Option<String> {
        if self.buf.len() < 4 {
            return None;
        }
        let len = u32::from_be_bytes([self.buf[0], self.buf[1], self.buf[2], self.buf[3]]) as usize;
        // Real algorithm name-lists are short; bound to keep a malformed length from over-reading.
        if len > 4096 {
            return None;
        }
        let bytes = self.buf.get(4..4 + len)?;
        self.buf = &self.buf[4 + len..];
        Some(String::from_utf8_lossy(bytes).into_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal SSH KEXINIT binary packet from the given name-lists (no padding).
    fn kexinit_packet(lists: &[&str]) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.push(SSH_MSG_KEXINIT);
        msg.extend_from_slice(&[0u8; 16]); // cookie
        for l in lists {
            msg.extend_from_slice(&(l.len() as u32).to_be_bytes());
            msg.extend_from_slice(l.as_bytes());
        }
        msg.push(0); // first_kex_packet_follows
        msg.extend_from_slice(&[0u8; 4]); // reserved
        let pad_len = 0u8;
        let packet_len = (msg.len() + 1) as u32; // msg + padding_length byte
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&packet_len.to_be_bytes());
        pkt.push(pad_len);
        pkt.extend_from_slice(&msg);
        pkt
    }

    // The 10 KEXINIT name-lists in order (kex, hostkey, enc_c2s, enc_s2c, mac_c2s, mac_s2c,
    // comp_c2s, comp_s2c, lang_c2s, lang_s2c).
    const LISTS: [&str; 10] = [
        "curve25519-sha256,ecdh-sha2-nistp256",
        "ssh-ed25519,rsa-sha2-512",
        "chacha20-poly1305@openssh.com,aes128-ctr",
        "chacha20-poly1305@openssh.com,aes128-ctr",
        "hmac-sha2-256,hmac-sha1",
        "hmac-sha2-256,hmac-sha1",
        "none,zlib@openssh.com",
        "none,zlib@openssh.com",
        "",
        "",
    ];

    #[test]
    fn client_hassh_matches_the_md5_of_the_c2s_lists() {
        let pkt = kexinit_packet(&LISTS);
        // Client -> server: dst_port (22) < src_port (54321).
        let fp = sniff_client_hassh(Transport::Tcp, 54321, 22, &pkt).expect("client hassh");
        let expected =
            md5_hex(format!("{};{};{};{}", LISTS[0], LISTS[2], LISTS[4], LISTS[6]).as_bytes());
        assert_eq!(fp, expected);
        assert_eq!(fp.len(), 32);
    }

    #[test]
    fn identification_banner_prefix_is_skipped() {
        let mut buf = b"SSH-2.0-OpenSSH_9.6\r\n".to_vec();
        buf.extend_from_slice(&kexinit_packet(&LISTS));
        let fp = sniff_client_hassh(Transport::Tcp, 50000, 22, &buf).expect("hassh past banner");
        assert_eq!(fp.len(), 32);
    }

    #[test]
    fn server_side_or_symmetric_kexinit_is_not_fingerprinted_as_client() {
        let pkt = kexinit_packet(&LISTS);
        // Server -> client: src_port (22) < dst_port (54321) -> not a client HASSH.
        assert!(sniff_client_hassh(Transport::Tcp, 22, 54321, &pkt).is_none());
        // Symmetric ports are ambiguous -> dropped (strict dst_port < src_port), never mislabeled.
        assert!(sniff_client_hassh(Transport::Tcp, 22, 22, &pkt).is_none());
    }

    #[test]
    fn non_tcp_and_non_ssh_payloads_are_rejected() {
        let pkt = kexinit_packet(&LISTS);
        // SSH is TCP-only: a structurally-valid KEXINIT over UDP/SCTP must not fingerprint.
        assert!(sniff_client_hassh(Transport::Udp, 54321, 22, &pkt).is_none());
        assert!(sniff_client_hassh(Transport::Sctp, 54321, 22, &pkt).is_none());
        assert!(sniff_client_hassh(
            Transport::Tcp,
            54321,
            80,
            b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"
        )
        .is_none());
        assert!(sniff_client_hassh(Transport::Tcp, 54321, 22, b"").is_none());
        assert!(sniff_client_hassh(Transport::Tcp, 54321, 22, &[0u8; 8]).is_none());
        // msg type 0
    }

    #[test]
    fn server_hassh_matches_the_md5_of_the_s2c_lists() {
        // Distinct c2s vs s2c lists so the server fingerprint is provably the server→client one.
        let lists = [
            "curve25519-sha256",      // kex
            "ssh-ed25519",            // host key
            "aes128-ctr",             // enc_c2s
            "aes256-gcm@openssh.com", // enc_s2c (different)
            "hmac-sha2-256",          // mac_c2s
            "hmac-sha2-512",          // mac_s2c (different)
            "none",                   // comp_c2s
            "zlib@openssh.com",       // comp_s2c (different)
            "",
            "",
        ];
        let pkt = kexinit_packet(&lists);
        // Server -> client: src_port (22) < dst_port (54321).
        let fp = sniff_server_hassh(Transport::Tcp, 22, 54321, &pkt).expect("server hassh");
        let expected =
            md5_hex(format!("{};{};{};{}", lists[0], lists[3], lists[5], lists[7]).as_bytes());
        assert_eq!(fp, expected);
        // Must NOT equal the client (c2s) fingerprint.
        let client_fp =
            md5_hex(format!("{};{};{};{}", lists[0], lists[2], lists[4], lists[6]).as_bytes());
        assert_ne!(fp, client_fp);
    }

    #[test]
    fn client_side_or_symmetric_kexinit_is_not_fingerprinted_as_server() {
        let pkt = kexinit_packet(&LISTS);
        // Client -> server (dst < src) is not a server HASSH; symmetric ports drop; non-TCP rejected.
        assert!(sniff_server_hassh(Transport::Tcp, 54321, 22, &pkt).is_none());
        assert!(sniff_server_hassh(Transport::Tcp, 22, 22, &pkt).is_none());
        assert!(sniff_server_hassh(Transport::Udp, 22, 54321, &pkt).is_none());
    }

    // ── SSH posture ──────────────────────────────────────────────────────────

    #[test]
    fn banner_is_read_only_from_a_well_formed_identification_line() {
        assert_eq!(
            sniff_ssh_banner(Transport::Tcp, b"SSH-2.0-OpenSSH_9.6p1 Debian-2\r\nrest"),
            Some("SSH-2.0-OpenSSH_9.6p1 Debian-2".to_string())
        );
        // Bare LF is what a number of stacks actually send; RFC 4253 wants CRLF.
        assert_eq!(
            sniff_ssh_banner(Transport::Tcp, b"SSH-2.0-libssh_0.10.5\n"),
            Some("SSH-2.0-libssh_0.10.5".to_string())
        );
        // Not SSH, wrong transport, unterminated, and control bytes all yield nothing.
        assert!(sniff_ssh_banner(Transport::Tcp, b"HTTP/1.1 200 OK\r\n").is_none());
        assert!(sniff_ssh_banner(Transport::Udp, b"SSH-2.0-OpenSSH_9.6\r\n").is_none());
        assert!(sniff_ssh_banner(Transport::Tcp, b"SSH-2.0-OpenSSH_9.6").is_none());
        assert!(sniff_ssh_banner(Transport::Tcp, b"SSH-\x01\x02bad\r\n").is_none());
        // A 300-byte line exceeds the RFC 4253 §4.2 cap, so no terminator is found in range.
        let mut long = b"SSH-2.0-".to_vec();
        long.extend(std::iter::repeat_n(b'x', 300));
        long.extend_from_slice(b"\r\n");
        assert!(sniff_ssh_banner(Transport::Tcp, &long).is_none());
    }

    #[test]
    fn ssh1_banners_are_flagged_and_ssh2_banners_are_not() {
        let ssh1 = sniff_ssh_issues(Transport::Tcp, b"SSH-1.5-OpenSSH_3.4p1\r\n");
        assert_eq!(
            ssh1,
            vec![SshIssue::Ssh1Supported {
                banner: "SSH-1.5-OpenSSH_3.4p1".to_string()
            }]
        );
        // "1.99" is the dual-stack banner: SSH-1 is *accepted*, so it is equally flagged.
        assert_eq!(
            sniff_ssh_issues(Transport::Tcp, b"SSH-1.99-OpenSSH_3.9p1\r\n").len(),
            1
        );
        assert!(sniff_ssh_issues(Transport::Tcp, b"SSH-2.0-OpenSSH_9.6p1\r\n").is_empty());
    }

    #[test]
    fn kexinit_weak_host_keys_and_ciphers_are_flagged_exactly() {
        let lists = [
            "curve25519-sha256",
            "rsa-sha2-512,ssh-dss", // ssh-dss is DSA — deprecated
            "aes128-ctr,3des-cbc",  // c2s carries a CBC cipher
            "aes128-ctr",
            "hmac-sha2-256",
            "hmac-sha2-256",
            "none",
            "none",
            "",
            "",
        ];
        let issues = sniff_ssh_issues(Transport::Tcp, &kexinit_packet(&lists));
        // Worst-first: the exploitable cipher leads the deprecated host key.
        assert_eq!(
            issues,
            vec![
                SshIssue::WeakCipher {
                    algo: "3des-cbc".to_string()
                },
                SshIssue::WeakHostKey {
                    algo: "ssh-dss".to_string()
                },
            ]
        );
        // A weakness offered only server→client is just as real as one offered client→server.
        let s2c_only = [
            "curve25519-sha256",
            "ssh-ed25519",
            "aes128-ctr",
            "aes256-cbc",
            "hmac-sha2-256",
            "hmac-sha2-256",
            "none",
            "none",
            "",
            "",
        ];
        assert_eq!(
            sniff_ssh_issues(Transport::Tcp, &kexinit_packet(&s2c_only)),
            vec![SshIssue::WeakCipher {
                algo: "aes256-cbc".to_string()
            }]
        );
    }

    /// The whole point of an exact name-list match: `ssh-rsa` (SHA-1) is weak, `rsa-sha2-512` is
    /// not, and `arcfour` is not `arcfour256`. A substring test would flag all of them.
    #[test]
    fn a_modern_handshake_is_never_flagged_by_prefix_collision() {
        assert!(sniff_ssh_issues(Transport::Tcp, &kexinit_packet(&LISTS)).is_empty());

        let modern = [
            "sntrup761x25519-sha512@openssh.com",
            "rsa-sha2-512,rsa-sha2-256,ecdsa-sha2-nistp256", // none of these is "ssh-rsa"
            "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com",
            "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com",
            "hmac-sha2-256-etm@openssh.com",
            "hmac-sha2-256-etm@openssh.com",
            // "none" here is the *compression* list, not a cipher — must not be flagged.
            "none,zlib@openssh.com",
            "none,zlib@openssh.com",
            "",
            "",
        ];
        assert!(sniff_ssh_issues(Transport::Tcp, &kexinit_packet(&modern)).is_empty());
        assert!(list_contains("ssh-rsa,rsa-sha2-512", "ssh-rsa"));
        assert!(!list_contains("rsa-sha2-512,rsa-sha2-256", "ssh-rsa"));
        assert!(!list_contains("arcfour256", "arcfour"));
    }

    #[test]
    fn issues_are_deduped_and_deterministically_ordered() {
        // An identification line + a KEXINIT in one segment: both sources contribute.
        let lists = [
            "curve25519-sha256",
            "ssh-rsa",
            "aes128-cbc",
            "aes128-cbc", // same cipher on both directions -> one issue, not two
            "hmac-sha2-256",
            "hmac-sha2-256",
            "none",
            "none",
            "",
            "",
        ];
        let mut buf = b"SSH-1.99-OpenSSH_4.3\r\n".to_vec();
        buf.extend_from_slice(&kexinit_packet(&lists));
        let issues = sniff_ssh_issues(Transport::Tcp, &buf);
        assert_eq!(
            issues,
            vec![
                SshIssue::Ssh1Supported {
                    banner: "SSH-1.99-OpenSSH_4.3".to_string()
                },
                SshIssue::WeakCipher {
                    algo: "aes128-cbc".to_string()
                },
                SshIssue::WeakHostKey {
                    algo: "ssh-rsa".to_string()
                },
            ]
        );
        // Non-SSH and non-TCP payloads return an empty vec rather than erroring, so the caller
        // can store the result unconditionally.
        assert!(sniff_ssh_issues(Transport::Udp, &buf).is_empty());
        assert!(sniff_ssh_issues(Transport::Tcp, b"GET / HTTP/1.1\r\n\r\n").is_empty());
    }

    /// The wire tokens are contract: they reach the summary JSON and the UI.
    #[test]
    fn issue_kind_tokens_and_ranks_are_stable() {
        let ssh1 = SshIssue::Ssh1Supported {
            banner: "SSH-1.5-x".to_string(),
        };
        let hk = SshIssue::WeakHostKey {
            algo: "ssh-dss".to_string(),
        };
        let cipher = SshIssue::WeakCipher {
            algo: "3des-cbc".to_string(),
        };
        assert_eq!(ssh1.kind_str(), "ssh1-supported");
        assert_eq!(hk.kind_str(), "weak-host-key");
        assert_eq!(cipher.kind_str(), "weak-cipher");
        // Broken protocol > exploitable cipher > deprecated host key.
        assert!(ssh1.severity_rank() > cipher.severity_rank());
        assert!(cipher.severity_rank() > hk.severity_rank());
        // Evidence names the specific algorithm, so an operator knows what to turn off.
        assert!(cipher.evidence().contains("3des-cbc"));
        assert!(hk.evidence().contains("ssh-dss"));
    }
}
