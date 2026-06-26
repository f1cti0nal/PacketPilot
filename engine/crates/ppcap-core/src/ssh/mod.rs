//! SSH fingerprinting (HASSH / HASSHServer) — the SSH analogue of JA3 / JA3S.
//!
//! HASSH fingerprints an SSH *client* from the algorithm name-lists it offers in its `SSH_MSG_KEXINIT`
//! (sent in the clear, before key exchange): `MD5("kex;enc_c2s;mac_c2s;comp_c2s")`. HASSHServer is the
//! *server*'s counterpart over its KEXINIT's server→client lists: `MD5("kex;enc_s2c;mac_s2c;comp_s2c")`.
//! Distinct SSH stacks (OpenSSH, PuTTY, libssh, paramiko, Go x/crypto/ssh, scanners) produce distinct
//! HASSHes, so they surface scripted/automated SSH clients and identify server builds — a useful
//! companion to the brute-force detector. Payload-free: only the derived fingerprint is kept, never
//! the handshake bytes.

use crate::fingerprint::md5_hex;
use crate::model::packet::Transport;

const SSH_MSG_KEXINIT: u8 = 20;

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
    let _host_key = r.next()?; // server_host_key_algorithms
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
}
