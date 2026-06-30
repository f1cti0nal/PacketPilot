//! NSS key-log (`SSLKEYLOGFILE`) parser.
//!
//! The user supplies the key-log their browser/app wrote while the capture ran; this maps each TLS
//! session — keyed by the 32-byte ClientHello random — to its derived secrets. Decryption keys are
//! derived from those secrets (see [`super::decrypt`]). Like the capture itself, the key-log stays
//! on the device; nothing leaves the browser. Pure parsing, wasm-safe.
//!
//! Format: one entry per line, `<LABEL> <client_random_hex> <secret_hex>`; `#` comments and blank
//! lines are ignored. Labels include `CLIENT_TRAFFIC_SECRET_0` / `SERVER_TRAFFIC_SECRET_0` (TLS 1.3
//! application data), the `*_HANDSHAKE_TRAFFIC_SECRET` pair (1.3 handshake), and `CLIENT_RANDOM`
//! (TLS 1.2 master secret). Reference: Mozilla NSS key-log format.

use std::collections::HashMap;

/// Parsed key-log: ClientHello random → (label → secret bytes).
#[derive(Debug, Default, Clone)]
pub struct KeyLog {
    by_random: HashMap<[u8; 32], HashMap<String, Vec<u8>>>,
}

/// Decode an even-length lowercase/uppercase hex string to bytes; `None` on any non-hex char.
fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    let mut i = 0;
    while i < b.len() {
        let hi = (b[i] as char).to_digit(16)?;
        let lo = (b[i + 1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
        i += 2;
    }
    Some(out)
}

impl KeyLog {
    /// Parse a key-log file's text. Comment/blank/malformed lines are skipped (best-effort — a
    /// stray line never discards the rest of the log).
    pub fn parse(text: &str) -> Self {
        let mut by_random: HashMap<[u8; 32], HashMap<String, Vec<u8>>> = HashMap::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut it = line.split_whitespace();
            let (Some(label), Some(cr_hex), Some(secret_hex)) = (it.next(), it.next(), it.next())
            else {
                continue;
            };
            if it.next().is_some() {
                continue; // exactly three fields
            }
            let Some(cr) = decode_hex(cr_hex) else {
                continue;
            };
            if cr.len() != 32 {
                continue;
            }
            let Some(secret) = decode_hex(secret_hex) else {
                continue;
            };
            let mut random = [0u8; 32];
            random.copy_from_slice(&cr);
            by_random
                .entry(random)
                .or_default()
                .insert(label.to_string(), secret);
        }
        KeyLog { by_random }
    }

    /// The secret bytes for a (ClientHello random, label) pair, if present.
    pub fn secret(&self, client_random: &[u8; 32], label: &str) -> Option<&[u8]> {
        self.by_random
            .get(client_random)?
            .get(label)
            .map(Vec::as_slice)
    }

    /// Number of distinct TLS sessions (ClientHello randoms) in the log.
    pub fn session_count(&self) -> usize {
        self.by_random.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_random.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn random32(hex_byte: &str) -> [u8; 32] {
        let mut r = [0u8; 32];
        r.copy_from_slice(&decode_hex(&hex_byte.repeat(32)).unwrap());
        r
    }

    #[test]
    fn parses_tls13_secrets_keyed_by_client_random() {
        let cr = "ab".repeat(32);
        let log = KeyLog::parse(&format!(
            "# SSL/TLS secrets log file\n\
             CLIENT_TRAFFIC_SECRET_0 {cr} {}\n\
             SERVER_TRAFFIC_SECRET_0 {cr} {}\n",
            "cd".repeat(32),
            "ef".repeat(32),
        ));
        assert_eq!(log.session_count(), 1);
        let r = random32("ab");
        assert_eq!(log.secret(&r, "CLIENT_TRAFFIC_SECRET_0").unwrap().len(), 32);
        assert!(log.secret(&r, "SERVER_TRAFFIC_SECRET_0").is_some());
        assert!(log.secret(&r, "NOT_A_LABEL").is_none());
    }

    #[test]
    fn skips_comments_blanks_and_malformed_lines() {
        let log = KeyLog::parse("\n  \n# a comment\nONLY_TWO fields\nCLIENT_RANDOM short beef\n");
        assert!(log.is_empty());
    }

    #[test]
    fn parses_tls12_master_secret_48_bytes() {
        let cr = "11".repeat(32);
        let ms = "22".repeat(48); // TLS 1.2 master secret is 48 bytes
        let log = KeyLog::parse(&format!("CLIENT_RANDOM {cr} {ms}"));
        assert_eq!(
            log.secret(&random32("11"), "CLIENT_RANDOM").unwrap().len(),
            48
        );
    }

    #[test]
    fn last_write_wins_for_duplicate_label() {
        let cr = "00".repeat(32);
        let log = KeyLog::parse(&format!(
            "CLIENT_TRAFFIC_SECRET_0 {cr} {}\nCLIENT_TRAFFIC_SECRET_0 {cr} {}\n",
            "01".repeat(32),
            "02".repeat(32),
        ));
        assert_eq!(
            log.secret(&random32("00"), "CLIENT_TRAFFIC_SECRET_0")
                .unwrap()[0],
            0x02
        );
    }
}
