//! NTLMSSP (MS-NLMP) message parser: the cleartext fields of the three handshake messages.
//!
//! NTLM rides inside SMB session setup (raw or SPNEGO-wrapped), HTTP and LDAP; the caller hands
//! this module any blob and it finds the `NTLMSSP\0` signature itself. From an AUTHENTICATE
//! (type 3) message it reads the account, domain and workstation names and the *lengths* of the
//! LM and NT responses — the length alone separates NTLMv1 (a 24-byte response, derived straight
//! from the password hash) from NTLMv2, which is all the legacy-auth detector needs. The response
//! bytes themselves, the session key and the MIC are never read or retained: nothing that could
//! help crack a password leaves this module.

use super::ber;

/// `NTLMSSP\0`.
const SIG: &[u8] = b"NTLMSSP\0";

/// NEGOTIATE flags we act on.
const NEGOTIATE_UNICODE: u32 = 0x0000_0001;

/// Which handshake message, and what little we keep from it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum NtlmMsg {
    /// Type 1, from the client. Carries only negotiated flags.
    Negotiate { flags: u32 },
    /// Type 2, from the server (the challenge). Flags only.
    Challenge { flags: u32 },
    /// Type 3, from the client: the response. Names, and the response lengths that tell the
    /// NTLM version apart.
    Authenticate(Auth),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Auth {
    pub user: String,
    pub domain: String,
    pub workstation: String,
    /// Length of the LM response field (0, or 24 for the legacy LM response).
    pub lm_len: u16,
    /// Length of the NT response field: 24 marks NTLMv1, longer marks NTLMv2.
    pub nt_len: u16,
    pub flags: u32,
}

impl Auth {
    /// An NTLMv1 (or LM) response: the 24-byte form, derived directly from the password hash and
    /// crackable far faster than NTLMv2's per-exchange blob.
    pub(crate) fn is_ntlm_v1(&self) -> bool {
        self.nt_len == 24 || (self.nt_len == 0 && self.lm_len == 24)
    }

    /// `user@domain` where both are known, else whichever is present.
    pub(crate) fn account(&self) -> String {
        match (self.user.is_empty(), self.domain.is_empty()) {
            (false, false) => format!("{}\\{}", self.domain, self.user),
            (false, true) => self.user.clone(),
            (true, false) => format!("{}\\", self.domain),
            (true, true) => String::new(),
        }
    }
}

/// Find the NTLMSSP signature in a blob (raw or SPNEGO-wrapped) and parse the message at it.
pub(crate) fn find(blob: &[u8]) -> Option<NtlmMsg> {
    let pos = find_sig(blob)?;
    parse(&blob[pos..])
}

/// Index of the `NTLMSSP\0` signature, if present. Bounded scan.
fn find_sig(blob: &[u8]) -> Option<usize> {
    blob.windows(SIG.len()).take(4096).position(|w| w == SIG)
}

/// Parse an NTLMSSP message whose signature is at the front of `msg`.
pub(crate) fn parse(msg: &[u8]) -> Option<NtlmMsg> {
    if msg.len() < 12 || &msg[..8] != SIG {
        return None;
    }
    let mtype = u32::from_le_bytes([msg[8], msg[9], msg[10], msg[11]]);
    match mtype {
        1 => Some(NtlmMsg::Negotiate {
            flags: u32_at(msg, 12).unwrap_or(0),
        }),
        2 => Some(NtlmMsg::Challenge {
            flags: u32_at(msg, 20).unwrap_or(0),
        }),
        3 => {
            let flags = u32_at(msg, 60).unwrap_or(0);
            let unicode = flags & NEGOTIATE_UNICODE != 0;
            let (lm_len, _) = field(msg, 12)?;
            let (nt_len, _) = field(msg, 20)?;
            Some(NtlmMsg::Authenticate(Auth {
                domain: string_field(msg, 28, unicode),
                user: string_field(msg, 36, unicode),
                workstation: string_field(msg, 44, unicode),
                lm_len,
                nt_len,
                flags,
            }))
        }
        _ => None,
    }
}

fn u32_at(b: &[u8], off: usize) -> Option<u32> {
    let s = b.get(off..off + 4)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

/// A security-buffer descriptor at `off`: `(Len, BufferOffset)`.
fn field(msg: &[u8], off: usize) -> Option<(u16, u32)> {
    let s = msg.get(off..off + 8)?;
    Some((
        u16::from_le_bytes([s[0], s[1]]),
        u32::from_le_bytes([s[4], s[5], s[6], s[7]]),
    ))
}

/// Decode the string a security buffer at `off` points to (UTF-16LE or OEM), cleaned and bounded.
fn string_field(msg: &[u8], off: usize, unicode: bool) -> String {
    let Some((len, buf_off)) = field(msg, off) else {
        return String::new();
    };
    let start = buf_off as usize;
    let end = start.saturating_add(usize::from(len));
    let Some(bytes) = msg.get(start..end) else {
        return String::new();
    };
    let decoded: Vec<u8> = if unicode {
        // UTF-16LE -> take the low byte of each unit; account/domain/host names are ASCII in
        // practice, and clean_str drops anything that is not.
        bytes
            .chunks_exact(2)
            .take(ber::MAX_STR)
            .map(|c| c[0])
            .collect()
    } else {
        bytes.to_vec()
    };
    ber::clean_str(&decoded)
}

#[cfg(test)]
pub(crate) mod build {
    use super::SIG;

    /// A security buffer descriptor (len, maxlen, offset).
    fn desc(len: u16, off: u32) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&len.to_le_bytes());
        v.extend_from_slice(&len.to_le_bytes());
        v.extend_from_slice(&off.to_le_bytes());
        v
    }

    fn u16le(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
    }

    /// Build a type-3 AUTHENTICATE message (unicode names) with the given response lengths.
    pub fn authenticate(domain: &str, user: &str, host: &str, lm_len: u16, nt_len: u16) -> Vec<u8> {
        let flags: u32 = 0x0000_0001; // NEGOTIATE_UNICODE
        let d = u16le(domain);
        let u = u16le(user);
        let w = u16le(host);
        // Payload order: LM resp, NT resp, domain, user, workstation, session key.
        let base = 64u32; // fixed header, no Version/MIC
        let lm_off = base;
        let nt_off = lm_off + u32::from(lm_len);
        let dom_off = nt_off + u32::from(nt_len);
        let usr_off = dom_off + d.len() as u32;
        let wks_off = usr_off + u.len() as u32;

        let mut m = Vec::new();
        m.extend_from_slice(SIG);
        m.extend_from_slice(&3u32.to_le_bytes()); // MessageType
        m.extend_from_slice(&desc(lm_len, lm_off)); // LmChallengeResponse
        m.extend_from_slice(&desc(nt_len, nt_off)); // NtChallengeResponse
        m.extend_from_slice(&desc(d.len() as u16, dom_off)); // DomainName
        m.extend_from_slice(&desc(u.len() as u16, usr_off)); // UserName
        m.extend_from_slice(&desc(w.len() as u16, wks_off)); // Workstation
        m.extend_from_slice(&desc(0, wks_off)); // EncryptedRandomSessionKey
        m.extend_from_slice(&flags.to_le_bytes()); // NegotiateFlags
        debug_assert_eq!(m.len(), 64);
        m.extend(std::iter::repeat_n(0xAAu8, usize::from(lm_len))); // opaque LM response
        m.extend(std::iter::repeat_n(0xBBu8, usize::from(nt_len))); // opaque NT response
        m.extend_from_slice(&d);
        m.extend_from_slice(&u);
        m.extend_from_slice(&w);
        m
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_account_and_detects_ntlm_v1() {
        let m = build::authenticate("CORP", "svc_sql", "WS01", 24, 24);
        let NtlmMsg::Authenticate(a) = find(&m).unwrap() else {
            panic!("not an authenticate")
        };
        assert_eq!(a.user, "svc_sql");
        assert_eq!(a.domain, "CORP");
        assert_eq!(a.workstation, "WS01");
        assert_eq!(a.account(), "CORP\\svc_sql");
        assert!(a.is_ntlm_v1(), "24-byte NT response is NTLMv1");
    }

    #[test]
    fn ntlm_v2_is_not_flagged() {
        let m = build::authenticate("CORP", "alice", "WS02", 0, 220);
        let NtlmMsg::Authenticate(a) = parse(&m).unwrap() else {
            panic!()
        };
        assert!(!a.is_ntlm_v1());
        assert_eq!(a.account(), "CORP\\alice");
    }

    #[test]
    fn finds_signature_inside_a_spnego_wrapper() {
        let inner = build::authenticate("CORP", "bob", "WS03", 24, 24);
        let mut wrapped = vec![0x60, 0x40, 0x06, 0x06, 0x2b]; // junk SPNEGO prefix
        wrapped.extend_from_slice(&inner);
        let NtlmMsg::Authenticate(a) = find(&wrapped).unwrap() else {
            panic!()
        };
        assert_eq!(a.user, "bob");
    }

    #[test]
    fn garbage_never_panics() {
        let mut x: u32 = 0x9e37_79b9;
        for len in 0..300 {
            let buf: Vec<u8> = (0..len)
                .map(|_| {
                    x ^= x << 13;
                    x ^= x >> 17;
                    x ^= x << 5;
                    x as u8
                })
                .collect();
            let _ = find(&buf);
            let _ = parse(&buf);
        }
        // Lengths that point past the end must not panic.
        let mut m = build::authenticate("A", "b", "C", 24, 24);
        m.truncate(70);
        let _ = parse(&m);
    }
}
