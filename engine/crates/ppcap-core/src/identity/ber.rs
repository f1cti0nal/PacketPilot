//! Minimal BER/DER reader for the identity parsers (Kerberos is DER, LDAP is BER).
//!
//! Only what the parsers need: definite-length TLVs, single- and multi-byte tags, and helpers
//! to walk a constructed value's children. Never panics; every length is checked against the
//! slice it claims to cover, and indefinite lengths (never used by Kerberos or LDAP) are rejected.

/// Tag class (the top two bits of the identifier octet).
pub(crate) const CLASS_UNIVERSAL: u8 = 0;
pub(crate) const CLASS_APPLICATION: u8 = 1;
pub(crate) const CLASS_CONTEXT: u8 = 2;

/// One decoded TLV.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Tlv<'a> {
    pub class: u8,
    pub constructed: bool,
    pub tag: u32,
    pub body: &'a [u8],
    /// Header + body length (how many bytes of the input this TLV spans).
    pub total_len: usize,
}

/// The identifier + length header of a TLV, without requiring the body to be present.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Header {
    pub class: u8,
    pub constructed: bool,
    pub tag: u32,
    pub hdr_len: usize,
    pub body_len: usize,
}

/// Why a header could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HeaderErr {
    /// Not enough bytes yet (stream framing: wait for more).
    Short,
    /// Not a definite-length BER header.
    Invalid,
}

/// Read a TLV header. Tags wider than 28 bits and lengths wider than 4 bytes are invalid.
pub(crate) fn header(buf: &[u8]) -> Result<Header, HeaderErr> {
    let first = *buf.first().ok_or(HeaderErr::Short)?;
    let class = first >> 6;
    let constructed = first & 0x20 != 0;
    let mut i = 1;
    let mut tag = u32::from(first & 0x1f);
    if tag == 0x1f {
        tag = 0;
        loop {
            let b = *buf.get(i).ok_or(HeaderErr::Short)?;
            i += 1;
            if i > 5 {
                return Err(HeaderErr::Invalid);
            }
            tag = (tag << 7) | u32::from(b & 0x7f);
            if b & 0x80 == 0 {
                break;
            }
        }
    }
    let lb = *buf.get(i).ok_or(HeaderErr::Short)?;
    i += 1;
    let body_len = if lb & 0x80 == 0 {
        usize::from(lb)
    } else {
        let n = usize::from(lb & 0x7f);
        if n == 0 || n > 4 {
            return Err(HeaderErr::Invalid);
        }
        let mut len: usize = 0;
        for _ in 0..n {
            let b = *buf.get(i).ok_or(HeaderErr::Short)?;
            i += 1;
            len = (len << 8) | usize::from(b);
        }
        len
    };
    Ok(Header {
        class,
        constructed,
        tag,
        hdr_len: i,
        body_len,
    })
}

/// Read one complete TLV from the front of `buf`.
pub(crate) fn read(buf: &[u8]) -> Option<Tlv<'_>> {
    let h = header(buf).ok()?;
    let end = h.hdr_len.checked_add(h.body_len)?;
    let body = buf.get(h.hdr_len..end)?;
    Some(Tlv {
        class: h.class,
        constructed: h.constructed,
        tag: h.tag,
        body,
        total_len: end,
    })
}

/// Iterate the children of a constructed value. Stops at the first malformed child.
pub(crate) fn children(body: &[u8]) -> Children<'_> {
    Children { rest: body }
}

pub(crate) struct Children<'a> {
    rest: &'a [u8],
}

impl<'a> Iterator for Children<'a> {
    type Item = Tlv<'a>;
    fn next(&mut self) -> Option<Tlv<'a>> {
        if self.rest.is_empty() {
            return None;
        }
        match read(self.rest) {
            Some(t) => {
                self.rest = &self.rest[t.total_len..];
                Some(t)
            }
            None => {
                self.rest = &[];
                None
            }
        }
    }
}

impl<'a> Tlv<'a> {
    pub(crate) fn is(&self, class: u8, tag: u32) -> bool {
        self.class == class && self.tag == tag
    }

    /// The context-specific child `[n]` of this constructed value, if present.
    pub(crate) fn ctx(&self, n: u32) -> Option<Tlv<'a>> {
        children(self.body).find(|c| c.is(CLASS_CONTEXT, n))
    }

    /// The single TLV wrapped by an explicit tag (`[n] EXPLICIT X` -> X).
    pub(crate) fn inner(&self) -> Option<Tlv<'a>> {
        read(self.body)
    }

    /// Body as a signed big-endian integer (up to 8 bytes).
    pub(crate) fn int(&self) -> Option<i64> {
        int_of(self.body)
    }
}

/// Decode a two's-complement big-endian INTEGER body.
pub(crate) fn int_of(body: &[u8]) -> Option<i64> {
    if body.is_empty() || body.len() > 8 {
        return None;
    }
    let mut v: i64 = if body[0] & 0x80 != 0 { -1 } else { 0 };
    for &b in body {
        v = (v << 8) | i64::from(b);
    }
    Some(v)
}

/// Longest string retained from the wire (account names, SPNs, filters).
pub(crate) const MAX_STR: usize = 256;

/// A wire string made safe to keep: lossy UTF-8, control characters dropped, capped at
/// [`MAX_STR`] characters.
pub(crate) fn clean_str(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_STR)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_short_and_long_form_lengths() {
        let t = read(&[0x02, 0x01, 0x05]).unwrap();
        assert_eq!(t.int(), Some(5));
        let mut long = vec![0x04, 0x82, 0x01, 0x00];
        long.extend_from_slice(&[b'a'; 256]);
        let t = read(&long).unwrap();
        assert_eq!(t.body.len(), 256);
        assert_eq!(t.total_len, 260);
    }

    #[test]
    fn multi_byte_tags_and_application_class() {
        // [APPLICATION 30] constructed, 0 length.
        let t = read(&[0x7e, 0x00]).unwrap();
        assert!(t.is(CLASS_APPLICATION, 30) && t.constructed);
        // High-tag-number form: [CONTEXT 40].
        let t = read(&[0xbf, 0x28, 0x00]).unwrap();
        assert!(t.is(CLASS_CONTEXT, 40));
    }

    #[test]
    fn negative_integers_and_rejects() {
        assert_eq!(int_of(&[0xff, 0x79]), Some(-135));
        assert_eq!(int_of(&[]), None);
        assert_eq!(header(&[0x30, 0x80]), Err(HeaderErr::Invalid)); // indefinite
        assert_eq!(
            header(&[0x30, 0x85, 1, 1, 1, 1, 1]),
            Err(HeaderErr::Invalid)
        );
        assert_eq!(header(&[0x30, 0x82, 0x01]), Err(HeaderErr::Short));
        assert!(read(&[0x30, 0x05, 0x01]).is_none()); // body past the end
    }

    #[test]
    fn garbage_never_panics() {
        let mut x: u32 = 0x1234_5678;
        for len in 0..200 {
            let buf: Vec<u8> = (0..len)
                .map(|_| {
                    x ^= x << 13;
                    x ^= x >> 17;
                    x ^= x << 5;
                    x as u8
                })
                .collect();
            let _ = header(&buf);
            if let Some(t) = read(&buf) {
                for c in children(t.body) {
                    let _ = c.int();
                    let _ = c.inner();
                }
            }
        }
    }

    #[test]
    fn clean_str_strips_controls_and_caps() {
        assert_eq!(clean_str(b"svc\x00_sql\n"), "svc_sql");
        assert_eq!(clean_str(&[b'a'; 1000]).len(), MAX_STR);
    }
}
