//! Minimal, bounds-checked DER (ASN.1 distinguished encoding rules) reader — just enough to walk
//! an X.509 certificate for the cert-health checks (validity dates, issuer/subject names, SAN).
//!
//! Hand-rolled in the engine house style (`.get(..)`, `checked_add`, never panics, no allocation
//! while walking) to honour the no-new-deps / C-compiler-free invariant. This is NOT a general
//! ASN.1 library: it understands definite-length TLVs and constructed children, nothing more.

/// Common DER tag bytes (see X.690 / RFC 5280).
pub(crate) const TAG_SEQUENCE: u8 = 0x30;
pub(crate) const TAG_OID: u8 = 0x06;
pub(crate) const TAG_BOOLEAN: u8 = 0x01;
pub(crate) const TAG_OCTET_STRING: u8 = 0x04;
pub(crate) const TAG_UTC_TIME: u8 = 0x17;
pub(crate) const TAG_GENERALIZED_TIME: u8 = 0x18;
/// Context `[0]` constructed — the optional `version` of a `tbsCertificate`.
pub(crate) const TAG_CTX_VERSION: u8 = 0xA0;
/// Context `[3]` constructed — the optional `extensions` of a `tbsCertificate`.
pub(crate) const TAG_CTX_EXTENSIONS: u8 = 0xA3;
/// Context `[2]` primitive — a `dNSName` inside a `subjectAltName` `GeneralNames`.
pub(crate) const TAG_GENERALNAME_DNS: u8 = 0x82;

/// One DER element: its tag byte, its content slice, and the offset just past it in the parent.
pub(crate) struct Tlv<'a> {
    pub tag: u8,
    pub content: &'a [u8],
    pub end: usize,
}

/// Read the TLV at `pos` in `buf`. Handles short- and long-form definite lengths. Returns `None`
/// on any truncation, an indefinite length, or a length wider than 4 bytes (no real certificate
/// field needs more). Never panics.
pub(crate) fn read_tlv(buf: &[u8], pos: usize) -> Option<Tlv<'_>> {
    let tag = *buf.get(pos)?;
    let len_pos = pos.checked_add(1)?;
    let first = *buf.get(len_pos)?;
    let (len, content_start) = if first & 0x80 == 0 {
        // Short form: the byte itself is the length.
        (first as usize, len_pos.checked_add(1)?)
    } else {
        // Long form: low 7 bits = number of subsequent length octets.
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 4 {
            return None; // indefinite (n == 0) is invalid DER; >4 bytes is absurd for a cert.
        }
        let mut len: usize = 0;
        for i in 0..n {
            let b = *buf.get(len_pos.checked_add(1)?.checked_add(i)?)?;
            len = (len << 8) | b as usize;
        }
        (len, len_pos.checked_add(1)?.checked_add(n)?)
    };
    let end = content_start.checked_add(len)?;
    let content = buf.get(content_start..end)?;
    Some(Tlv { tag, content, end })
}

/// Iterate the immediate children of a constructed element's `content`.
pub(crate) fn children(content: &[u8]) -> DerChildren<'_> {
    DerChildren {
        buf: content,
        pos: 0,
    }
}

/// Iterator over consecutive sibling TLVs in a constructed element. Stops at the first malformed
/// child (so a truncated tail never panics and never loops forever).
pub(crate) struct DerChildren<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Iterator for DerChildren<'a> {
    type Item = Tlv<'a>;

    fn next(&mut self) -> Option<Tlv<'a>> {
        if self.pos >= self.buf.len() {
            return None;
        }
        let tlv = read_tlv(self.buf, self.pos)?;
        // `end` is strictly greater than `pos` for any well-formed TLV (tag + length byte), so
        // the iterator always makes progress.
        self.pos = tlv.end;
        Some(tlv)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_short_form_tlv() {
        // SEQUENCE (len 3) { INTEGER 0x01 }
        let buf = [0x30, 0x03, 0x02, 0x01, 0x01];
        let seq = read_tlv(&buf, 0).unwrap();
        assert_eq!(seq.tag, TAG_SEQUENCE);
        assert_eq!(seq.end, 5);
        let int = read_tlv(seq.content, 0).unwrap();
        assert_eq!(int.tag, 0x02);
        assert_eq!(int.content, &[0x01]);
    }

    #[test]
    fn reads_long_form_length() {
        // OCTET STRING with a 2-byte (long-form) length of 0x0102 = 258 bytes.
        let mut buf = vec![TAG_OCTET_STRING, 0x82, 0x01, 0x02];
        buf.extend(std::iter::repeat_n(0xAB, 258));
        let tlv = read_tlv(&buf, 0).unwrap();
        assert_eq!(tlv.tag, TAG_OCTET_STRING);
        assert_eq!(tlv.content.len(), 258);
        assert_eq!(tlv.end, buf.len());
    }

    #[test]
    fn rejects_truncated_content() {
        // Claims 10 bytes of content but only 2 are present.
        let buf = [0x04, 0x0a, 0x00, 0x00];
        assert!(read_tlv(&buf, 0).is_none());
    }

    #[test]
    fn rejects_indefinite_length() {
        let buf = [0x30, 0x80, 0x00, 0x00];
        assert!(read_tlv(&buf, 0).is_none());
    }

    #[test]
    fn children_iterates_all_siblings() {
        // SEQUENCE { INTEGER 1, INTEGER 2, INTEGER 3 } — iterate the inner three.
        let inner = [0x02, 0x01, 0x01, 0x02, 0x01, 0x02, 0x02, 0x01, 0x03];
        let kinds: Vec<u8> = children(&inner).map(|t| t.content[0]).collect();
        assert_eq!(kinds, vec![1, 2, 3]);
    }
}
