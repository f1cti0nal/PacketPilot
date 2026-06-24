//! Extract the few X.509 leaf-certificate fields the cert-health checks need — validity dates,
//! the issuer/subject Distinguished Names (for self-signed detection), the subject CN, and the
//! `subjectAltName` dNSNames — by walking the DER with [`super::der`]. No full X.509 validation.

use super::der::{
    children, read_tlv, TAG_BOOLEAN, TAG_CTX_EXTENSIONS, TAG_CTX_VERSION, TAG_GENERALIZED_TIME,
    TAG_GENERALNAME_DNS, TAG_OCTET_STRING, TAG_OID, TAG_SEQUENCE, TAG_UTC_TIME,
};

/// `id-at-commonName` (2.5.4.3) DER-encoded OID bytes.
const OID_COMMON_NAME: &[u8] = &[0x55, 0x04, 0x03];
/// `id-ce-subjectAltName` (2.5.29.17) DER-encoded OID bytes.
const OID_SUBJECT_ALT_NAME: &[u8] = &[0x55, 0x1D, 0x11];

/// The leaf-certificate fields relevant to cert health. Dates are normalized to a comparable
/// `YYYYMMDDhhmmss` integer (UTC); `0` / `u64::MAX` are "unknown" sentinels that disable the
/// corresponding expiry check rather than firing a false positive.
pub(crate) struct CertInfo {
    pub not_before: u64,
    pub not_after: u64,
    /// Raw RDNSequence bytes of the issuer / subject names — compared for equality to flag a
    /// self-signed certificate.
    pub issuer_raw: Vec<u8>,
    pub subject_raw: Vec<u8>,
    pub cn: Option<String>,
    pub sans: Vec<String>,
}

/// Parse a single DER-encoded X.509 certificate's health-relevant fields. Returns `None` if the
/// outer structure is too malformed to locate the validity / names (never panics).
pub(crate) fn parse_leaf(der: &[u8]) -> Option<CertInfo> {
    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
    let cert = read_tlv(der, 0)?;
    if cert.tag != TAG_SEQUENCE {
        return None;
    }
    let tbs = read_tlv(cert.content, 0)?;
    if tbs.tag != TAG_SEQUENCE {
        return None;
    }

    // tbsCertificate ::= SEQUENCE {
    //   [0] version DEFAULT v1,  serialNumber,  signature AlgId,
    //   issuer Name,  validity,  subject Name,  subjectPublicKeyInfo,
    //   ... [1] issuerUID, [2] subjectUID, [3] extensions }
    let mut it = children(tbs.content);
    let mut field = it.next()?;
    if field.tag == TAG_CTX_VERSION {
        field = it.next()?; // skip the explicit version; `field` becomes serialNumber
    }
    let _serial = field;
    let _sig_alg = it.next()?;
    let issuer = it.next()?;
    let validity = it.next()?;
    let subject = it.next()?;
    let _spki = it.next()?;

    // The optional UIDs and extensions follow; we only want the SAN extension ([3]).
    let mut extensions: Option<&[u8]> = None;
    for tlv in it {
        if tlv.tag == TAG_CTX_EXTENSIONS {
            extensions = Some(tlv.content);
        }
    }

    // validity ::= SEQUENCE { notBefore Time, notAfter Time }
    let mut vit = children(validity.content);
    let not_before = vit.next().and_then(|t| parse_time(&t)).unwrap_or(0);
    let not_after = vit.next().and_then(|t| parse_time(&t)).unwrap_or(u64::MAX);

    Some(CertInfo {
        not_before,
        not_after,
        issuer_raw: issuer.content.to_vec(),
        subject_raw: subject.content.to_vec(),
        cn: extract_cn(subject.content),
        sans: extensions.map(extract_sans).unwrap_or_default(),
    })
}

/// Parse a DER `Time` (UTCTime `YYMMDDhhmmssZ` or GeneralizedTime `YYYYMMDDhhmmssZ`) into a
/// comparable `YYYYMMDDhhmmss` integer. Only the UTC (`Z`) seconds form is handled — the only
/// form RFC 5280 permits for certificate validity. Returns `None` otherwise.
fn parse_time(tlv: &super::der::Tlv) -> Option<u64> {
    let s = tlv.content;
    let (year, rest): (u64, &[u8]) = match tlv.tag {
        TAG_UTC_TIME => {
            // YYMMDDhhmmssZ -> 13 bytes
            if s.len() != 13 || s[12] != b'Z' {
                return None;
            }
            let yy = two_digits(s, 0)?;
            // RFC 5280 sliding window: 00..=49 -> 20YY, 50..=99 -> 19YY.
            let year = if yy < 50 { 2000 + yy } else { 1900 + yy };
            (year, &s[2..12])
        }
        TAG_GENERALIZED_TIME => {
            // YYYYMMDDhhmmssZ -> 15 bytes
            if s.len() != 15 || s[14] != b'Z' {
                return None;
            }
            let year = two_digits(s, 0)? * 100 + two_digits(s, 2)?;
            (year, &s[4..14])
        }
        _ => return None,
    };
    let mo = two_digits(rest, 0)?;
    let da = two_digits(rest, 2)?;
    let hh = two_digits(rest, 4)?;
    let mi = two_digits(rest, 6)?;
    let ss = two_digits(rest, 8)?;
    Some(year * 10_000_000_000 + mo * 100_000_000 + da * 1_000_000 + hh * 10_000 + mi * 100 + ss)
}

/// Two ASCII digits at `off` as a `u64`; `None` if either byte is not a digit or is out of range.
fn two_digits(s: &[u8], off: usize) -> Option<u64> {
    let hi = s.get(off)?;
    let lo = s.get(off + 1)?;
    if !hi.is_ascii_digit() || !lo.is_ascii_digit() {
        return None;
    }
    Some((hi - b'0') as u64 * 10 + (lo - b'0') as u64)
}

/// Find the first commonName (CN) attribute value in an RDNSequence's content.
fn extract_cn(name: &[u8]) -> Option<String> {
    for rdn in children(name) {
        // Each RDN is a SET of AttributeTypeAndValue SEQUENCEs.
        for atv in children(rdn.content) {
            let mut it = children(atv.content);
            let oid = match it.next() {
                Some(o) => o,
                None => continue,
            };
            if oid.tag == TAG_OID && oid.content == OID_COMMON_NAME {
                if let Some(val) = it.next() {
                    if let Some(s) = der_string(&val) {
                        return Some(s);
                    }
                }
            }
        }
    }
    None
}

/// Collect every `dNSName` in the SAN extension. `ext_explicit` is the content of the `[3]` tag,
/// which wraps the `Extensions` SEQUENCE.
fn extract_sans(ext_explicit: &[u8]) -> Vec<String> {
    let seq = match read_tlv(ext_explicit, 0) {
        Some(t) if t.tag == TAG_SEQUENCE => t,
        _ => return Vec::new(),
    };
    for ext in children(seq.content) {
        // Extension ::= SEQUENCE { extnID OID, critical BOOLEAN DEFAULT FALSE, extnValue OCTET STRING }
        let mut it = children(ext.content);
        let oid = match it.next() {
            Some(o) => o,
            None => continue,
        };
        if !(oid.tag == TAG_OID && oid.content == OID_SUBJECT_ALT_NAME) {
            continue;
        }
        let mut val = it.next();
        if let Some(v) = &val {
            if v.tag == TAG_BOOLEAN {
                val = it.next(); // skip the optional `critical` flag
            }
        }
        let octet = match val {
            Some(v) if v.tag == TAG_OCTET_STRING => v,
            _ => continue,
        };
        // The OCTET STRING wraps the GeneralNames SEQUENCE.
        let names = match read_tlv(octet.content, 0) {
            Some(t) if t.tag == TAG_SEQUENCE => t,
            _ => continue,
        };
        return children(names.content)
            .filter(|gn| gn.tag == TAG_GENERALNAME_DNS)
            .map(|gn| String::from_utf8_lossy(gn.content).into_owned())
            .collect();
    }
    Vec::new()
}

/// Decode a DER string value (PrintableString / UTF8String / IA5String / TeletexString as UTF-8;
/// BMPString as UTF-16BE). Good enough for a CN, which is virtually always ASCII.
fn der_string(tlv: &super::der::Tlv) -> Option<String> {
    match tlv.tag {
        // PrintableString, UTF8String, IA5String, TeletexString, VisibleString.
        0x13 | 0x0C | 0x16 | 0x14 | 0x1A => Some(String::from_utf8_lossy(tlv.content).into_owned()),
        // BMPString: UTF-16BE.
        0x1E => {
            let units: Vec<u16> = tlv
                .content
                .chunks_exact(2)
                .map(|c| u16::from_be_bytes([c[0], c[1]]))
                .collect();
            Some(String::from_utf16_lossy(&units))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::testcert;

    #[test]
    fn parses_validity_and_names() {
        let der = testcert::build(testcert::Spec {
            subject_cn: "example.com",
            issuer_cn: "Example CA",
            not_before: "200101000000Z",
            not_after: "300101000000Z",
            sans: &["example.com", "www.example.com"],
        });
        let cert = parse_leaf(&der).expect("parse");
        assert_eq!(cert.not_before, 20_200_101_000_000);
        assert_eq!(cert.not_after, 20_300_101_000_000);
        assert_eq!(cert.cn.as_deref(), Some("example.com"));
        assert_eq!(cert.sans, vec!["example.com", "www.example.com"]);
        assert_ne!(cert.issuer_raw, cert.subject_raw);
    }

    #[test]
    fn self_signed_has_equal_issuer_and_subject() {
        let der = testcert::build(testcert::Spec {
            subject_cn: "selfsigned.local",
            issuer_cn: "selfsigned.local",
            not_before: "200101000000Z",
            not_after: "300101000000Z",
            sans: &[],
        });
        let cert = parse_leaf(&der).expect("parse");
        assert_eq!(cert.issuer_raw, cert.subject_raw);
    }

    #[test]
    fn generalized_time_parses() {
        // GeneralizedTime tag (0x18), 15 bytes "YYYYMMDDhhmmssZ".
        let tlv = super::super::der::read_tlv(
            &[
                0x18, 0x0F, b'2', b'0', b'2', b'5', b'0', b'6', b'2', b'3', b'1', b'2', b'0', b'0',
                b'0', b'0', b'Z',
            ],
            0,
        )
        .unwrap();
        assert_eq!(parse_time(&tlv), Some(20_250_623_120_000));
    }

    #[test]
    fn malformed_der_is_none() {
        assert!(parse_leaf(&[0x30, 0x05, 0x00]).is_none());
        assert!(parse_leaf(&[]).is_none());
    }
}
