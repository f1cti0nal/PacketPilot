//! LDAP (RFC 4511) request parser: binds and search requests, cleartext only.
//!
//! A sealed SASL session (the Windows default) or LDAPS is not BER on the wire, so it fails the
//! framing check and the stream is dropped — nothing is guessed. What is read from a cleartext
//! search is the base DN, the filter (rendered back to its RFC 4515 text form, bounded) and the
//! requested attribute names; result entries are never read.

use super::ber::{self, Tlv, CLASS_APPLICATION, CLASS_CONTEXT, CLASS_UNIVERSAL};

/// Longest rendered filter kept.
const MAX_FILTER: usize = 256;
/// Deepest filter nesting walked.
const MAX_DEPTH: usize = 12;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LdapOp {
    /// BindRequest; `simple` = a simple (password) bind rather than SASL.
    Bind {
        simple: bool,
    },
    Search(Search),
    /// Any other well-formed LDAP message (responses included).
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct Search {
    pub base: String,
    /// The filter in RFC 4515 text form (bounded; `…` marks a cut).
    pub filter: String,
    /// Requested attribute names (at most 32).
    pub attrs: Vec<String>,
}

/// Total length of the LDAPMessage at the front of `buf`. `Err(true)` = need more bytes,
/// `Err(false)` = not an LDAPMessage.
pub(crate) fn record_len(buf: &[u8]) -> Result<usize, bool> {
    match ber::header(buf) {
        Ok(h) if h.class == CLASS_UNIVERSAL && h.constructed && h.tag == 16 => {
            h.hdr_len.checked_add(h.body_len).ok_or(false)
        }
        Ok(_) => Err(false),
        Err(ber::HeaderErr::Short) => Err(true),
        Err(ber::HeaderErr::Invalid) => Err(false),
    }
}

/// Parse one complete LDAPMessage.
pub(crate) fn parse(msg: &[u8]) -> Option<LdapOp> {
    let m = ber::read(msg)?;
    if !m.is(CLASS_UNIVERSAL, 16) {
        return None;
    }
    let mut kids = ber::children(m.body);
    let id = kids.next()?;
    if !id.is(CLASS_UNIVERSAL, 2) {
        return None;
    }
    let op = kids.next()?;
    if op.class != CLASS_APPLICATION {
        return None;
    }
    Some(match op.tag {
        0 => {
            // BindRequest ::= [APPLICATION 0] SEQUENCE { version, name, authentication CHOICE }
            let auth = ber::children(op.body).nth(2)?;
            LdapOp::Bind {
                simple: auth.is(CLASS_CONTEXT, 0),
            }
        }
        3 => LdapOp::Search(search(&op)?),
        _ => LdapOp::Other,
    })
}

fn search(op: &Tlv) -> Option<Search> {
    // SearchRequest ::= [APPLICATION 3] SEQUENCE { baseObject, scope, derefAliases, sizeLimit,
    //                                              timeLimit, typesOnly, filter, attributes }
    let fields: Vec<Tlv> = ber::children(op.body).take(8).collect();
    let base = ber::clean_str(fields.first()?.body);
    let mut filter = String::new();
    render_filter(fields.get(6)?, &mut filter, 0);
    if filter.chars().count() > MAX_FILTER {
        filter = filter.chars().take(MAX_FILTER - 1).collect();
        filter.push('…');
    }
    let attrs = fields
        .get(7)
        .map(|a| {
            ber::children(a.body)
                .take(32)
                .map(|s| ber::clean_str(s.body))
                .collect()
        })
        .unwrap_or_default();
    Some(Search {
        base,
        filter,
        attrs,
    })
}

/// Render a Filter CHOICE into RFC 4515 text. Stops adding once the output is past the cap.
fn render_filter(f: &Tlv, out: &mut String, depth: usize) {
    if depth > MAX_DEPTH || out.len() > MAX_FILTER * 2 || f.class != CLASS_CONTEXT {
        return;
    }
    let pair = |out: &mut String, op: &str| {
        let mut k = ber::children(f.body);
        let attr = k.next().map(|t| ber::clean_str(t.body)).unwrap_or_default();
        let val = k.next().map(|t| ber::clean_str(t.body)).unwrap_or_default();
        out.push('(');
        out.push_str(&attr);
        out.push_str(op);
        out.push_str(&val);
        out.push(')');
    };
    match f.tag {
        0..=2 => {
            out.push('(');
            out.push(match f.tag {
                0 => '&',
                1 => '|',
                _ => '!',
            });
            for c in ber::children(f.body).take(64) {
                render_filter(&c, out, depth + 1);
            }
            out.push(')');
        }
        3 => pair(out, "="),
        5 => pair(out, ">="),
        6 => pair(out, "<="),
        8 => pair(out, "~="),
        4 => {
            // SubstringFilter ::= SEQUENCE { type, substrings SEQUENCE OF CHOICE { initial [0],
            //                                any [1], final [2] } }
            let mut k = ber::children(f.body);
            let attr = k.next().map(|t| ber::clean_str(t.body)).unwrap_or_default();
            out.push('(');
            out.push_str(&attr);
            out.push('=');
            let mut first = true;
            let mut last_tag = 0;
            if let Some(subs) = k.next() {
                for s in ber::children(subs.body).take(16) {
                    if !(first && s.tag == 0) {
                        out.push('*');
                    }
                    out.push_str(&ber::clean_str(s.body));
                    first = false;
                    last_tag = s.tag;
                }
            }
            if last_tag != 2 {
                out.push('*');
            }
            out.push(')');
        }
        7 => {
            out.push('(');
            out.push_str(&ber::clean_str(f.body));
            out.push_str("=*)");
        }
        9 => {
            // MatchingRuleAssertion ::= SEQUENCE { matchingRule [1], type [2], matchValue [3],
            //                                      dnAttributes [4] }
            let mut rule = String::new();
            let mut ty = String::new();
            let mut val = String::new();
            for c in ber::children(f.body) {
                match c.tag {
                    1 => rule = ber::clean_str(c.body),
                    2 => ty = ber::clean_str(c.body),
                    3 => val = ber::clean_str(c.body),
                    _ => {}
                }
            }
            out.push('(');
            out.push_str(&ty);
            if !rule.is_empty() {
                out.push(':');
                out.push_str(&rule);
            }
            out.push_str(":=");
            out.push_str(&val);
            out.push(')');
        }
        _ => {}
    }
}

/// Builders for tests.
#[cfg(test)]
pub(crate) mod build {
    use crate::identity::kerberos::build::{int, seq, tlv};

    pub fn s(v: &str) -> Vec<u8> {
        tlv(0x04, v.as_bytes())
    }
    pub fn and(parts: &[Vec<u8>]) -> Vec<u8> {
        tlv(0xa0, &parts.concat())
    }
    pub fn eq(a: &str, v: &str) -> Vec<u8> {
        tlv(0xa3, &[s(a), s(v)].concat())
    }
    pub fn present(a: &str) -> Vec<u8> {
        tlv(0x87, a.as_bytes())
    }
    pub fn ext(rule: &str, attr: &str, v: &str) -> Vec<u8> {
        tlv(
            0xa9,
            &[
                tlv(0x81, rule.as_bytes()),
                tlv(0x82, attr.as_bytes()),
                tlv(0x83, v.as_bytes()),
            ]
            .concat(),
        )
    }
    pub fn search(id: i64, base: &str, filter: Vec<u8>, attrs: &[&str]) -> Vec<u8> {
        let body = [
            s(base),
            tlv(0x0a, &[2]),
            tlv(0x0a, &[0]),
            int(0),
            int(0),
            tlv(0x01, &[0]),
            filter,
            seq(&attrs.iter().map(|a| s(a)).collect::<Vec<_>>()),
        ]
        .concat();
        seq(&[int(id), tlv(0x63, &body)])
    }
    pub fn simple_bind(id: i64, dn: &str) -> Vec<u8> {
        let body = [int(3), s(dn), tlv(0x80, b"Password1")].concat();
        seq(&[int(id), tlv(0x60, &body)])
    }
}

#[cfg(test)]
mod tests {
    use super::build::{and, eq, ext, present, search, simple_bind};
    use super::{parse, record_len, LdapOp, MAX_FILTER};

    #[test]
    fn renders_a_kerberoast_recon_filter() {
        let f = and(&[
            eq("objectCategory", "person"),
            present("servicePrincipalName"),
            tlv_not(ext("1.2.840.113556.1.4.803", "userAccountControl", "2")),
        ]);
        let m = search(
            7,
            "DC=corp,DC=local",
            f,
            &["sAMAccountName", "servicePrincipalName"],
        );
        assert_eq!(record_len(&m), Ok(m.len()));
        let LdapOp::Search(s) = parse(&m).unwrap() else {
            panic!()
        };
        assert_eq!(s.base, "DC=corp,DC=local");
        assert_eq!(
            s.filter,
            "(&(objectCategory=person)(servicePrincipalName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
        );
        assert_eq!(s.attrs, vec!["sAMAccountName", "servicePrincipalName"]);
    }

    fn tlv_not(inner: Vec<u8>) -> Vec<u8> {
        crate::identity::kerberos::build::tlv(0xa2, &inner)
    }

    #[test]
    fn binds_and_framing() {
        let b = simple_bind(1, "CN=svc,DC=corp,DC=local");
        assert_eq!(parse(&b), Some(LdapOp::Bind { simple: true }));
        assert_eq!(record_len(&b[..1]), Err(true));
        // A sealed SASL wrapper (4-byte length) is not an LDAPMessage.
        assert_eq!(record_len(&[0, 0, 4, 0, 5, 4]), Err(false));
    }

    #[test]
    fn truncation_and_deep_nesting_are_safe() {
        let m = search(1, "DC=x", and(&[eq("a", "b"), present("c")]), &["cn"]);
        for cut in 0..m.len() {
            let _ = parse(&m[..cut]);
        }
        let mut f = eq("a", "b");
        for _ in 0..40 {
            f = and(&[f]);
        }
        let m = search(1, "DC=x", f, &[]);
        let LdapOp::Search(s) = parse(&m).unwrap() else {
            panic!()
        };
        assert!(s.filter.len() <= MAX_FILTER * 4);
    }
}
