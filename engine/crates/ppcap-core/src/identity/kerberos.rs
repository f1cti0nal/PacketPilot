//! Kerberos v5 (RFC 4120) message parser: the cleartext envelope only.
//!
//! Tickets and authenticators are encrypted, but everything an identity-attack detector needs
//! sits outside them: the message type, the requested and returned encryption types, whether
//! pre-authentication data was sent, the client principal on replies, the service principal
//! (SPN) of every ticket, and KDC error codes. Nothing encrypted is retained — only the
//! integer encryption-type ids and the principal names.

use super::ber::{self, Tlv, CLASS_APPLICATION, CLASS_UNIVERSAL};

/// Encryption type ids (RFC 3961 / RFC 4757 / RFC 3962).
pub(crate) const ETYPE_DES_CBC_CRC: i32 = 1;
pub(crate) const ETYPE_DES_CBC_MD5: i32 = 3;
pub(crate) const ETYPE_AES128: i32 = 17;
pub(crate) const ETYPE_AES256: i32 = 18;
pub(crate) const ETYPE_RC4_HMAC: i32 = 23;
pub(crate) const ETYPE_RC4_HMAC_EXP: i32 = 24;

/// `PA-ENC-TIMESTAMP`: the classic password pre-authentication.
const PA_ENC_TIMESTAMP: i32 = 2;
/// PKINIT (smart card) pre-authentication request types.
const PA_PK_AS_REQ_OLD: i32 = 14;
const PA_PK_AS_REQ: i32 = 16;
/// FAST armor and encrypted challenge (RFC 6113) — also proof of a pre-authenticated request.
const PA_FX_FAST: i32 = 136;
const PA_ENCRYPTED_CHALLENGE: i32 = 138;

/// KDC error codes the detectors read.
pub(crate) const KDC_ERR_C_PRINCIPAL_UNKNOWN: i32 = 6;

/// Short human name for an encryption type.
pub(crate) fn etype_name(e: i32) -> String {
    match e {
        ETYPE_DES_CBC_CRC => "DES-CBC-CRC".to_string(),
        ETYPE_DES_CBC_MD5 => "DES-CBC-MD5".to_string(),
        ETYPE_AES128 => "AES128".to_string(),
        ETYPE_AES256 => "AES256".to_string(),
        ETYPE_RC4_HMAC => "RC4-HMAC".to_string(),
        ETYPE_RC4_HMAC_EXP => "RC4-HMAC-EXP".to_string(),
        other => format!("etype {other}"),
    }
}

pub(crate) fn is_des(e: i32) -> bool {
    matches!(e, ETYPE_DES_CBC_CRC | 2 | ETYPE_DES_CBC_MD5)
}

pub(crate) fn is_rc4(e: i32) -> bool {
    matches!(e, ETYPE_RC4_HMAC | ETYPE_RC4_HMAC_EXP)
}

pub(crate) fn is_aes(e: i32) -> bool {
    matches!(e, ETYPE_AES128 | ETYPE_AES256 | 19 | 20)
}

/// AS-REQ / TGS-REQ.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct KdcReq {
    /// `padata-type` of every PA-DATA entry.
    pub pa_types: Vec<i32>,
    /// Client principal (AS-REQ only; a TGS-REQ carries the client inside the encrypted TGT).
    pub cname: Option<String>,
    pub realm: Option<String>,
    /// Requested service principal.
    pub sname: Option<String>,
    /// Encryption types the client will accept, in preference order.
    pub etypes: Vec<i32>,
}

impl KdcReq {
    /// The request proves knowledge of the client key (password timestamp, PKINIT, FAST).
    pub(crate) fn preauthenticated(&self) -> bool {
        self.pa_types.iter().any(|t| {
            matches!(
                *t,
                PA_ENC_TIMESTAMP
                    | PA_PK_AS_REQ_OLD
                    | PA_PK_AS_REQ
                    | PA_FX_FAST
                    | PA_ENCRYPTED_CHALLENGE
            )
        })
    }

    /// Every acceptable etype is RC4 or DES — the downgrade a roasting tool asks for so the
    /// ticket it gets back is fast to crack.
    pub(crate) fn weak_etypes_only(&self) -> bool {
        !self.etypes.is_empty() && self.etypes.iter().all(|e| is_rc4(*e) || is_des(*e))
    }

    pub(crate) fn offers_aes(&self) -> bool {
        self.etypes.iter().any(|e| is_aes(*e))
    }
}

/// AS-REP / TGS-REP.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct KdcRep {
    pub crealm: Option<String>,
    pub cname: Option<String>,
    /// Service principal the ticket is for.
    pub ticket_sname: Option<String>,
    /// Ticket encryption type (the *service's* key — the roastable part of a TGS-REP).
    pub ticket_etype: Option<i32>,
    /// Reply `enc-part` encryption type (the *client's* key on an AS-REP — the roastable part
    /// of an AS-REP).
    pub enc_etype: Option<i32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct KrbError {
    pub code: i32,
    pub cname: Option<String>,
    pub sname: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum KrbMsg {
    AsReq(KdcReq),
    AsRep(KdcRep),
    TgsReq(KdcReq),
    TgsRep(KdcRep),
    Error(KrbError),
}

/// Parse one complete Kerberos message (no TCP length prefix). `None` for anything else.
pub(crate) fn parse(msg: &[u8]) -> Option<KrbMsg> {
    let app = ber::read(msg)?;
    if app.class != CLASS_APPLICATION || !app.constructed {
        return None;
    }
    let seq = app.inner()?;
    if !seq.is(CLASS_UNIVERSAL, 16) {
        return None;
    }
    match app.tag {
        10 => Some(KrbMsg::AsReq(kdc_req(&seq)?)),
        12 => Some(KrbMsg::TgsReq(kdc_req(&seq)?)),
        11 => Some(KrbMsg::AsRep(kdc_rep(&seq)?)),
        13 => Some(KrbMsg::TgsRep(kdc_rep(&seq)?)),
        30 => Some(KrbMsg::Error(krb_error(&seq)?)),
        _ => None,
    }
}

/// Length of the TCP record at the front of `buf` (RFC 4120 §7.2.2: a 4-byte big-endian length,
/// high bit reserved). `Err(true)` = need more bytes, `Err(false)` = not a Kerberos record.
pub(crate) fn tcp_record_len(buf: &[u8]) -> Result<usize, bool> {
    if buf.len() < 4 {
        return Err(true);
    }
    let n = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
    if n & 0x8000_0000 != 0 || n < 2 {
        return Err(false);
    }
    // The record must open with an APPLICATION-class constructed tag of a known message.
    if let Some(&b) = buf.get(4) {
        if !matches!(b, 0x6a | 0x6b | 0x6c | 0x6d | 0x7e) {
            return Err(false);
        }
    }
    Ok(n as usize)
}

/// `[n] EXPLICIT INTEGER` child as i32.
fn ctx_int(seq: &Tlv, n: u32) -> Option<i32> {
    seq.ctx(n)?
        .inner()?
        .int()
        .and_then(|v| i32::try_from(v).ok())
}

/// `[n] EXPLICIT KerberosString` child.
fn ctx_str(seq: &Tlv, n: u32) -> Option<String> {
    Some(ber::clean_str(seq.ctx(n)?.inner()?.body))
}

/// `PrincipalName ::= SEQUENCE { name-type [0] Int32, name-string [1] SEQUENCE OF KerberosString }`
/// rendered `a/b/c`.
fn principal(t: &Tlv) -> Option<String> {
    let seq = t.inner()?;
    let names = seq.ctx(1)?.inner()?;
    let parts: Vec<String> = ber::children(names.body)
        .map(|s| ber::clean_str(s.body))
        .collect();
    if parts.is_empty() {
        return None;
    }
    // Character-bounded: a byte truncation could split a multibyte character and panic.
    Some(parts.join("/").chars().take(ber::MAX_STR).collect())
}

/// `EncryptedData ::= SEQUENCE { etype [0] Int32, kvno [1] UInt32 OPTIONAL, cipher [2] OCTET STRING }`.
fn enc_etype(t: &Tlv) -> Option<i32> {
    let seq = t.inner()?;
    ctx_int(&seq, 0)
}

fn kdc_req(seq: &Tlv) -> Option<KdcReq> {
    let mut req = KdcReq::default();
    if let Some(pa) = seq.ctx(3).and_then(|t| t.inner()) {
        for entry in ber::children(pa.body).take(32) {
            if let Some(t) = ctx_int(&entry, 1) {
                req.pa_types.push(t);
            }
        }
    }
    let body = seq.ctx(4)?.inner()?;
    req.cname = body.ctx(1).and_then(|t| principal(&t));
    req.realm = ctx_str(&body, 2);
    req.sname = body.ctx(3).and_then(|t| principal(&t));
    if let Some(list) = body.ctx(8).and_then(|t| t.inner()) {
        for e in ber::children(list.body).take(32) {
            if let Some(v) = e.int().and_then(|v| i32::try_from(v).ok()) {
                req.etypes.push(v);
            }
        }
    }
    Some(req)
}

fn kdc_rep(seq: &Tlv) -> Option<KdcRep> {
    let mut rep = KdcRep {
        crealm: ctx_str(seq, 3),
        cname: seq.ctx(4).and_then(|t| principal(&t)),
        ..KdcRep::default()
    };
    // Ticket ::= [APPLICATION 1] SEQUENCE { tkt-vno [0], realm [1], sname [2], enc-part [3] }
    if let Some(tkt) = seq.ctx(5).and_then(|t| t.inner()) {
        if tkt.is(CLASS_APPLICATION, 1) {
            if let Some(ts) = tkt.inner() {
                rep.ticket_sname = ts.ctx(2).and_then(|t| principal(&t));
                rep.ticket_etype = ts.ctx(3).and_then(|t| enc_etype(&t));
            }
        }
    }
    rep.enc_etype = seq.ctx(6).and_then(|t| enc_etype(&t));
    Some(rep)
}

fn krb_error(seq: &Tlv) -> Option<KrbError> {
    Some(KrbError {
        code: ctx_int(seq, 6)?,
        cname: seq.ctx(8).and_then(|t| principal(&t)),
        sname: seq.ctx(10).and_then(|t| principal(&t)),
    })
}

/// DER builders for tests (shared with the identity detector tests).
#[cfg(test)]
pub(crate) mod build {
    pub fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut v = vec![tag];
        let n = body.len();
        if n < 0x80 {
            v.push(n as u8);
        } else if n < 0x100 {
            v.extend_from_slice(&[0x81, n as u8]);
        } else {
            v.extend_from_slice(&[0x82, (n >> 8) as u8, n as u8]);
        }
        v.extend_from_slice(body);
        v
    }
    pub fn seq(parts: &[Vec<u8>]) -> Vec<u8> {
        tlv(0x30, &parts.concat())
    }
    pub fn ctx(n: u8, inner: Vec<u8>) -> Vec<u8> {
        tlv(0xa0 | n, &inner)
    }
    pub fn int(v: i64) -> Vec<u8> {
        let bytes = v.to_be_bytes();
        let mut start = 0;
        while start < 7
            && ((bytes[start] == 0 && bytes[start + 1] & 0x80 == 0)
                || (bytes[start] == 0xff && bytes[start + 1] & 0x80 != 0))
        {
            start += 1;
        }
        tlv(0x02, &bytes[start..])
    }
    pub fn gstr(s: &str) -> Vec<u8> {
        tlv(0x1b, s.as_bytes())
    }
    pub fn principal(name_type: i64, parts: &[&str]) -> Vec<u8> {
        seq(&[
            ctx(0, int(name_type)),
            ctx(1, seq(&parts.iter().map(|p| gstr(p)).collect::<Vec<_>>())),
        ])
    }
    pub fn enc_data(etype: i64) -> Vec<u8> {
        seq(&[ctx(0, int(etype)), ctx(2, tlv(0x04, &[0xAB; 32]))])
    }

    /// AS-REQ (app 10) or TGS-REQ (app 12).
    pub fn kdc_req(
        app: u8,
        pa_types: &[i64],
        cname: Option<&str>,
        sname: &str,
        etypes: &[i64],
    ) -> Vec<u8> {
        let mut body = vec![ctx(0, tlv(0x03, &[0, 0x40, 0x81, 0, 0x10]))];
        if let Some(c) = cname {
            body.push(ctx(1, principal(1, &[c])));
        }
        body.push(ctx(2, gstr("CORP.LOCAL")));
        let sparts: Vec<&str> = sname.split('/').collect();
        body.push(ctx(3, principal(2, &sparts)));
        body.push(ctx(5, tlv(0x18, b"20370913024805Z")));
        body.push(ctx(7, int(12345)));
        body.push(ctx(
            8,
            seq(&etypes.iter().map(|e| int(*e)).collect::<Vec<_>>()),
        ));
        let mut fields = vec![ctx(1, int(5)), ctx(2, int(app as i64))];
        if !pa_types.is_empty() {
            let pas: Vec<Vec<u8>> = pa_types
                .iter()
                .map(|t| seq(&[ctx(1, int(*t)), ctx(2, tlv(0x04, &[0u8; 8]))]))
                .collect();
            fields.push(ctx(3, seq(&pas)));
        }
        fields.push(ctx(4, seq(&body)));
        tlv(0x60 | app, &seq(&fields))
    }

    /// AS-REP (app 11) or TGS-REP (app 13).
    pub fn kdc_rep(app: u8, cname: &str, sname: &str, ticket_etype: i64, enc: i64) -> Vec<u8> {
        let sparts: Vec<&str> = sname.split('/').collect();
        let ticket = tlv(
            0x61,
            &seq(&[
                ctx(0, int(5)),
                ctx(1, gstr("CORP.LOCAL")),
                ctx(2, principal(2, &sparts)),
                ctx(3, enc_data(ticket_etype)),
            ]),
        );
        let fields = vec![
            ctx(0, int(5)),
            ctx(1, int(app as i64)),
            ctx(3, gstr("CORP.LOCAL")),
            ctx(4, principal(1, &[cname])),
            ctx(5, ticket),
            ctx(6, enc_data(enc)),
        ];
        tlv(0x60 | app, &seq(&fields))
    }

    pub fn krb_error(code: i64, cname: Option<&str>) -> Vec<u8> {
        let mut fields = vec![
            ctx(0, int(5)),
            ctx(1, int(30)),
            ctx(4, tlv(0x18, b"20261029034500Z")),
            ctx(5, int(0)),
            ctx(6, int(code)),
        ];
        if let Some(c) = cname {
            fields.push(ctx(8, principal(1, &[c])));
        }
        fields.push(ctx(9, gstr("CORP.LOCAL")));
        fields.push(ctx(10, principal(2, &["krbtgt", "CORP.LOCAL"])));
        tlv(0x7e, &seq(&fields))
    }

    /// Prefix a message with the 4-byte TCP record length.
    pub fn tcp(msg: &[u8]) -> Vec<u8> {
        let mut v = (msg.len() as u32).to_be_bytes().to_vec();
        v.extend_from_slice(msg);
        v
    }
}

#[cfg(test)]
mod tests {
    use super::build::{kdc_rep, kdc_req, krb_error, tcp};
    use super::{parse, tcp_record_len, KrbMsg};

    #[test]
    fn parses_an_as_req_without_preauth() {
        let m = kdc_req(10, &[128], Some("svc_backup"), "krbtgt/CORP.LOCAL", &[23]);
        match parse(&m).unwrap() {
            KrbMsg::AsReq(r) => {
                assert_eq!(r.cname.as_deref(), Some("svc_backup"));
                assert_eq!(r.sname.as_deref(), Some("krbtgt/CORP.LOCAL"));
                assert_eq!(r.realm.as_deref(), Some("CORP.LOCAL"));
                assert!(!r.preauthenticated()); // 128 = PA-PAC-REQUEST, not pre-auth
                assert!(r.weak_etypes_only());
            }
            other => panic!("{other:?}"),
        }
        let pre = kdc_req(
            10,
            &[2, 128],
            Some("alice"),
            "krbtgt/CORP.LOCAL",
            &[18, 17, 23],
        );
        let KrbMsg::AsReq(r) = parse(&pre).unwrap() else {
            panic!()
        };
        assert!(r.preauthenticated() && r.offers_aes() && !r.weak_etypes_only());
    }

    #[test]
    fn parses_a_tgs_req_and_rep() {
        let m = kdc_req(12, &[1], None, "MSSQLSvc/sql01.corp.local:1433", &[23]);
        let KrbMsg::TgsReq(r) = parse(&m).unwrap() else {
            panic!()
        };
        assert_eq!(r.sname.as_deref(), Some("MSSQLSvc/sql01.corp.local:1433"));
        assert_eq!(r.cname, None);
        assert_eq!(r.etypes, vec![23]);

        let rep = kdc_rep(13, "alice", "MSSQLSvc/sql01.corp.local:1433", 23, 18);
        let KrbMsg::TgsRep(r) = parse(&rep).unwrap() else {
            panic!()
        };
        assert_eq!(r.cname.as_deref(), Some("alice"));
        assert_eq!(
            r.ticket_sname.as_deref(),
            Some("MSSQLSvc/sql01.corp.local:1433")
        );
        assert_eq!(r.ticket_etype, Some(23));
        assert_eq!(r.enc_etype, Some(18));
    }

    #[test]
    fn multibyte_principal_past_the_cap_is_truncated_on_a_char_boundary() {
        let long = format!("{}é", "a".repeat(255));
        let m = kdc_rep(13, &long, "HTTP/web01", 18, 18);
        let KrbMsg::TgsRep(r) = parse(&m).unwrap() else {
            panic!()
        };
        let c = r.cname.unwrap();
        assert_eq!(c.chars().count(), 256);
        assert!(c.ends_with('é'));
        // Several components joined past the cap.
        let m = kdc_rep(
            13,
            "alice",
            &format!("{}/{}é{}", "x".repeat(200), "y".repeat(54), "z".repeat(40)),
            18,
            18,
        );
        let KrbMsg::TgsRep(r) = parse(&m).unwrap() else {
            panic!()
        };
        assert_eq!(r.ticket_sname.unwrap().chars().count(), 256);
    }

    #[test]
    fn parses_errors_and_tcp_framing() {
        let e = krb_error(25, Some("bob"));
        let KrbMsg::Error(err) = parse(&e).unwrap() else {
            panic!()
        };
        assert_eq!(err.code, 25); // KDC_ERR_PREAUTH_REQUIRED
        assert_eq!(err.cname.as_deref(), Some("bob"));
        let framed = tcp(&e);
        assert_eq!(tcp_record_len(&framed), Ok(e.len()));
        assert_eq!(tcp_record_len(&framed[..3]), Err(true));
        assert_eq!(tcp_record_len(b"GET / HTTP/1.1"), Err(false));
    }

    #[test]
    fn truncated_and_garbage_input_is_rejected_without_panicking() {
        let m = kdc_rep(13, "alice", "HTTP/web01", 23, 18);
        for cut in 0..m.len() {
            let _ = parse(&m[..cut]);
        }
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        for len in 0..300 {
            let mut buf: Vec<u8> = (0..len)
                .map(|_| {
                    x ^= x << 13;
                    x ^= x >> 7;
                    x ^= x << 17;
                    x as u8
                })
                .collect();
            if let Some(b) = buf.first_mut() {
                *b = 0x6d; // force an APPLICATION 13 opener to reach the deeper paths
            }
            let _ = parse(&buf);
        }
    }
}
