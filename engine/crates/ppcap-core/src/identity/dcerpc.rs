//! DCE-RPC (connection-oriented, MS-RPCE) PDU header parser.
//!
//! Only the cleartext PDU headers are read: the interface UUIDs a client binds to and the
//! operation number of each request. Both stay in the clear even when the call is sealed with
//! packet privacy, which is why DCSync (DRSUAPI `DRSGetNCChanges`) is visible on the wire
//! although its stub is encrypted. Stub data is never read or retained.

/// PDU types used here.
pub(crate) const PTYPE_REQUEST: u8 = 0;
pub(crate) const PTYPE_BIND: u8 = 11;
pub(crate) const PTYPE_ALTER_CONTEXT: u8 = 14;

const HEADER_LEN: usize = 16;
/// Request PDUs carry an object UUID after the header when this flag is set.
const PFC_OBJECT_UUID: u8 = 0x80;

/// Interfaces the identity detectors care about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum Iface {
    /// MS-DRSR directory replication (DCSync).
    Drsuapi,
    /// MS-SAMR security account manager (user/group enumeration).
    Samr,
    /// MS-LSAD/LSAT local security authority (SID lookups).
    Lsarpc,
    /// MS-SCMR service control manager (remote service creation).
    Svcctl,
    /// MS-TSCH task scheduler (`atsvc` and ITaskSchedulerService).
    TaskScheduler,
    /// MS-SRVS server service (session / share enumeration).
    Srvsvc,
    /// MS-WKST workstation service (logged-on user enumeration).
    Wkssvc,
}

impl Iface {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Iface::Drsuapi => "DRSUAPI",
            Iface::Samr => "SAMR",
            Iface::Lsarpc => "LSARPC",
            Iface::Svcctl => "SVCCTL",
            Iface::TaskScheduler => "Task Scheduler",
            Iface::Srvsvc => "SRVSVC",
            Iface::Wkssvc => "WKSSVC",
        }
    }

    /// Human name of an operation number on this interface, for the ones the detectors use.
    pub(crate) fn op_name(self, opnum: u16) -> Option<&'static str> {
        Some(match (self, opnum) {
            (Iface::Drsuapi, 0) => "DRSBind",
            (Iface::Drsuapi, 3) => "DRSGetNCChanges",
            (Iface::Drsuapi, 12) => "DRSCrackNames",
            (Iface::Samr, 6) => "SamrEnumerateDomainsInSamServer",
            (Iface::Samr, 11) => "SamrEnumerateGroupsInDomain",
            (Iface::Samr, 13) => "SamrEnumerateUsersInDomain",
            (Iface::Samr, 15) => "SamrEnumerateAliasesInDomain",
            (Iface::Samr, 25) => "SamrGetMembersInGroup",
            (Iface::Samr, 33) => "SamrGetMembersInAlias",
            (Iface::Samr, 40) => "SamrQueryDisplayInformation",
            (Iface::Samr, 48) => "SamrQueryDisplayInformation2",
            (Iface::Samr, 51) => "SamrQueryDisplayInformation3",
            (Iface::Lsarpc, 15) => "LsarLookupSids",
            (Iface::Lsarpc, 57) => "LsarLookupSids2",
            (Iface::Lsarpc, 76) => "LsarLookupSids3",
            (Iface::Svcctl, 12) => "RCreateServiceW",
            (Iface::Svcctl, 19) => "RStartServiceW",
            (Iface::Svcctl, 24) => "RCreateServiceA",
            (Iface::TaskScheduler, 0) => "NetrJobAdd",
            (Iface::TaskScheduler, 1) => "SchRpcRegisterTask",
            (Iface::Srvsvc, 12) => "NetrSessionEnum",
            (Iface::Srvsvc, 15) => "NetrShareEnum",
            (Iface::Wkssvc, 2) => "NetrWkstaUserEnum",
            _ => return None,
        })
    }

    /// Operations that enumerate directory principals (the recon signal).
    pub(crate) fn is_enumeration(self, opnum: u16) -> bool {
        matches!(
            (self, opnum),
            (Iface::Samr, 6 | 11 | 13 | 15 | 25 | 33 | 40 | 48 | 51)
                | (Iface::Lsarpc, 15 | 57 | 76)
                | (Iface::Srvsvc, 12)
                | (Iface::Wkssvc, 2)
        )
    }
}

/// `(data1, data2, data3, data4)` of a UUID in its canonical text order.
type Uuid = (u32, u16, u16, [u8; 8]);

#[rustfmt::skip]
const KNOWN: &[(Uuid, Iface)] = &[
    ((0xe3514235, 0x4b06, 0x11d1, [0xab, 0x04, 0x00, 0xc0, 0x4f, 0xc2, 0xdc, 0xd2]), Iface::Drsuapi),
    ((0x12345778, 0x1234, 0xabcd, [0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xac]), Iface::Samr),
    ((0x12345778, 0x1234, 0xabcd, [0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab]), Iface::Lsarpc),
    ((0x367abb81, 0x9844, 0x35f1, [0xad, 0x32, 0x98, 0xf0, 0x38, 0x00, 0x10, 0x03]), Iface::Svcctl),
    ((0x1ff70682, 0x0a51, 0x30e8, [0x07, 0x6d, 0x74, 0x0b, 0xe8, 0xce, 0xe9, 0x8b]), Iface::TaskScheduler),
    ((0x86d35949, 0x83c9, 0x4044, [0xb4, 0x24, 0xdb, 0x36, 0x32, 0x31, 0xfd, 0x0c]), Iface::TaskScheduler),
    ((0x4b324fc8, 0x1670, 0x01d3, [0x12, 0x78, 0x5a, 0x47, 0xbf, 0x6e, 0xe1, 0x88]), Iface::Srvsvc),
    ((0x6bffd098, 0xa112, 0x3610, [0x98, 0x33, 0x46, 0xc3, 0xf8, 0x7e, 0x34, 0x5a]), Iface::Wkssvc),
];

/// The fixed 16-byte common header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PduHeader {
    pub ptype: u8,
    pub flags: u8,
    pub little_endian: bool,
    pub frag_len: u16,
}

/// Read the common header. `Err(true)` = need more bytes, `Err(false)` = not DCE-RPC.
pub(crate) fn header(buf: &[u8]) -> Result<PduHeader, bool> {
    if buf.len() < HEADER_LEN {
        // Reject early on the bytes we do have, so a non-RPC stream is dropped promptly.
        if (!buf.is_empty() && buf[0] != 5) || (buf.len() > 1 && buf[1] > 1) {
            return Err(false);
        }
        return Err(true);
    }
    if buf[0] != 5 || buf[1] > 1 || buf[2] > 20 {
        return Err(false);
    }
    // drep[0] high nibble: 1 = little-endian, 0 = big-endian; anything else is not NDR.
    let little_endian = match buf[4] >> 4 {
        1 => true,
        0 => false,
        _ => return Err(false),
    };
    let frag_len = if little_endian {
        u16::from_le_bytes([buf[8], buf[9]])
    } else {
        u16::from_be_bytes([buf[8], buf[9]])
    };
    if usize::from(frag_len) < HEADER_LEN {
        return Err(false);
    }
    Ok(PduHeader {
        ptype: buf[2],
        flags: buf[3],
        little_endian,
        frag_len,
    })
}

/// Cheap shape test: does this payload open with a bind / alter-context PDU? Used to pick up
/// RPC on dynamic ports (the endpoint mapper hands DRSUAPI a high port).
///
/// A bind can span TCP segments, so a first segment shorter than the 16-byte header is accepted
/// on the bytes it has (version 5.0/5.1, a bind / alter-context type, an NDR data representation);
/// the stream framing validates the completed PDU before any context is read.
pub(crate) fn looks_like_bind(payload: &[u8]) -> bool {
    if payload.len() < HEADER_LEN {
        return payload.len() >= 3
            && payload[0] == 5
            && payload[1] <= 1
            && matches!(payload[2], PTYPE_BIND | PTYPE_ALTER_CONTEXT)
            && payload.get(4).is_none_or(|d| d >> 4 <= 1);
    }
    matches!(header(payload), Ok(h) if matches!(h.ptype, PTYPE_BIND | PTYPE_ALTER_CONTEXT)
        && usize::from(h.frag_len) >= 44)
}

fn u16_at(b: &[u8], off: usize, le: bool) -> Option<u16> {
    let s = b.get(off..off + 2)?;
    Some(if le {
        u16::from_le_bytes([s[0], s[1]])
    } else {
        u16::from_be_bytes([s[0], s[1]])
    })
}

fn u32_at(b: &[u8], off: usize, le: bool) -> Option<u32> {
    let s = b.get(off..off + 4)?;
    let a = [s[0], s[1], s[2], s[3]];
    Some(if le {
        u32::from_le_bytes(a)
    } else {
        u32::from_be_bytes(a)
    })
}

fn uuid_at(b: &[u8], off: usize, le: bool) -> Option<Uuid> {
    let d4 = b.get(off + 8..off + 16)?;
    let mut data4 = [0u8; 8];
    data4.copy_from_slice(d4);
    Some((
        u32_at(b, off, le)?,
        u16_at(b, off + 4, le)?,
        u16_at(b, off + 6, le)?,
        data4,
    ))
}

/// The presentation contexts a bind / alter-context PDU proposes: `(context id, interface)` for
/// every known interface (unknown interfaces are skipped). `pdu` is the whole fragment.
pub(crate) fn bind_contexts(pdu: &[u8], h: &PduHeader) -> Vec<(u16, Iface)> {
    let le = h.little_endian;
    let mut out = Vec::new();
    // header(16) + max_xmit(2) + max_recv(2) + assoc_group(4) = 24; then n_context_elem(1) + pad(3).
    let n = match pdu.get(24) {
        Some(&n) => usize::from(n),
        None => return out,
    };
    let mut off = 28;
    for _ in 0..n.min(16) {
        let (Some(ctx_id), Some(&n_syn)) = (u16_at(pdu, off, le), pdu.get(off + 2)) else {
            break;
        };
        let Some(uuid) = uuid_at(pdu, off + 4, le) else {
            break;
        };
        if let Some((_, iface)) = KNOWN.iter().find(|(u, _)| *u == uuid) {
            out.push((ctx_id, *iface));
        }
        // ctx_id(2) + n_syn(1) + pad(1) + abstract syntax(20) + n_syn transfer syntaxes(20 each).
        off += 4 + 20 + 20 * usize::from(n_syn);
    }
    out
}

/// `(context id, opnum)` of a request PDU.
pub(crate) fn request_op(pdu: &[u8], h: &PduHeader) -> Option<(u16, u16)> {
    let le = h.little_endian;
    // header(16) + alloc_hint(4) + p_cont_id(2) + opnum(2)
    let ctx = u16_at(pdu, 20, le)?;
    let op = u16_at(pdu, 22, le)?;
    let _ = h.flags & PFC_OBJECT_UUID; // the object UUID (if any) follows; not needed
    Some((ctx, op))
}

/// Builders for tests.
#[cfg(test)]
pub(crate) mod build {
    use super::*;

    pub fn uuid_le(iface: Iface) -> [u8; 16] {
        let (d1, d2, d3, d4) = KNOWN.iter().find(|(_, i)| *i == iface).unwrap().0;
        let mut b = [0u8; 16];
        b[0..4].copy_from_slice(&d1.to_le_bytes());
        b[4..6].copy_from_slice(&d2.to_le_bytes());
        b[6..8].copy_from_slice(&d3.to_le_bytes());
        b[8..16].copy_from_slice(&d4);
        b
    }

    fn hdr(ptype: u8, body: &[u8]) -> Vec<u8> {
        let mut v = vec![5, 0, ptype, 0x03, 0x10, 0, 0, 0];
        v.extend_from_slice(&((16 + body.len()) as u16).to_le_bytes());
        v.extend_from_slice(&0u16.to_le_bytes());
        v.extend_from_slice(&1u32.to_le_bytes());
        v.extend_from_slice(body);
        v
    }

    /// A bind proposing each `(ctx_id, iface)` with one NDR transfer syntax.
    pub fn bind(ctxs: &[(u16, Iface)]) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&4280u16.to_le_bytes());
        b.extend_from_slice(&4280u16.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.push(ctxs.len() as u8);
        b.extend_from_slice(&[0, 0, 0]);
        for (id, iface) in ctxs {
            b.extend_from_slice(&id.to_le_bytes());
            b.push(1);
            b.push(0);
            b.extend_from_slice(&uuid_le(*iface));
            b.extend_from_slice(&4u32.to_le_bytes());
            b.extend_from_slice(&[0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11]);
            b.extend_from_slice(&[0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60]);
            b.extend_from_slice(&2u32.to_le_bytes());
        }
        hdr(PTYPE_BIND, &b)
    }

    pub fn bind_ack() -> Vec<u8> {
        hdr(12, &[0u8; 40]) // bind_ack
    }

    /// A request with an opaque `stub_len`-byte stub.
    pub fn request(ctx: u16, opnum: u16, stub_len: usize) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&(stub_len as u32).to_le_bytes());
        b.extend_from_slice(&ctx.to_le_bytes());
        b.extend_from_slice(&opnum.to_le_bytes());
        b.extend(std::iter::repeat_n(0xCDu8, stub_len));
        hdr(PTYPE_REQUEST, &b)
    }
}

#[cfg(test)]
mod tests {
    use super::build::*;
    use super::*;

    #[test]
    fn reads_bind_contexts_and_request_opnums() {
        let b = bind(&[(0, Iface::Drsuapi), (1, Iface::Samr)]);
        let h = header(&b).unwrap();
        assert_eq!(h.ptype, PTYPE_BIND);
        assert_eq!(usize::from(h.frag_len), b.len());
        assert!(looks_like_bind(&b));
        assert_eq!(
            bind_contexts(&b, &h),
            vec![(0, Iface::Drsuapi), (1, Iface::Samr)]
        );
        let r = request(0, 3, 100);
        let h = header(&r).unwrap();
        assert_eq!(request_op(&r, &h), Some((0, 3)));
        assert_eq!(Iface::Drsuapi.op_name(3), Some("DRSGetNCChanges"));
        assert!(Iface::Samr.is_enumeration(13));
        assert!(!Iface::Drsuapi.is_enumeration(3));
    }

    #[test]
    fn rejects_non_rpc_and_survives_truncation() {
        assert_eq!(header(b"GET / HTTP/1.1\r\n"), Err(false));
        assert_eq!(header(&[5, 0, 11]), Err(true));
        assert!(!looks_like_bind(&request(0, 3, 10)));
        // A bind split across segments is recognised from its first few bytes.
        let b = bind(&[(0, Iface::Drsuapi)]);
        assert!(looks_like_bind(&b[..3]) && looks_like_bind(&b[..12]));
        assert!(!looks_like_bind(&b[..2]) && !looks_like_bind(b"\x05\x00\x00"));
        let b = bind(&[(0, Iface::Drsuapi)]);
        for cut in 0..b.len() {
            if let Ok(h) = header(&b[..cut]) {
                let _ = bind_contexts(&b[..cut], &h);
                let _ = request_op(&b[..cut], &h);
            }
        }
    }
}
