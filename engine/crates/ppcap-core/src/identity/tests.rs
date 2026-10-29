//! Identity observer + detector tests, driven through real decoded frames.

use std::net::{IpAddr, Ipv4Addr};

use super::dcerpc::build as rpc;
use super::dcerpc::Iface;
use super::kerberos::build as krb;
use super::ldap::build as ldap;
use super::ntlm::build as ntlm;
use super::smb2::build as smb;
use super::*;

/// NTSTATUS values used in the SMB tests.
const STATUS_OK: u32 = 0x0000_0000;
const STATUS_LOGON_FAILURE: u32 = 0xC000_006D;
use crate::gen::frames::{build_ipv4, build_udp, inet_checksum};
use crate::reader::{LinkType, RawFrame};

const TCP_ACK: u8 = 0x10;
const TCP_PSH: u8 = 0x08;

const DC: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 10);
const DC2: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 11);
const WS: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 50);
const ATTACKER: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 66);

fn ip(v: Ipv4Addr) -> IpAddr {
    IpAddr::V4(v)
}

/// A TCP segment with an explicit sequence number (the gen builder derives seq from ports).
fn tcp_frame(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    sp: u16,
    dp: u16,
    seq: u32,
    flags: u8,
    p: &[u8],
) -> Vec<u8> {
    let mut seg = Vec::with_capacity(20 + p.len());
    seg.extend_from_slice(&sp.to_be_bytes());
    seg.extend_from_slice(&dp.to_be_bytes());
    seg.extend_from_slice(&seq.to_be_bytes());
    seg.extend_from_slice(&1u32.to_be_bytes());
    seg.push(0x50);
    seg.push(flags);
    seg.extend_from_slice(&64240u16.to_be_bytes());
    seg.extend_from_slice(&[0, 0, 0, 0]);
    seg.extend_from_slice(p);
    let mut pseudo = Vec::new();
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.extend_from_slice(&[0, 6]);
    pseudo.extend_from_slice(&(seg.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(&seg);
    let cks = inet_checksum(&pseudo);
    seg[16..18].copy_from_slice(&cks.to_be_bytes());
    let mut pkt = build_ipv4(src, dst, 6, 64, seg.len());
    pkt.extend_from_slice(&seg);
    pkt
}

fn udp_frame(src: Ipv4Addr, dst: Ipv4Addr, sp: u16, dp: u16, p: &[u8]) -> Vec<u8> {
    let seg = build_udp(src, dst, sp, dp, p);
    let mut pkt = build_ipv4(src, dst, 17, 64, seg.len());
    pkt.extend_from_slice(&seg);
    pkt
}

/// Feeds frames through `decode_frame` into an observer, like the analysis loop does.
struct Harness {
    obs: IdentityObserver,
    n: u64,
}

impl Harness {
    fn new() -> Harness {
        Harness {
            obs: IdentityObserver::new(true),
            n: 0,
        }
    }

    fn frame(&mut self, data: &[u8]) {
        self.n += 1;
        let f = RawFrame {
            index: self.n,
            ts_ns: 1_700_000_000_000_000_000 + self.n as i64 * 1_000_000,
            ts_known: true,
            iface_id: 0,
            wire_len: data.len() as u32,
            cap_len: data.len() as u32,
            link_type: LinkType::Raw,
            data,
        };
        let meta = crate::decode::decode_frame(&f).expect("decodes");
        self.obs.observe(&meta, &f);
    }

    fn findings(self) -> Vec<Finding> {
        self.obs.into_findings(&IdentityParams::default())
    }
}

/// One TCP connection with per-direction sequence tracking.
struct Conn {
    c: Ipv4Addr,
    cp: u16,
    s: Ipv4Addr,
    sp: u16,
    cseq: u32,
    sseq: u32,
}

impl Conn {
    fn new(c: Ipv4Addr, cp: u16, s: Ipv4Addr, sp: u16) -> Conn {
        Conn {
            c,
            cp,
            s,
            sp,
            cseq: 1000,
            sseq: 9000,
        }
    }
    /// Client -> server bytes, cut into `mss`-sized segments.
    fn send(&mut self, h: &mut Harness, data: &[u8], mss: usize) {
        for chunk in data.chunks(mss.max(1)) {
            h.frame(&tcp_frame(
                self.c,
                self.s,
                self.cp,
                self.sp,
                self.cseq,
                TCP_PSH | TCP_ACK,
                chunk,
            ));
            self.cseq = self.cseq.wrapping_add(chunk.len() as u32);
        }
    }
    fn reply(&mut self, h: &mut Harness, data: &[u8], mss: usize) {
        for chunk in data.chunks(mss.max(1)) {
            h.frame(&tcp_frame(
                self.s,
                self.c,
                self.sp,
                self.cp,
                self.sseq,
                TCP_PSH | TCP_ACK,
                chunk,
            ));
            self.sseq = self.sseq.wrapping_add(chunk.len() as u32);
        }
    }
}

/// A Kerberos TGS exchange over TCP: request with `etypes`, reply with a `ticket_etype` ticket.
fn tgs(h: &mut Harness, client: Ipv4Addr, port: u16, spn: &str, etypes: &[i64], ticket_etype: i64) {
    let mut c = Conn::new(client, port, DC, 88);
    // A real TGS-REQ carries the TGT and often spans segments; 40-byte segments force reassembly.
    let req = krb::kdc_req(12, &[1], None, spn, etypes);
    c.send(h, &krb::tcp(&req), 40);
    let rep = krb::kdc_rep(13, "jdoe", spn, ticket_etype, 18);
    c.reply(h, &krb::tcp(&rep), 1460);
}

fn kinds(f: &[Finding]) -> Vec<FindingKind> {
    f.iter().map(|x| x.kind).collect()
}

#[test]
fn rc4_only_service_ticket_requests_are_kerberoasting() {
    let mut h = Harness::new();
    let spns = [
        "MSSQLSvc/sql01.corp.local:1433",
        "HTTP/intranet.corp.local",
        "svc_backup/bkp01.corp.local",
        "CIFS/files01.corp.local", // a machine class: ignored
    ];
    for (i, spn) in spns.iter().enumerate() {
        tgs(&mut h, ATTACKER, 50000 + i as u16, spn, &[23], 23);
    }
    let f = h.findings();
    assert_eq!(kinds(&f), vec![FindingKind::Kerberoasting], "{f:#?}");
    let k = &f[0];
    assert_eq!(k.src_ip, "10.0.0.66");
    assert_eq!(k.dst_ip.as_deref(), Some("10.0.0.10"));
    assert_eq!(k.dst_port, Some(88));
    assert_eq!(k.severity, Severity::High);
    assert_eq!(k.attack, vec!["T1558.003"]);
    let ev = k.evidence.join(" | ");
    assert!(ev.contains("MSSQLSvc/sql01.corp.local:1433"), "{ev}");
    assert!(!ev.contains("CIFS/files01"), "{ev}");
    assert!(ev.contains("requesting account: jdoe"), "{ev}");
    assert!(k.first_seen_ns.is_some() && k.last_seen_ns >= k.first_seen_ns);
}

#[test]
fn ordinary_aes_logon_traffic_is_silent() {
    let mut h = Harness::new();
    for (i, spn) in [
        "krbtgt/CORP.LOCAL",
        "host/ws01.corp.local",
        "cifs/files01.corp.local",
        "ldap/dc01.corp.local",
        "HTTP/intranet.corp.local",
    ]
    .iter()
    .enumerate()
    {
        tgs(
            &mut h,
            WS,
            51000 + i as u16,
            spn,
            &[18, 17, 23, 24, -135],
            18,
        );
    }
    // A normal AS exchange: no pre-auth -> PREAUTH_REQUIRED -> retry with a timestamp -> AS-REP.
    let mut c = Conn::new(WS, 52000, DC, 88);
    c.send(
        &mut h,
        &krb::tcp(&krb::kdc_req(
            10,
            &[128],
            Some("alice"),
            "krbtgt/CORP.LOCAL",
            &[18, 17, 23],
        )),
        1460,
    );
    c.reply(&mut h, &krb::tcp(&krb::krb_error(25, Some("alice"))), 1460);
    let mut c = Conn::new(WS, 52001, DC, 88);
    c.send(
        &mut h,
        &krb::tcp(&krb::kdc_req(
            10,
            &[2, 128],
            Some("alice"),
            "krbtgt/CORP.LOCAL",
            &[18, 17, 23],
        )),
        1460,
    );
    c.reply(
        &mut h,
        &krb::tcp(&krb::kdc_rep(11, "alice", "krbtgt/CORP.LOCAL", 18, 18)),
        1460,
    );
    let f = h.findings();
    assert!(f.is_empty(), "{f:#?}");
}

#[test]
fn as_rep_for_an_unauthenticated_request_is_as_rep_roasting() {
    let mut h = Harness::new();
    for (i, user) in ["svc_legacy", "old_unix"].iter().enumerate() {
        // UDP this time: the request/reply pair correlates on the client port.
        let req = krb::kdc_req(10, &[128], Some(user), "krbtgt/CORP.LOCAL", &[23]);
        h.frame(&udp_frame(ATTACKER, DC, 53000 + i as u16, 88, &req));
        let rep = krb::kdc_rep(11, user, "krbtgt/CORP.LOCAL", 18, 23);
        h.frame(&udp_frame(DC, ATTACKER, 88, 53000 + i as u16, &rep));
    }
    let f = h.findings();
    assert_eq!(kinds(&f), vec![FindingKind::AsrepRoasting], "{f:#?}");
    assert_eq!(f[0].severity, Severity::High);
    assert_eq!(f[0].attack, vec!["T1558.004"]);
    let ev = f[0].evidence.join(" | ");
    assert!(
        ev.contains("svc_legacy (RC4-HMAC)") && ev.contains("old_unix"),
        "{ev}"
    );
}

#[test]
fn rc4_ticket_despite_an_aes_offer_is_legacy_auth_on_the_kdc() {
    let mut h = Harness::new();
    tgs(
        &mut h,
        WS,
        51000,
        "MSSQLSvc/sql01.corp.local:1433",
        &[18, 17, 23],
        23,
    );
    let f = h.findings();
    assert_eq!(kinds(&f), vec![FindingKind::LegacyAuth], "{f:#?}");
    assert_eq!(f[0].src_ip, "10.0.0.10");
    assert_eq!(f[0].dst_ip, None);
    assert_eq!(f[0].severity, Severity::Medium);
    assert!(f[0].evidence[0].contains("MSSQLSvc/sql01.corp.local:1433"));
}

#[test]
fn drs_get_nc_changes_from_a_workstation_is_dcsync() {
    let mut h = Harness::new();
    let mut c = Conn::new(ATTACKER, 50100, DC, 49667);
    c.send(&mut h, &rpc::bind(&[(0, Iface::Drsuapi)]), 1460);
    c.reply(&mut h, &rpc::bind_ack(), 1460);
    c.send(&mut h, &rpc::request(0, 0, 60), 1460); // DRSBind
                                                   // A big, sealed stub split across segments: only the header is read.
    c.send(&mut h, &rpc::request(0, 3, 5000), 1460);
    c.send(&mut h, &rpc::request(0, 3, 300), 1460);
    let f = h.findings();
    assert_eq!(kinds(&f), vec![FindingKind::DcSync], "{f:#?}");
    let d = &f[0];
    assert_eq!(d.severity, Severity::Critical);
    assert_eq!(d.src_ip, "10.0.0.66");
    assert_eq!(d.dst_ip.as_deref(), Some("10.0.0.10"));
    assert_eq!(d.dst_port, Some(49667));
    assert_eq!(d.contacts, Some(2));
    assert_eq!(d.attack, vec!["T1003.006"]);
}

#[test]
fn dc_to_dc_replication_is_not_dcsync() {
    // DC2 answers Kerberos in this capture, so it is a DC and its replication is expected.
    let mut h = Harness::new();
    h.frame(&udp_frame(
        DC2,
        WS,
        88,
        53111,
        &krb::krb_error(25, Some("bob")),
    ));
    let mut c = Conn::new(DC2, 50200, DC, 49667);
    c.send(&mut h, &rpc::bind(&[(0, Iface::Drsuapi)]), 1460);
    c.send(&mut h, &rpc::request(0, 3, 200), 1460);
    assert!(h.findings().is_empty());

    // And a configured DC needs no inference.
    let mut h = Harness::new();
    let mut c = Conn::new(ATTACKER, 50200, DC, 49667);
    c.send(&mut h, &rpc::bind(&[(0, Iface::Drsuapi)]), 1460);
    c.send(&mut h, &rpc::request(0, 3, 200), 1460);
    let params = IdentityParams {
        domain_controllers: vec![ip(ATTACKER)],
        ..IdentityParams::default()
    };
    assert!(h.obs.into_findings(&params).is_empty());
}

#[test]
fn ldap_recon_then_roasting_escalates_the_recon() {
    let mut h = Harness::new();
    let mut c = Conn::new(ATTACKER, 50300, DC, 389);
    c.send(
        &mut h,
        &ldap::simple_bind(1, "CN=jdoe,CN=Users,DC=corp,DC=local"),
        1460,
    );
    let spn_filter = ldap::and(&[
        ldap::eq("objectCategory", "person"),
        ldap::present("servicePrincipalName"),
    ]);
    c.send(
        &mut h,
        &ldap::search(2, "DC=corp,DC=local", spn_filter, &["servicePrincipalName"]),
        1460,
    );
    let np = ldap::ext("1.2.840.113556.1.4.803", "userAccountControl", "4194304");
    c.send(
        &mut h,
        &ldap::search(3, "DC=corp,DC=local", np, &["sAMAccountName"]),
        7,
    );
    let mut alone = Harness::new();
    std::mem::swap(&mut alone.obs, &mut h.obs);
    let recon_only = alone.findings();
    assert_eq!(
        kinds(&recon_only),
        vec![FindingKind::AdRecon],
        "{recon_only:#?}"
    );
    let r = &recon_only[0];
    assert_eq!(r.severity, Severity::Medium);
    assert_eq!(r.dst_port, Some(389));
    let ev = r.evidence.join(" | ");
    assert!(ev.contains("Kerberoasting target list"), "{ev}");
    assert!(ev.contains("AS-REP roasting target list"), "{ev}");
    assert!(ev.contains("(servicePrincipalName=*)"), "{ev}");

    // Same recon, then the roast: the recon is raised to High.
    let mut h = Harness::new();
    let mut c = Conn::new(ATTACKER, 50300, DC, 389);
    let spn_filter = ldap::present("servicePrincipalName");
    c.send(
        &mut h,
        &ldap::search(2, "DC=corp,DC=local", spn_filter, &[]),
        1460,
    );
    for i in 0..3u16 {
        tgs(
            &mut h,
            ATTACKER,
            50400 + i,
            &format!("HTTP/app{i}.corp.local"),
            &[23],
            23,
        );
    }
    let f = h.findings();
    let recon = f
        .iter()
        .find(|x| x.kind == FindingKind::AdRecon)
        .expect("recon");
    assert_eq!(recon.severity, Severity::High);
    assert!(f.iter().any(|x| x.kind == FindingKind::Kerberoasting));
}

#[test]
fn recon_seen_after_the_roast_is_not_escalated() {
    let mut h = Harness::new();
    for i in 0..3u16 {
        tgs(
            &mut h,
            ATTACKER,
            50400 + i,
            &format!("HTTP/app{i}.corp.local"),
            &[23],
            23,
        );
    }
    let mut c = Conn::new(ATTACKER, 50300, DC, 389);
    let spn_filter = ldap::present("servicePrincipalName");
    c.send(
        &mut h,
        &ldap::search(2, "DC=corp,DC=local", spn_filter, &[]),
        1460,
    );
    let f = h.findings();
    let recon = f
        .iter()
        .find(|x| x.kind == FindingKind::AdRecon)
        .expect("recon");
    assert_eq!(recon.severity, Severity::Medium, "{recon:#?}");
}

#[test]
fn a_bind_split_across_segments_still_reveals_dcsync() {
    let mut h = Harness::new();
    let mut c = Conn::new(ATTACKER, 50700, DC, 49667);
    let b = rpc::bind(&[(0, Iface::Drsuapi)]);
    c.send(&mut h, &b[..20], 1460);
    c.send(&mut h, &b[20..], 1460);
    c.send(&mut h, &rpc::request(0, 3, 200), 1460);
    let f = h.findings();
    assert_eq!(kinds(&f), vec![FindingKind::DcSync], "{f:#?}");
}

#[test]
fn kerberos_username_enumeration_is_recon() {
    let mut h = Harness::new();
    for i in 0..12u16 {
        let user = format!("user{i}");
        let req = krb::kdc_req(10, &[128], Some(&user), "krbtgt/CORP.LOCAL", &[18, 17, 23]);
        h.frame(&udp_frame(ATTACKER, DC, 54000 + i, 88, &req));
        let code = if i < 8 { 6 } else { 25 };
        h.frame(&udp_frame(
            DC,
            ATTACKER,
            88,
            54000 + i,
            &krb::krb_error(code, Some(&user)),
        ));
    }
    let f = h.findings();
    assert_eq!(kinds(&f), vec![FindingKind::AdRecon], "{f:#?}");
    assert!(f[0].title.contains("12 usernames"), "{}", f[0].title);
}

#[test]
fn samr_enumeration_over_rpc_is_recon() {
    let mut h = Harness::new();
    let mut c = Conn::new(ATTACKER, 50500, DC, 49668);
    c.send(&mut h, &rpc::bind(&[(1, Iface::Samr)]), 1460);
    for _ in 0..6 {
        c.send(&mut h, &rpc::request(1, 13, 40), 1460);
        c.send(&mut h, &rpc::request(1, 25, 40), 1460);
    }
    let f = h.findings();
    assert_eq!(kinds(&f), vec![FindingKind::AdRecon], "{f:#?}");
    assert!(f[0].attack.contains(&"T1069.002".to_string()));
    assert!(
        f[0].evidence[0].contains("SamrEnumerateUsersInDomain"),
        "{:?}",
        f[0].evidence
    );
}

#[test]
fn retransmits_gaps_and_garbage_are_handled() {
    let mut h = Harness::new();
    // Garbage on the identity ports and an RPC-looking high port.
    let mut x: u32 = 7;
    let junk: Vec<u8> = (0..3000)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x as u8
        })
        .collect();
    for (i, port) in [88u16, 389, 3268, 135].iter().enumerate() {
        let mut c = Conn::new(WS, 40000 + i as u16, DC, *port);
        c.send(&mut h, &junk, 1000);
        c.reply(&mut h, &junk, 1000);
    }
    h.frame(&udp_frame(WS, DC, 40100, 88, &junk[..500]));

    // A Kerberoast request whose segments arrive duplicated: still parsed exactly once.
    let req = krb::tcp(&krb::kdc_req(12, &[1], None, "HTTP/a.corp.local", &[23]));
    let (a, b) = req.split_at(30);
    let seq = 1000;
    h.frame(&tcp_frame(
        ATTACKER,
        DC,
        41000,
        88,
        seq,
        TCP_PSH | TCP_ACK,
        a,
    ));
    h.frame(&tcp_frame(
        ATTACKER,
        DC,
        41000,
        88,
        seq,
        TCP_PSH | TCP_ACK,
        a,
    )); // retransmit
    h.frame(&tcp_frame(
        ATTACKER,
        DC,
        41000,
        88,
        seq + 30,
        TCP_PSH | TCP_ACK,
        b,
    ));
    let f = h.findings();
    assert_eq!(kinds(&f), vec![FindingKind::Kerberoasting], "{f:#?}");
    assert_eq!(
        f[0].severity,
        Severity::Medium,
        "one RC4-only SPN is a lead"
    );
}

#[test]
fn stream_table_and_buffers_stay_bounded() {
    let mut h = Harness::new();
    // A partial Kerberos record on many connections: each holds a buffer until the cap.
    let partial = [0u8, 0, 0xF0, 0, 0x6c, 0x82, 0xEF, 0xFC];
    for i in 0..(MAX_STREAMS as u32 + 100) {
        let src = Ipv4Addr::from(0x0a01_0000 + i);
        h.frame(&tcp_frame(
            src,
            DC,
            40000,
            88,
            1,
            TCP_PSH | TCP_ACK,
            &partial,
        ));
    }
    assert!(h.obs.streams.len() <= MAX_STREAMS);
    assert!(h.obs.buffered <= MAX_TOTAL_BUFFERED);
    assert!(h.obs.krb.len() <= MAX_KEYS);
}

#[test]
fn idle_streams_are_evicted_when_the_table_is_full() {
    let mut obs = IdentityObserver::new(true);
    let partial = [0u8, 0, 0x10, 0, 0x6c];
    let feed = |obs: &mut IdentityObserver, src: Ipv4Addr, ts: i64| {
        let data = tcp_frame(src, DC, 40000, 88, 1, TCP_PSH | TCP_ACK, &partial);
        let f = RawFrame {
            index: 0,
            ts_ns: ts,
            ts_known: true,
            iface_id: 0,
            wire_len: data.len() as u32,
            cap_len: data.len() as u32,
            link_type: LinkType::Raw,
            data: &data,
        };
        let meta = crate::decode::decode_frame(&f).expect("decodes");
        obs.observe(&meta, &f);
    };
    for i in 0..MAX_STREAMS as u32 {
        feed(&mut obs, Ipv4Addr::from(0x0a01_0000 + i), 0);
    }
    assert_eq!(obs.streams.len(), MAX_STREAMS);
    // Ten minutes later a new Kerberos connection still gets a stream.
    let late = Ipv4Addr::new(10, 9, 9, 9);
    feed(&mut obs, late, 600 * 1_000_000_000);
    assert!(obs.streams.keys().any(|k| k.0 == ip(late)));
    assert!(obs.streams.len() < MAX_STREAMS);
}

#[test]
fn disabled_observer_does_nothing() {
    let mut h = Harness::new();
    h.obs = IdentityObserver::new(false);
    tgs(&mut h, ATTACKER, 50000, "HTTP/a.corp.local", &[23], 23);
    assert!(h.obs.streams.is_empty());
    assert!(h.findings().is_empty());
}

#[test]
fn user_spn_classification() {
    assert!(is_user_spn("MSSQLSvc/sql01:1433"));
    assert!(is_user_spn("HTTP/web"));
    assert!(!is_user_spn("krbtgt/CORP.LOCAL"));
    assert!(!is_user_spn("HOST/ws01"));
    assert!(!is_user_spn("WS01$"));
    assert!(!is_user_spn("cifs/"));
}

// ── SMB / NTLM ────────────────────────────────────────────────────────────────

/// One SMB SESSION_SETUP exchange on its own connection: a type-3 NTLM AUTHENTICATE for
/// `domain\user` (NT-response length `nt_len`, 24 = NTLMv1) answered with `status`.
#[allow(clippy::too_many_arguments)]
fn smb_logon(
    h: &mut Harness,
    client: Ipv4Addr,
    cport: u16,
    server: Ipv4Addr,
    domain: &str,
    user: &str,
    nt_len: u16,
    status: u32,
) {
    let mut c = Conn::new(client, cport, server, 445);
    let auth = ntlm::authenticate(domain, user, "WS", 0, nt_len);
    c.send(h, &smb::nbss(&smb::session_setup_req(&auth)), 1460);
    c.reply(h, &smb::nbss(&smb::session_setup_resp(status)), 1460);
}

/// DCE-RPC PDUs carried to a named pipe over one SMB connection (pipe-transceive IOCTLs),
/// cut into `mss`-sized TCP segments.
fn smb_pipe_rpc(
    h: &mut Harness,
    client: Ipv4Addr,
    cport: u16,
    server: Ipv4Addr,
    pdus: &[Vec<u8>],
    mss: usize,
) {
    let mut c = Conn::new(client, cport, server, 445);
    for pdu in pdus {
        c.send(h, &smb::nbss(&smb::ioctl_transceive(pdu)), mss);
    }
}

#[test]
fn smb_logons_failing_across_many_accounts_are_a_password_spray() {
    let mut h = Harness::new();
    let users = ["alice", "bob", "carol", "dave", "erin", "frank"];
    for (i, u) in users.iter().enumerate() {
        smb_logon(
            &mut h,
            ATTACKER,
            40000 + i as u16,
            DC,
            "CORP",
            u,
            220,
            STATUS_LOGON_FAILURE,
        );
    }
    let f = h.findings();
    assert_eq!(kinds(&f), vec![FindingKind::PasswordSpray], "{f:#?}");
    let s = &f[0];
    assert_eq!(s.src_ip, "10.0.0.66");
    assert_eq!(s.dst_ip.as_deref(), Some("10.0.0.10"));
    assert_eq!(s.dst_port, Some(445));
    assert_eq!(s.severity, Severity::Medium);
    assert_eq!(s.attack, vec!["T1110.003"]);
    let ev = s.evidence.join(" | ");
    assert!(ev.contains("6 distinct accounts"), "{ev}");
    assert!(ev.contains("CORP\\alice"), "{ev}");
}

#[test]
fn psexec_style_service_creation_over_a_named_pipe_is_remote_execution() {
    let mut h = Harness::new();
    // Reach ADMIN$ (payload drop) then create + start a service over \svcctl, split small.
    let mut c = Conn::new(ATTACKER, 41000, DC, 445);
    c.send(
        &mut h,
        &smb::nbss(&smb::tree_connect_req("\\\\dc01\\ADMIN$")),
        1460,
    );
    let pdus = [
        rpc::bind(&[(0, Iface::Svcctl)]),
        rpc::request(0, 12, 60), // RCreateServiceW
        rpc::request(0, 19, 10), // RStartServiceW
    ];
    for pdu in &pdus {
        c.send(&mut h, &smb::nbss(&smb::ioctl_transceive(pdu)), 16);
    }
    let f = h.findings();
    assert_eq!(kinds(&f), vec![FindingKind::RemoteServiceExec], "{f:#?}");
    let r = &f[0];
    assert_eq!(r.src_ip, "10.0.0.66");
    assert_eq!(r.dst_ip.as_deref(), Some("10.0.0.10"));
    assert_eq!(r.severity, Severity::High);
    assert!(r.attack.contains(&"T1021.002".to_string()));
    assert!(r.attack.contains(&"T1569.002".to_string()));
    let ev = r.evidence.join(" | ");
    assert!(ev.contains("PsExec"), "{ev}");
    assert!(ev.contains("ADMIN$"), "{ev}");
}

#[test]
fn scheduled_task_registration_over_a_pipe_is_remote_execution() {
    let mut h = Harness::new();
    let pdus = [
        rpc::bind(&[(0, Iface::TaskScheduler)]),
        rpc::request(0, 1, 40), // SchRpcRegisterTask
    ];
    smb_pipe_rpc(&mut h, ATTACKER, 42000, WS, &pdus, 1460);
    let f = h.findings();
    assert_eq!(kinds(&f), vec![FindingKind::RemoteServiceExec], "{f:#?}");
    assert!(f[0].attack.contains(&"T1053.005".to_string()));
}

#[test]
fn dcsync_over_an_smb_named_pipe_is_detected() {
    let mut h = Harness::new();
    let pdus = [
        rpc::bind(&[(0, Iface::Drsuapi)]),
        rpc::request(0, 3, 120), // DRSGetNCChanges
    ];
    smb_pipe_rpc(&mut h, ATTACKER, 43000, DC, &pdus, 24);
    let f = h.findings();
    assert_eq!(kinds(&f), vec![FindingKind::DcSync], "{f:#?}");
    assert_eq!(f[0].dst_port, Some(445));
}

#[test]
fn ntlm_v1_logon_is_legacy_auth() {
    let mut h = Harness::new();
    smb_logon(&mut h, WS, 44000, DC, "CORP", "jdoe", 24, STATUS_OK);
    let f = h.findings();
    assert_eq!(kinds(&f), vec![FindingKind::LegacyAuth], "{f:#?}");
    let l = &f[0];
    assert_eq!(l.severity, Severity::High);
    let ev = l.evidence.join(" | ");
    assert!(ev.contains("NTLMv1"), "{ev}");
    assert!(ev.contains("CORP\\jdoe"), "{ev}");
}

#[test]
fn a_normal_ntlm_v2_smb_logon_is_silent() {
    let mut h = Harness::new();
    smb_logon(&mut h, WS, 45000, DC, "CORP", "jdoe", 220, STATUS_OK);
    smb_logon(&mut h, WS, 45001, DC, "CORP", "jdoe", 220, STATUS_OK);
    assert!(h.findings().is_empty());
}

#[test]
fn two_named_pipes_on_one_connection_keep_separate_rpc_contexts() {
    // Over one SMB connection: pipe handle A binds context 0 to SAMR; pipe handle B reuses
    // context 0 for SVCCTL and creates + starts a service. The second bind must not be shadowed
    // by the first — otherwise the service calls would be miscounted as SAMR and go unreported.
    let mut h = Harness::new();
    let mut c = Conn::new(ATTACKER, 46000, DC, 445);
    let a = [1u8; 16];
    let b = [2u8; 16];
    c.send(
        &mut h,
        &smb::nbss(&smb::ioctl_transceive_h(a, &rpc::bind(&[(0, Iface::Samr)]))),
        1460,
    );
    c.send(
        &mut h,
        &smb::nbss(&smb::ioctl_transceive_h(
            b,
            &rpc::bind(&[(0, Iface::Svcctl)]),
        )),
        1460,
    );
    c.send(
        &mut h,
        &smb::nbss(&smb::ioctl_transceive_h(b, &rpc::request(0, 12, 40))),
        1460,
    );
    c.send(
        &mut h,
        &smb::nbss(&smb::ioctl_transceive_h(b, &rpc::request(0, 19, 10))),
        1460,
    );
    let f = h.findings();
    assert_eq!(kinds(&f), vec![FindingKind::RemoteServiceExec], "{f:#?}");
    assert!(f[0].attack.contains(&"T1021.002".to_string()));
}

#[test]
fn raw_tcp_service_execution_is_not_labelled_smb_admin_shares() {
    // The same SVCCTL create + start over a raw dynamic RPC port: service execution, but not via
    // an SMB admin share, so no T1021.002.
    let mut h = Harness::new();
    let mut c = Conn::new(ATTACKER, 47000, WS, 49671);
    c.send(&mut h, &rpc::bind(&[(0, Iface::Svcctl)]), 1460);
    c.send(&mut h, &rpc::request(0, 12, 40), 1460);
    c.send(&mut h, &rpc::request(0, 19, 10), 1460);
    let f = h.findings();
    assert_eq!(kinds(&f), vec![FindingKind::RemoteServiceExec], "{f:#?}");
    assert!(
        !f[0].attack.contains(&"T1021.002".to_string()),
        "{:?}",
        f[0].attack
    );
    assert!(f[0].attack.contains(&"T1569.002".to_string()));
    assert!(f[0].evidence.join(" ").contains("over RPC"));
}

#[test]
fn file_writes_do_not_exhaust_named_pipe_tracking() {
    // A deployment client writes many ordinary files (non-RPC) on distinct handles, then opens
    // \svcctl and creates + starts a service. The file writes must not fill the pipe-handle
    // budget: only data that opens an RPC bind reserves a handle, so the service calls are still
    // detected.
    let mut h = Harness::new();
    let mut c = Conn::new(ATTACKER, 48000, DC, 445);
    for i in 0..40u16 {
        let mut fid = [0u8; 16];
        fid[0..2].copy_from_slice(&i.to_le_bytes());
        c.send(
            &mut h,
            &smb::nbss(&smb::write_req_h(
                fid,
                b"MZ\x90\x00 not rpc, just a file body",
            )),
            1460,
        );
    }
    let pipe = [0xFFu8; 16];
    for pdu in [
        rpc::bind(&[(0, Iface::Svcctl)]),
        rpc::request(0, 12, 40),
        rpc::request(0, 19, 10),
    ] {
        c.send(&mut h, &smb::nbss(&smb::write_req_h(pipe, &pdu)), 1460);
    }
    let f = h.findings();
    assert_eq!(kinds(&f), vec![FindingKind::RemoteServiceExec], "{f:#?}");
}

#[test]
fn a_bind_split_so_the_first_write_is_tiny_still_registers_the_pipe() {
    // A DCE-RPC bind can be split across SMB WRITEs. When the first write carries only one or two
    // bytes it is still the opening of a bind (`05` / `05 00`): the pipe must register
    // provisionally so the next write completes the bind and the \svcctl calls are detected.
    for split in [1usize, 2] {
        let mut h = Harness::new();
        let mut c = Conn::new(ATTACKER, 41100 + split as u16, DC, 445);
        let bind = rpc::bind(&[(0, Iface::Svcctl)]);
        let pipe = [7u8; 16];
        c.send(
            &mut h,
            &smb::nbss(&smb::write_req_h(pipe, &bind[..split])),
            1460,
        );
        c.send(
            &mut h,
            &smb::nbss(&smb::write_req_h(pipe, &bind[split..])),
            1460,
        );
        for pdu in [rpc::request(0, 12, 40), rpc::request(0, 19, 10)] {
            c.send(&mut h, &smb::nbss(&smb::write_req_h(pipe, &pdu)), 1460);
        }
        let f = h.findings();
        assert_eq!(
            kinds(&f),
            vec![FindingKind::RemoteServiceExec],
            "bind split at offset {split}: {f:#?}"
        );
    }
}
