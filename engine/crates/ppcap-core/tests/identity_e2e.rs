//! End-to-end Windows identity-attack detection: hand-built Kerberos / LDAP / DCE-RPC frames
//! written to a pcap and run through the real pipeline, then through the alert queue and the
//! teach-it-once suppression rules.
//!
//! Black-box by construction: frames and protocol messages are byte-built here (the crate's own
//! builders are private), the convention `eta_e2e.rs` and `l7_enrichment_proof.rs` set.

use std::net::Ipv4Addr;

use ppcap_core::analyze::{self, PipelineConfig};
use ppcap_core::gen::{GenConfig, Scenario, SynthGen};
use ppcap_core::model::finding::FindingKind;
use ppcap_core::model::severity::Severity;
use ppcap_core::model::summary::Summary;
use ppcap_core::{apply_suppressions, SuppressionOutcome, SuppressionRule};

const DC: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 10);
const WS: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 50);
const ATTACKER: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 66);
const AAD_CONNECT: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 20);

// ── DER / BER ───────────────────────────────────────────────────────────────

fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
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
fn seq(parts: &[Vec<u8>]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}
fn ctx(n: u8, inner: Vec<u8>) -> Vec<u8> {
    tlv(0xa0 | n, &inner)
}
fn int(v: u8) -> Vec<u8> {
    tlv(0x02, &[v])
}
fn gstr(s: &str) -> Vec<u8> {
    tlv(0x1b, s.as_bytes())
}
fn principal(parts: &[&str]) -> Vec<u8> {
    seq(&[
        ctx(0, int(1)),
        ctx(1, seq(&parts.iter().map(|p| gstr(p)).collect::<Vec<_>>())),
    ])
}
fn enc_data(etype: u8) -> Vec<u8> {
    seq(&[ctx(0, int(etype)), ctx(2, tlv(0x04, &[0xAB; 64]))])
}

/// TGS-REQ for `spn` accepting `etypes`, with a TGT-sized padata so it spans segments.
fn tgs_req(spn: &str, etypes: &[u8]) -> Vec<u8> {
    let sparts: Vec<&str> = spn.split('/').collect();
    let body = seq(&[
        ctx(0, tlv(0x03, &[0, 0x40, 0x81, 0, 0x10])),
        ctx(2, gstr("CORP.LOCAL")),
        ctx(3, principal(&sparts)),
        ctx(5, tlv(0x18, b"20370913024805Z")),
        ctx(7, int(42)),
        ctx(8, seq(&etypes.iter().map(|e| int(*e)).collect::<Vec<_>>())),
    ]);
    let ap_req = seq(&[ctx(1, int(1)), ctx(2, tlv(0x04, &[0x55; 1400]))]);
    let msg = tlv(
        0x6c,
        &seq(&[
            ctx(1, int(5)),
            ctx(2, int(12)),
            ctx(3, seq(&[ap_req])),
            ctx(4, body),
        ]),
    );
    framed(&msg)
}

fn tgs_rep(user: &str, spn: &str, ticket_etype: u8) -> Vec<u8> {
    let sparts: Vec<&str> = spn.split('/').collect();
    let ticket = tlv(
        0x61,
        &seq(&[
            ctx(0, int(5)),
            ctx(1, gstr("CORP.LOCAL")),
            ctx(2, principal(&sparts)),
            ctx(3, enc_data(ticket_etype)),
        ]),
    );
    let msg = tlv(
        0x6d,
        &seq(&[
            ctx(0, int(5)),
            ctx(1, int(13)),
            ctx(3, gstr("CORP.LOCAL")),
            ctx(4, principal(&[user])),
            ctx(5, ticket),
            ctx(6, enc_data(18)),
        ]),
    );
    framed(&msg)
}

fn framed(msg: &[u8]) -> Vec<u8> {
    let mut v = (msg.len() as u32).to_be_bytes().to_vec();
    v.extend_from_slice(msg);
    v
}

/// LDAP search for accounts with an SPN.
fn ldap_spn_search() -> Vec<u8> {
    let s = |v: &str| tlv(0x04, v.as_bytes());
    let filter = tlv(
        0xa0,
        &[
            tlv(0xa3, &[s("objectCategory"), s("person")].concat()),
            tlv(0x87, b"servicePrincipalName"),
        ]
        .concat(),
    );
    let body = [
        s("DC=corp,DC=local"),
        tlv(0x0a, &[2]),
        tlv(0x0a, &[0]),
        int(0),
        int(0),
        tlv(0x01, &[0]),
        filter,
        seq(&[s("servicePrincipalName")]),
    ]
    .concat();
    seq(&[int(2), tlv(0x63, &body)])
}

// ── DCE-RPC ─────────────────────────────────────────────────────────────────

const DRSUAPI_UUID_LE: [u8; 16] = [
    0x35, 0x42, 0x51, 0xe3, 0x06, 0x4b, 0xd1, 0x11, 0xab, 0x04, 0x00, 0xc0, 0x4f, 0xc2, 0xdc, 0xd2,
];

fn rpc_pdu(ptype: u8, body: &[u8]) -> Vec<u8> {
    let mut v = vec![5, 0, ptype, 0x03, 0x10, 0, 0, 0];
    v.extend_from_slice(&((16 + body.len()) as u16).to_le_bytes());
    v.extend_from_slice(&0u16.to_le_bytes());
    v.extend_from_slice(&1u32.to_le_bytes());
    v.extend_from_slice(body);
    v
}

fn drsuapi_bind() -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&4280u16.to_le_bytes());
    b.extend_from_slice(&4280u16.to_le_bytes());
    b.extend_from_slice(&0u32.to_le_bytes());
    b.extend_from_slice(&[1, 0, 0, 0]); // one context
    b.extend_from_slice(&0u16.to_le_bytes()); // context id 0
    b.extend_from_slice(&[1, 0]);
    b.extend_from_slice(&DRSUAPI_UUID_LE);
    b.extend_from_slice(&4u32.to_le_bytes());
    b.extend_from_slice(&[0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11]);
    b.extend_from_slice(&[0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60]);
    b.extend_from_slice(&2u32.to_le_bytes());
    rpc_pdu(11, &b)
}

fn rpc_request(opnum: u16, stub: usize) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&(stub as u32).to_le_bytes());
    b.extend_from_slice(&0u16.to_le_bytes());
    b.extend_from_slice(&opnum.to_le_bytes());
    b.extend(std::iter::repeat_n(0xCDu8, stub));
    rpc_pdu(0, &b)
}

// ── Frames / pcap ───────────────────────────────────────────────────────────

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = bytes.chunks_exact(2);
    for c in &mut chunks {
        sum += (u32::from(c[0]) << 8) | u32::from(c[1]);
    }
    if let [last] = chunks.remainder() {
        sum += u32::from(*last) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

fn tcp(src: Ipv4Addr, dst: Ipv4Addr, sp: u16, dp: u16, seq_no: u32, payload: &[u8]) -> Vec<u8> {
    let mut seg = Vec::new();
    seg.extend_from_slice(&sp.to_be_bytes());
    seg.extend_from_slice(&dp.to_be_bytes());
    seg.extend_from_slice(&seq_no.to_be_bytes());
    seg.extend_from_slice(&1u32.to_be_bytes());
    seg.push(0x50);
    seg.push(0x18); // PSH|ACK
    seg.extend_from_slice(&64240u16.to_be_bytes());
    seg.extend_from_slice(&[0, 0, 0, 0]);
    seg.extend_from_slice(payload);
    let mut pseudo = Vec::new();
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.extend_from_slice(&[0, 6]);
    pseudo.extend_from_slice(&(seg.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(&seg);
    let c = checksum(&pseudo);
    seg[16..18].copy_from_slice(&c.to_be_bytes());

    let mut ip = vec![0x45, 0];
    ip.extend_from_slice(&((20 + seg.len()) as u16).to_be_bytes());
    ip.extend_from_slice(&[0, 0, 0x40, 0, 64, 6, 0, 0]);
    ip.extend_from_slice(&src.octets());
    ip.extend_from_slice(&dst.octets());
    let c = checksum(&ip);
    ip[10..12].copy_from_slice(&c.to_be_bytes());
    ip.extend_from_slice(&seg);
    ip
}

/// A TCP conversation builder with per-direction sequence numbers.
struct Conv {
    frames: Vec<Vec<u8>>,
}

impl Conv {
    fn new() -> Conv {
        Conv { frames: Vec::new() }
    }
    /// Client -> server data then server -> client data, in 1460-byte segments.
    fn exchange(&mut self, c: Ipv4Addr, cp: u16, s: Ipv4Addr, sp: u16, req: &[u8], rep: &[u8]) {
        let mut cs = 1000u32;
        for chunk in req.chunks(1460) {
            self.frames.push(tcp(c, s, cp, sp, cs, chunk));
            cs += chunk.len() as u32;
        }
        let mut ss = 9000u32;
        for chunk in rep.chunks(1460) {
            self.frames.push(tcp(s, c, sp, cp, ss, chunk));
            ss += chunk.len() as u32;
        }
    }
}

fn analyze_frames(name: &str, frames: &[Vec<u8>], cfg: &PipelineConfig) -> Summary {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "ppcap_identity_{}_{}.pcap",
        name,
        std::process::id()
    ));
    let mut out = Vec::new();
    out.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes());
    out.extend_from_slice(&2u16.to_le_bytes());
    out.extend_from_slice(&4u16.to_le_bytes());
    out.extend_from_slice(&[0u8; 8]);
    out.extend_from_slice(&65535u32.to_le_bytes());
    out.extend_from_slice(&101u32.to_le_bytes()); // LINKTYPE_RAW
    for (i, f) in frames.iter().enumerate() {
        out.extend_from_slice(&(1_761_700_000u32 + i as u32).to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&(f.len() as u32).to_le_bytes());
        out.extend_from_slice(&(f.len() as u32).to_le_bytes());
        out.extend_from_slice(f);
    }
    std::fs::write(&path, out).expect("write pcap");
    let res = analyze::run(&path, cfg, |_, _, _| {}).expect("analyze");
    let _ = std::fs::remove_file(&path);
    res.summary
}

/// Recon, Kerberoasting and DCSync from one attacker, a directory-sync server replicating, and a
/// workstation doing ordinary AES Kerberos.
fn attack_story() -> Vec<Vec<u8>> {
    let mut c = Conv::new();
    c.exchange(ATTACKER, 50300, DC, 389, &ldap_spn_search(), &[]);
    for (i, spn) in [
        "MSSQLSvc/sql01.corp.local:1433",
        "HTTP/intranet.corp.local",
        "svc_backup/bkp01.corp.local",
    ]
    .iter()
    .enumerate()
    {
        let port = 50400 + i as u16;
        c.exchange(
            ATTACKER,
            port,
            DC,
            88,
            &tgs_req(spn, &[23]),
            &tgs_rep("jdoe", spn, 23),
        );
    }
    for (i, spn) in ["cifs/files01.corp.local", "HTTP/intranet.corp.local"]
        .iter()
        .enumerate()
    {
        let port = 51000 + i as u16;
        c.exchange(
            WS,
            port,
            DC,
            88,
            &tgs_req(spn, &[18, 17, 23]),
            &tgs_rep("alice", spn, 18),
        );
    }
    for (host, port) in [(ATTACKER, 50500u16), (AAD_CONNECT, 50600)] {
        let mut req = drsuapi_bind();
        req.extend_from_slice(&rpc_request(0, 60));
        req.extend_from_slice(&rpc_request(3, 4000));
        c.exchange(host, port, DC, 49667, &req, &[]);
    }
    c.frames
}

#[test]
fn attack_story_raises_explainable_identity_findings_and_alerts() {
    let s = analyze_frames("story", &attack_story(), &PipelineConfig::default());
    let of = |k: FindingKind| s.findings.iter().filter(move |f| f.kind == k);

    let roast: Vec<_> = of(FindingKind::Kerberoasting).collect();
    assert_eq!(roast.len(), 1, "{:#?}", s.findings);
    assert_eq!(roast[0].src_ip, "10.0.0.66");
    assert_eq!(roast[0].severity, Severity::High);
    assert!(roast[0]
        .evidence
        .iter()
        .any(|e| e.contains("MSSQLSvc/sql01.corp.local:1433")));

    let sync: Vec<_> = of(FindingKind::DcSync).collect();
    assert_eq!(sync.len(), 2, "attacker + directory-sync server");
    assert!(sync.iter().all(|f| f.severity == Severity::Critical));
    assert!(sync
        .iter()
        .all(|f| f.attack == vec!["T1003.006".to_string()]));

    // Recon then a credential attack from the same host: raised to High.
    let recon: Vec<_> = of(FindingKind::AdRecon).collect();
    assert_eq!(recon.len(), 1);
    assert_eq!(recon[0].severity, Severity::High);

    // The workstation's AES traffic raised nothing.
    assert!(!s.findings.iter().any(|f| f.src_ip == "10.0.0.50"));

    // Every identity finding reaches the alert queue.
    let alerted: std::collections::BTreeSet<u32> = s
        .alerts
        .iter()
        .flat_map(|a| a.finding_indices.iter().copied())
        .collect();
    for (i, f) in s.findings.iter().enumerate() {
        if matches!(f.kind, FindingKind::DcSync | FindingKind::Kerberoasting) {
            assert!(alerted.contains(&(i as u32)), "{} not alerted", f.title);
        }
    }
}

#[test]
fn a_directory_sync_server_can_be_taught_benign() {
    let mut s = analyze_frames("teach", &attack_story(), &PipelineConfig::default());
    let rule = SuppressionRule {
        id: String::new(),
        kind: "dcsync".to_string(),
        src: Some("10.0.0.20".to_string()),
        dst: Some("10.0.0.10".to_string()),
        dst_port: None,
        reason: "Entra Connect sync server".to_string(),
        author: Some("soc".to_string()),
        created: None,
        expires: None,
    };
    let loaded = ppcap_core::load_suppression_rules(
        &[ppcap_core::SuppressionFile {
            version: 1,
            rules: vec![rule],
        }],
        None,
    );
    apply_suppressions(&mut s, loaded.active);
    let hit = s.suppressions.iter().find(|h| {
        let f = &s.findings[h.finding_index as usize];
        f.kind == FindingKind::DcSync && f.src_ip == "10.0.0.20"
    });
    assert_eq!(hit.map(|h| h.outcome), Some(SuppressionOutcome::Suppressed));
    // The attacker's DCSync is untouched and still alerted.
    let attacker = s
        .findings
        .iter()
        .position(|f| f.kind == FindingKind::DcSync && f.src_ip == "10.0.0.66")
        .unwrap() as u32;
    assert!(s
        .alerts
        .iter()
        .any(|a| a.finding_indices.contains(&attacker)));
}

#[test]
fn configured_dcs_and_the_off_switch_are_honoured() {
    let mut cfg = PipelineConfig::default();
    cfg.identity.domain_controllers = vec![AAD_CONNECT.into()];
    let s = analyze_frames("dcflag", &attack_story(), &cfg);
    let sync: Vec<_> = s
        .findings
        .iter()
        .filter(|f| f.kind == FindingKind::DcSync)
        .collect();
    assert_eq!(sync.len(), 1);
    assert_eq!(sync[0].src_ip, "10.0.0.66");

    let mut off = PipelineConfig::default();
    off.identity.enabled = false;
    let s = analyze_frames("off", &attack_story(), &off);
    assert!(!s.findings.iter().any(|f| matches!(
        f.kind,
        FindingKind::Kerberoasting
            | FindingKind::AsrepRoasting
            | FindingKind::DcSync
            | FindingKind::AdRecon
            | FindingKind::LegacyAuth
    )));
}

#[test]
fn synthetic_benign_traffic_raises_no_identity_findings() {
    let mut path = std::env::temp_dir();
    path.push(format!("ppcap_identity_mixed_{}.pcap", std::process::id()));
    let mut gen = SynthGen::new(GenConfig {
        scenario: Scenario::Mixed,
        packets: 5_000,
        ..GenConfig::default()
    });
    gen.write_pcap(&path).expect("write capture");
    let out = analyze::run(&path, &PipelineConfig::default(), |_, _, _| {}).expect("analyze");
    let _ = std::fs::remove_file(&path);
    let noisy: Vec<_> = out
        .summary
        .findings
        .iter()
        .filter(|f| {
            matches!(
                f.kind,
                FindingKind::Kerberoasting
                    | FindingKind::AsrepRoasting
                    | FindingKind::DcSync
                    | FindingKind::AdRecon
                    | FindingKind::LegacyAuth
            )
        })
        .collect();
    assert!(noisy.is_empty(), "{noisy:#?}");
}

// ── SMB2 / NTLM ───────────────────────────────────────────────────────────────

const SVCCTL_UUID_LE: [u8; 16] = [
    0x81, 0xbb, 0x7a, 0x36, 0x44, 0x98, 0xf1, 0x35, 0xad, 0x32, 0x98, 0xf0, 0x38, 0x00, 0x10, 0x03,
];

fn nbss(msg: &[u8]) -> Vec<u8> {
    let n = msg.len() as u32;
    let mut v = vec![0x00, (n >> 16) as u8, (n >> 8) as u8, n as u8];
    v.extend_from_slice(msg);
    v
}

fn smb2_header(command: u16, flags: u32, status: u32) -> Vec<u8> {
    let mut h = Vec::new();
    h.extend_from_slice(b"\xfeSMB");
    h.extend_from_slice(&64u16.to_le_bytes());
    h.extend_from_slice(&0u16.to_le_bytes());
    h.extend_from_slice(&status.to_le_bytes());
    h.extend_from_slice(&command.to_le_bytes());
    h.extend_from_slice(&0u16.to_le_bytes());
    h.extend_from_slice(&flags.to_le_bytes());
    h.extend_from_slice(&0u32.to_le_bytes()); // NextCommand
    h.extend_from_slice(&0u64.to_le_bytes()); // MessageId
    h.extend_from_slice(&0u32.to_le_bytes()); // Reserved
    h.extend_from_slice(&0u32.to_le_bytes()); // TreeId
    h.extend_from_slice(&0u64.to_le_bytes()); // SessionId
    h.extend_from_slice(&[0u8; 16]); // Signature
    h
}

/// A type-3 NTLM AUTHENTICATE for `domain\user` with the given NT-response length.
fn ntlm_auth(domain: &str, user: &str, nt_len: u16) -> Vec<u8> {
    let u16le = |s: &str| -> Vec<u8> { s.encode_utf16().flat_map(|c| c.to_le_bytes()).collect() };
    let desc = |len: u16, off: u32| -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&len.to_le_bytes());
        v.extend_from_slice(&len.to_le_bytes());
        v.extend_from_slice(&off.to_le_bytes());
        v
    };
    let d = u16le(domain);
    let us = u16le(user);
    let nt_off = 64u32;
    let dom_off = nt_off + u32::from(nt_len);
    let usr_off = dom_off + d.len() as u32;
    let mut m = Vec::new();
    m.extend_from_slice(b"NTLMSSP\0");
    m.extend_from_slice(&3u32.to_le_bytes());
    m.extend_from_slice(&desc(0, nt_off)); // LM
    m.extend_from_slice(&desc(nt_len, nt_off)); // NT
    m.extend_from_slice(&desc(d.len() as u16, dom_off)); // domain
    m.extend_from_slice(&desc(us.len() as u16, usr_off)); // user
    m.extend_from_slice(&desc(0, usr_off)); // workstation
    m.extend_from_slice(&desc(0, usr_off)); // session key
    m.extend_from_slice(&1u32.to_le_bytes()); // flags: unicode
    m.extend(std::iter::repeat_n(0xBBu8, usize::from(nt_len)));
    m.extend_from_slice(&d);
    m.extend_from_slice(&us);
    m
}

fn smb_session_setup_req(blob: &[u8]) -> Vec<u8> {
    let mut m = smb2_header(1, 0, 0);
    let sec_off = 64u16 + 24;
    m.extend_from_slice(&25u16.to_le_bytes());
    m.extend_from_slice(&[0, 0]); // Flags, SecurityMode
    m.extend_from_slice(&0u32.to_le_bytes()); // Capabilities
    m.extend_from_slice(&0u32.to_le_bytes()); // Channel
    m.extend_from_slice(&sec_off.to_le_bytes());
    m.extend_from_slice(&(blob.len() as u16).to_le_bytes());
    m.extend_from_slice(&0u64.to_le_bytes()); // PreviousSessionId
    m.extend_from_slice(blob);
    nbss(&m)
}

fn smb_session_setup_resp(status: u32) -> Vec<u8> {
    let mut m = smb2_header(1, 0x0000_0001, status);
    m.extend_from_slice(&9u16.to_le_bytes());
    m.extend_from_slice(&[0u8; 6]);
    nbss(&m)
}

fn smb_ioctl_transceive(data: &[u8]) -> Vec<u8> {
    let mut m = smb2_header(11, 0, 0);
    let in_off = 64u32 + 56;
    m.extend_from_slice(&57u16.to_le_bytes());
    m.extend_from_slice(&0u16.to_le_bytes());
    m.extend_from_slice(&0x0011_C017u32.to_le_bytes()); // FSCTL_PIPE_TRANSCEIVE
    m.extend_from_slice(&[0u8; 16]); // FileId
    m.extend_from_slice(&in_off.to_le_bytes()); // InputOffset
    m.extend_from_slice(&(data.len() as u32).to_le_bytes()); // InputCount
    m.extend_from_slice(&0u32.to_le_bytes()); // MaxInputResponse
    m.extend_from_slice(&0u32.to_le_bytes()); // OutputOffset
    m.extend_from_slice(&0u32.to_le_bytes()); // OutputCount
    m.extend_from_slice(&0u32.to_le_bytes()); // MaxOutputResponse
    m.extend_from_slice(&0u32.to_le_bytes()); // Flags
    m.extend_from_slice(&0u32.to_le_bytes()); // Reserved2
    m.extend_from_slice(data);
    nbss(&m)
}

fn svcctl_bind() -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&4280u16.to_le_bytes());
    b.extend_from_slice(&4280u16.to_le_bytes());
    b.extend_from_slice(&0u32.to_le_bytes());
    b.extend_from_slice(&[1, 0, 0, 0]);
    b.extend_from_slice(&0u16.to_le_bytes());
    b.extend_from_slice(&[1, 0]);
    b.extend_from_slice(&SVCCTL_UUID_LE);
    b.extend_from_slice(&4u32.to_le_bytes());
    b.extend_from_slice(&[0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11]);
    b.extend_from_slice(&[0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60]);
    b.extend_from_slice(&2u32.to_le_bytes());
    rpc_pdu(11, &b)
}

/// One attacker over SMB: password spray (six failing logons) and a PsExec-style service
/// creation + start over the \svcctl named pipe.
fn smb_attack() -> Vec<Vec<u8>> {
    let mut c = Conv::new();
    for (i, user) in ["alice", "bob", "carol", "dave", "erin", "frank"]
        .iter()
        .enumerate()
    {
        c.exchange(
            ATTACKER,
            52000 + i as u16,
            DC,
            445,
            &smb_session_setup_req(&ntlm_auth("CORP", user, 220)),
            &smb_session_setup_resp(0xC000_006D), // STATUS_LOGON_FAILURE
        );
    }
    // Bind \svcctl, create a service (op 12), start it (op 19) — each PDU in its own
    // pipe-transceive IOCTL.
    let mut rpc_frames = Vec::new();
    for p in [svcctl_bind(), rpc_request(12, 60), rpc_request(19, 10)] {
        rpc_frames.push(smb_ioctl_transceive(&p));
    }
    c.exchange(ATTACKER, 52100, DC, 445, &rpc_frames.concat(), &[]);
    c.frames
}

#[test]
fn smb_spray_and_psexec_are_detected_and_suppressible() {
    let mut s = analyze_frames("smb", &smb_attack(), &PipelineConfig::default());
    let of = |k: FindingKind| s.findings.iter().filter(move |f| f.kind == k);

    let spray: Vec<_> = of(FindingKind::PasswordSpray).collect();
    assert_eq!(spray.len(), 1, "{:#?}", s.findings);
    assert_eq!(spray[0].src_ip, "10.0.0.66");
    assert_eq!(spray[0].dst_port, Some(445));
    assert_eq!(spray[0].attack, vec!["T1110.003".to_string()]);
    assert!(spray[0].evidence.iter().any(|e| e.contains("CORP\\alice")));

    let exec: Vec<_> = of(FindingKind::RemoteServiceExec).collect();
    assert_eq!(exec.len(), 1, "{:#?}", s.findings);
    assert_eq!(exec[0].severity, Severity::High);
    assert!(exec[0].attack.contains(&"T1569.002".to_string()));

    // Both reach the alert queue.
    let alerted: std::collections::BTreeSet<u32> = s
        .alerts
        .iter()
        .flat_map(|a| a.finding_indices.iter().copied())
        .collect();
    for (i, f) in s.findings.iter().enumerate() {
        if matches!(
            f.kind,
            FindingKind::PasswordSpray | FindingKind::RemoteServiceExec
        ) {
            assert!(alerted.contains(&(i as u32)), "{} not alerted", f.title);
        }
    }

    // A deployment host can be taught benign for remote service execution.
    let rule = SuppressionRule {
        id: String::new(),
        kind: "remote_service_exec".to_string(),
        src: Some("10.0.0.66".to_string()),
        dst: Some("10.0.0.10".to_string()),
        dst_port: None,
        reason: "SCCM software deployment".to_string(),
        author: Some("soc".to_string()),
        created: None,
        expires: None,
    };
    let loaded = ppcap_core::load_suppression_rules(
        &[ppcap_core::SuppressionFile {
            version: 1,
            rules: vec![rule],
        }],
        None,
    );
    apply_suppressions(&mut s, loaded.active);
    let hit = s
        .suppressions
        .iter()
        .find(|h| s.findings[h.finding_index as usize].kind == FindingKind::RemoteServiceExec);
    assert_eq!(hit.map(|h| h.outcome), Some(SuppressionOutcome::Suppressed));
}
