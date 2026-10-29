//! Windows identity-protocol analysis: Kerberos, DCE-RPC, LDAP, SMB2/3 and NTLM, parsed far
//! enough to see identity attacks on the wire.
//!
//! Like the TLS certificate reassembler, [`IdentityObserver`] is fed every decoded packet during
//! the single analysis pass. It keeps a small, bounded reassembly buffer per TCP direction on
//! identity channels (Kerberos 88, LDAP 389/3268, SMB 445/139, and DCE-RPC recognised by its bind
//! PDU on any other port), parses complete messages out of it, and folds what it learns into
//! per-client aggregates. At EOF [`IdentityObserver::into_findings`] turns those aggregates into
//! findings:
//!
//! - `kerberoasting` — service tickets for user-account SPNs requested or issued with RC4, or
//!   pulled in bulk (T1558.003);
//! - `asrep_roasting` — an AS-REP issued to a request with no pre-authentication (T1558.004);
//! - `dcsync` — `DRSGetNCChanges` from a host that is not a domain controller (T1003.006);
//! - `remote_service_exec` — a service created and started, or a task registered, over a named
//!   pipe (the PsExec / schtasks lateral-execution pattern; T1021.002 / T1569.002 / T1053.005);
//! - `password_spray` — SMB logons failing across many distinct accounts from one host
//!   (T1110.003);
//! - `ad_recon` — recon-shaped LDAP filters, SAMR/LSA enumeration, Kerberos username
//!   enumeration (T1087.002 / T1069.002);
//! - `legacy_auth` — a KDC issuing DES/RC4 tickets, NTLMv1 responses, or the SMB1 dialect.
//!
//! DCE-RPC carried on SMB named pipes (via WRITE or an FSCTL_PIPE_TRANSCEIVE IOCTL) is fed into
//! the same DCE-RPC logic as raw-port RPC, so DCSync and service execution are seen whether the
//! call rides 445 or a dynamic port.
//!
//! Retained: principal names, SPNs, LDAP filters, RPC operation names and logon account names,
//! each capped at 256 characters, and at most [`MAX_NAMES`] per aggregate. Never retained:
//! tickets, authenticators, NTLM responses, hashes, session keys, or any RPC or file payload.

pub(crate) mod ber;
pub(crate) mod dcerpc;
pub(crate) mod kerberos;
pub(crate) mod ldap;
pub(crate) mod ntlm;
pub(crate) mod smb2;

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::IpAddr;

use crate::model::finding::{Finding, FindingKind};
use crate::model::packet::{PacketMeta, Transport};
use crate::model::severity::Severity;

use dcerpc::Iface;
use kerberos::KrbMsg;

/// Concurrent reassembly streams tracked (one per TCP direction).
const MAX_STREAMS: usize = 4096;
/// Largest single message buffered; bigger ones are skipped (DCE-RPC requests are read from
/// their header alone, so this only limits Kerberos and LDAP).
const MAX_MSG: usize = 64 * 1024;
/// Total bytes buffered across all streams.
const MAX_TOTAL_BUFFERED: usize = 8 * 1024 * 1024;
/// Keys per aggregate map (clients, KDCs, RPC / LDAP channels, pending requests).
const MAX_KEYS: usize = 4096;
/// Names kept per aggregate set (SPNs, accounts, filters).
pub(crate) const MAX_NAMES: usize = 512;
/// Names listed in one evidence bullet.
const LIST_IN_EVIDENCE: usize = 10;

const LDAP_PORTS: [u16; 2] = [389, 3268];
const KERBEROS_PORT: u16 = 88;
/// SMB (direct-host TCP 445, and NetBIOS session service 139).
const SMB_PORTS: [u16; 2] = [445, 139];
/// NTSTATUS the detectors read.
const STATUS_SUCCESS: u32 = 0x0000_0000;
const STATUS_MORE_PROCESSING_REQUIRED: u32 = 0xC000_0016;
/// A stream or pending request idle this long (capture time) may be evicted to make room.
const IDLE_EVICT_NS: i64 = 120 * 1_000_000_000;
/// Fewest bytes a first segment needs to be recognised as the start of an RPC bind.
const MIN_BIND_PREFIX: u32 = 3;
const TCP_FIN: u8 = 0x01;
const TCP_RST: u8 = 0x04;

/// Tuning for the identity detectors.
#[derive(Debug, Clone)]
pub struct IdentityParams {
    /// Master switch: parsing and detection.
    pub enabled: bool,
    /// Known domain controllers, in addition to the ones inferred from the capture (hosts that
    /// answer Kerberos, or that clients bind DRSUAPI on). A DC is never reported for `dcsync`.
    pub domain_controllers: Vec<IpAddr>,
    /// Hosts never reported by any identity detector.
    pub ignore_ips: Vec<IpAddr>,
    /// Distinct user-account SPNs issued as RC4 tickets to one client before it counts as
    /// Kerberoasting (when the client did not itself ask for RC4 only).
    pub kerberoast_rc4_spns: usize,
    /// Distinct user-account SPNs requested by one client, any encryption, before the volume alone
    /// counts as Kerberoasting.
    pub kerberoast_bulk_spns: usize,
    /// Distinct usernames probed without pre-authentication, with at least
    /// `user_enum_unknown` "principal unknown" errors, before it counts as username enumeration.
    pub user_enum_names: usize,
    pub user_enum_unknown: usize,
    /// SAMR/LSA/SRVSVC/WKSSVC enumeration calls from one client to one server before they count
    /// as recon.
    pub rpc_enum_calls: u32,
    /// Distinct accounts whose SMB logon fails from one host before it counts as a password spray.
    pub smb_spray_users: usize,
}

impl Default for IdentityParams {
    fn default() -> Self {
        IdentityParams {
            enabled: true,
            domain_controllers: Vec::new(),
            ignore_ips: Vec::new(),
            kerberoast_rc4_spns: 3,
            kerberoast_bulk_spns: 20,
            user_enum_names: 10,
            user_enum_unknown: 5,
            rpc_enum_calls: 10,
            smb_spray_users: 5,
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Reassembly
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Proto {
    Kerberos,
    Ldap,
    DceRpc,
    Smb,
}

type StreamKey = (IpAddr, u16, IpAddr, u16);

/// Named-pipe RPC state for one SMB file handle. Each pipe handle has its own presentation-context
/// numbering, so they cannot share one table.
#[derive(Debug)]
struct PipeState {
    file_id: [u8; 16],
    contexts: Vec<(u16, Iface)>,
    /// DCE-RPC bytes carried but not yet forming a complete PDU.
    buf: Vec<u8>,
}

/// Named-pipe handles tracked per SMB connection.
const MAX_PIPES: usize = 32;

#[derive(Debug)]
struct Stream {
    proto: Proto,
    next_seq: Option<u32>,
    buf: Vec<u8>,
    /// Bytes still to discard (the rest of a message too large to buffer, or an RPC stub).
    skip: usize,
    /// DCE-RPC presentation contexts bound on a raw (ncacn_ip_tcp) RPC connection.
    contexts: Vec<(u16, Iface)>,
    /// Per-file-handle named-pipe RPC state (SMB only).
    pipes: Vec<PipeState>,
    /// Capture time of the last segment (for idle eviction).
    last_ts: i64,
}

impl Stream {
    fn new(proto: Proto, ts: i64) -> Stream {
        Stream {
            proto,
            next_seq: None,
            buf: Vec::new(),
            skip: 0,
            contexts: Vec::new(),
            pipes: Vec::new(),
            last_ts: ts,
        }
    }

    /// Total bytes this stream holds against the global budget: its reassembly buffer plus every
    /// named-pipe handle's buffer.
    fn buffered_len(&self) -> usize {
        self.buf.len() + self.pipes.iter().map(|p| p.buf.len()).sum::<usize>()
    }

    /// Append a segment in sequence order. Retransmissions are trimmed; a gap (lost or
    /// out-of-order segment) drops the partial message and resynchronises on this segment.
    fn push(&mut self, seq: Option<u32>, payload: &[u8]) {
        let data = match (self.next_seq, seq) {
            (Some(next), Some(seq)) => {
                let delta = seq.wrapping_sub(next) as i32;
                if delta == 0 {
                    payload
                } else if delta < 0 {
                    let overlap = delta.unsigned_abs() as usize;
                    if overlap >= payload.len() {
                        return; // pure retransmission
                    }
                    &payload[overlap..]
                } else {
                    self.buf.clear();
                    self.skip = 0;
                    payload
                }
            }
            _ => payload,
        };
        if let Some(seq) = seq {
            let end = seq.wrapping_add(payload.len() as u32);
            self.next_seq = Some(match self.next_seq {
                Some(n) if (end.wrapping_sub(n) as i32) < 0 => n,
                _ => end,
            });
        }
        let mut data = data;
        if self.skip > 0 {
            let n = self.skip.min(data.len());
            self.skip -= n;
            data = &data[n..];
        }
        self.buf.extend_from_slice(data);
    }
}

/// One complete unit pulled out of a stream.
enum Unit {
    /// A whole message.
    Msg(Vec<u8>),
    /// The first bytes of a DCE-RPC request (its stub is skipped).
    RpcRequestHead(Vec<u8>),
}

/// Pull every complete unit out of `s.buf`.
fn drain_units(s: &mut Stream) -> Vec<Unit> {
    let mut out = Vec::new();
    loop {
        if s.skip > 0 {
            let n = s.skip.min(s.buf.len());
            s.buf.drain(..n);
            s.skip -= n;
            if s.skip > 0 {
                break;
            }
        }
        if s.buf.is_empty() {
            break;
        }
        let len = match s.proto {
            Proto::Kerberos => kerberos::tcp_record_len(&s.buf).map(|n| n.saturating_add(4)),
            Proto::Ldap => ldap::record_len(&s.buf),
            Proto::DceRpc => match dcerpc::header(&s.buf) {
                Ok(h) if h.ptype == dcerpc::PTYPE_REQUEST => {
                    if s.buf.len() < 24 {
                        break;
                    }
                    out.push(Unit::RpcRequestHead(s.buf[..24].to_vec()));
                    s.skip = usize::from(h.frag_len);
                    continue;
                }
                Ok(h) => Ok(usize::from(h.frag_len)),
                Err(more) => Err(more),
            },
            Proto::Smb => smb2::record_len(&s.buf),
        };
        match len {
            Err(true) => break,
            Err(false) => {
                // Not this protocol at this offset (sealed session, mid-message capture start):
                // drop what we have and wait for a segment that starts a message.
                s.buf.clear();
                break;
            }
            Ok(n) if n > MAX_MSG => {
                s.skip = n;
            }
            Ok(n) if s.buf.len() >= n => {
                out.push(Unit::Msg(s.buf[..n].to_vec()));
                s.buf.drain(..n);
            }
            Ok(_) => break,
        }
    }
    out
}

// ---------------------------------------------------------------------------------------------
// Aggregates
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Default)]
struct Span {
    first: Option<i64>,
    last: Option<i64>,
}

impl Span {
    fn see(&mut self, ts: i64) {
        self.first = Some(self.first.map_or(ts, |f| f.min(ts)));
        self.last = Some(self.last.map_or(ts, |l| l.max(ts)));
    }
}

fn insert_capped(set: &mut BTreeSet<String>, v: &str) {
    if set.len() < MAX_NAMES || set.contains(v) {
        set.insert(v.to_string());
    }
}

/// The request a KDC reply on the same channel answers.
#[derive(Debug, Clone)]
struct PendingReq {
    as_req: bool,
    preauth: bool,
    cname: Option<String>,
    weak_only: bool,
    offers_aes: bool,
    ts: i64,
}

/// Per-client Kerberos activity.
#[derive(Debug, Default)]
struct ClientKrb {
    span: Span,
    /// KDC -> messages exchanged (picks the finding's destination).
    kdcs: BTreeMap<IpAddr, u32>,
    /// User-account SPNs requested with an RC4/DES-only etype list.
    weak_req_spns: BTreeSet<String>,
    /// User-account SPNs whose issued service ticket is RC4.
    rc4_ticket_spns: BTreeSet<String>,
    /// Every user-account SPN requested or issued.
    user_spns: BTreeSet<String>,
    /// Accounts named in this client's TGS-REPs (who did the requesting).
    tgs_users: BTreeSet<String>,
    tgs_reqs: u32,
    /// Accounts roasted via AS-REP -> reply enc-part etype.
    asrep_roasted: BTreeMap<String, i32>,
    /// Usernames sent in AS-REQs with no pre-authentication.
    nopreauth_names: BTreeSet<String>,
    principal_unknown: u32,
    unknown_names: BTreeSet<String>,
}

/// Per-KDC legacy-crypto issuance.
#[derive(Debug, Default)]
struct KdcWeak {
    span: Span,
    /// Principal -> etype, for DES tickets / replies.
    des: BTreeMap<String, i32>,
    /// SPNs issued an RC4 ticket although the client offered AES.
    rc4_despite_aes: BTreeSet<String>,
}

/// Per (client, server, port) DCE-RPC activity.
#[derive(Debug, Default)]
struct RpcPair {
    span: Span,
    bound: BTreeSet<Iface>,
    /// (interface, opnum) -> calls.
    ops: BTreeMap<(Iface, u16), u32>,
    /// At least one PDU on this pair arrived over an SMB named pipe (vs raw ncacn_ip_tcp).
    over_smb: bool,
}

/// Per (client, server, port) cleartext LDAP activity.
#[derive(Debug, Default)]
struct LdapPair {
    span: Span,
    searches: u32,
    /// Recon category -> first filter that matched it.
    recon: BTreeMap<&'static str, String>,
}

/// Per (client, server) SMB authentication and dialect activity.
#[derive(Debug, Default)]
struct SmbAuth {
    span: Span,
    /// SESSION_SETUP attempts that reached a final status (success or failure).
    attempts: u32,
    /// Accounts whose logon the server rejected.
    failed_users: BTreeSet<String>,
    /// Accounts whose logon succeeded.
    ok_users: BTreeSet<String>,
    /// Accounts that authenticated with an NTLMv1 / LM response.
    ntlm_v1_users: BTreeSet<String>,
    /// Administrative shares reached (`ADMIN$`, `C$`, …).
    admin_shares: BTreeSet<String>,
    /// The legacy SMB1 dialect was seen on this pair.
    smb1: bool,
}

/// A SESSION_SETUP whose response (carrying the logon status) has not yet arrived.
#[derive(Debug, Clone)]
struct SmbPend {
    account: String,
    ntlm_v1: bool,
    ts: i64,
}

/// LDAP recon categories: `(label, matcher over the lowercased filter + attribute list)`.
fn ldap_recon_categories(filter: &str, attrs: &[String]) -> Vec<&'static str> {
    let f = filter.to_ascii_lowercase();
    let a: Vec<String> = attrs.iter().map(|x| x.to_ascii_lowercase()).collect();
    let attr = |n: &str| a.iter().any(|x| x == n);
    let mut out = Vec::new();
    if f.contains("serviceprincipalname") {
        out.push("accounts with SPNs (Kerberoasting target list)");
    }
    if f.contains("useraccountcontrol") && f.contains("4194304") {
        out.push("accounts without Kerberos pre-authentication (AS-REP roasting target list)");
    }
    if f.contains("admincount=1") {
        out.push("privileged accounts (adminCount=1)");
    }
    if (f.contains("useraccountcontrol") && (f.contains("524288") || f.contains("16777216")))
        || f.contains("msds-allowedtodelegateto")
        || f.contains("msds-allowedtoactonbehalfofotheridentity")
    {
        out.push("delegation settings");
    }
    if f.contains("ms-mcs-admpwd")
        || f.contains("mslaps-")
        || attr("ms-mcs-admpwd")
        || attr("mslaps-password")
        || attr("mslaps-encryptedpassword")
    {
        out.push("LAPS local-admin passwords");
    }
    if f.contains("objectclass=trusteddomain") {
        out.push("domain trusts");
    }
    if f.contains("domain admins") || f.contains("enterprise admins") {
        out.push("privileged group membership");
    }
    out
}

/// Fed every decoded packet; owns all identity-protocol state for one analysis pass.
pub(crate) struct IdentityObserver {
    enabled: bool,
    streams: HashMap<StreamKey, Stream>,
    buffered: usize,
    last_sweep_ts: i64,
    pending: HashMap<(IpAddr, u16, IpAddr), PendingReq>,
    /// Hosts seen answering Kerberos.
    kdcs: BTreeSet<IpAddr>,
    /// Hosts clients bound DRSUAPI on.
    drs_servers: BTreeSet<IpAddr>,
    krb: BTreeMap<IpAddr, ClientKrb>,
    kdc_weak: BTreeMap<IpAddr, KdcWeak>,
    rpc: BTreeMap<(IpAddr, IpAddr, u16), RpcPair>,
    ldap: BTreeMap<(IpAddr, IpAddr, u16), LdapPair>,
    smb: BTreeMap<(IpAddr, IpAddr), SmbAuth>,
    /// SESSION_SETUP requests awaiting their response, keyed by (client, client port, server).
    smb_pending: HashMap<(IpAddr, u16, IpAddr), SmbPend>,
}

impl IdentityObserver {
    pub(crate) fn new(enabled: bool) -> IdentityObserver {
        IdentityObserver {
            enabled,
            streams: HashMap::new(),
            buffered: 0,
            last_sweep_ts: i64::MIN,
            pending: HashMap::new(),
            kdcs: BTreeSet::new(),
            drs_servers: BTreeSet::new(),
            krb: BTreeMap::new(),
            kdc_weak: BTreeMap::new(),
            rpc: BTreeMap::new(),
            ldap: BTreeMap::new(),
            smb: BTreeMap::new(),
            smb_pending: HashMap::new(),
        }
    }

    /// Fold one decoded packet. Returns immediately for traffic on no identity channel.
    pub(crate) fn observe(&mut self, meta: &PacketMeta, frame: &crate::reader::RawFrame) {
        if !self.enabled {
            return;
        }
        let Some((src, sport, dst, dport)) = meta.endpoints() else {
            return;
        };
        match meta.transport {
            Transport::Udp => {
                if (sport == KERBEROS_PORT) == (dport == KERBEROS_PORT) || meta.payload_len == 0 {
                    return;
                }
                let Some(info) = crate::decode::l4_payload(frame) else {
                    return;
                };
                self.on_kerberos(info.payload, src, sport, dst, dport, meta.ts_ns);
            }
            Transport::Tcp => self.observe_tcp(meta, frame, (src, sport, dst, dport)),
            _ => {}
        }
    }

    fn observe_tcp(&mut self, meta: &PacketMeta, frame: &crate::reader::RawFrame, key: StreamKey) {
        let (src, sport, dst, dport) = key;
        if meta.tcp_flags & (TCP_FIN | TCP_RST) != 0 {
            // Flush what this segment carries first, then forget both directions.
            if meta.payload_len > 0 && self.streams.contains_key(&key) {
                self.feed(meta, frame, key);
            }
            for k in [key, (dst, dport, src, sport)] {
                if let Some(s) = self.streams.remove(&k) {
                    self.buffered = self.buffered.saturating_sub(s.buffered_len());
                }
            }
            return;
        }
        if meta.payload_len == 0 {
            return;
        }
        if !self.streams.contains_key(&key) {
            let proto = if sport == KERBEROS_PORT || dport == KERBEROS_PORT {
                Proto::Kerberos
            } else if LDAP_PORTS.contains(&dport) {
                Proto::Ldap
            } else if SMB_PORTS.contains(&sport) || SMB_PORTS.contains(&dport) {
                Proto::Smb
            } else {
                // DCE-RPC on any port, picked up at its bind (the client's first PDU).
                if meta.payload_len < MIN_BIND_PREFIX {
                    return;
                }
                let Some(info) = crate::decode::l4_payload(frame) else {
                    return;
                };
                if !dcerpc::looks_like_bind(info.payload) {
                    return;
                }
                Proto::DceRpc
            };
            if self.streams.len() >= MAX_STREAMS {
                self.evict_idle(meta.ts_ns);
                if self.streams.len() >= MAX_STREAMS {
                    return;
                }
            }
            self.streams.insert(key, Stream::new(proto, meta.ts_ns));
        }
        self.feed(meta, frame, key);
    }

    /// Forget streams idle for [`IDLE_EVICT_NS`] (connections whose FIN was never captured).
    /// Runs only when the table is full, and at most once per second of capture time.
    fn evict_idle(&mut self, now: i64) {
        if now.saturating_sub(self.last_sweep_ts) < 1_000_000_000 {
            return;
        }
        self.last_sweep_ts = now;
        let mut freed = 0;
        self.streams.retain(|_, s| {
            let keep = now.saturating_sub(s.last_ts) < IDLE_EVICT_NS;
            if !keep {
                freed += s.buffered_len();
            }
            keep
        });
        self.buffered = self.buffered.saturating_sub(freed);
    }

    fn feed(&mut self, meta: &PacketMeta, frame: &crate::reader::RawFrame, key: StreamKey) {
        let Some(info) = crate::decode::l4_payload(frame) else {
            return;
        };
        if info.payload.is_empty() {
            return;
        }
        let Some(mut s) = self.streams.remove(&key) else {
            return;
        };
        let before = s.buffered_len();
        if self.buffered + info.payload.len() > MAX_TOTAL_BUFFERED {
            // Over the global budget: give this stream up rather than grow.
            self.buffered = self.buffered.saturating_sub(before);
            return;
        }
        s.last_ts = s.last_ts.max(meta.ts_ns);
        s.push(info.seq, info.payload);
        let units = drain_units(&mut s);
        let (src, sport, dst, dport) = key;
        let ts = meta.ts_ns;
        for u in units {
            match (s.proto, u) {
                (Proto::Kerberos, Unit::Msg(m)) => {
                    self.on_kerberos(&m[4..], src, sport, dst, dport, ts)
                }
                (Proto::Ldap, Unit::Msg(m)) => self.on_ldap(&m, src, dst, dport, ts),
                (Proto::DceRpc, Unit::Msg(m)) => {
                    self.on_rpc_pdu(&m, &mut s.contexts, false, src, dst, dport, ts);
                }
                (Proto::DceRpc, Unit::RpcRequestHead(m)) => {
                    self.on_rpc_pdu(&m, &mut s.contexts, false, src, dst, dport, ts);
                }
                (Proto::Smb, Unit::Msg(m)) => {
                    self.on_smb(&m[4..], &mut s, src, sport, dst, dport, ts);
                }
                _ => {}
            }
        }
        // Account every buffer the stream now holds (reassembly + named-pipe handles); pipe
        // buffers may have grown while handling the units above.
        self.buffered = (self.buffered + s.buffered_len()).saturating_sub(before);
        self.streams.insert(key, s);
    }

    // ---- Kerberos ---------------------------------------------------------------------------

    fn on_kerberos(
        &mut self,
        msg: &[u8],
        src: IpAddr,
        sport: u16,
        dst: IpAddr,
        dport: u16,
        ts: i64,
    ) {
        let Some(m) = kerberos::parse(msg) else {
            return;
        };
        let from_kdc = sport == KERBEROS_PORT;
        let (client, cport, kdc) = if from_kdc {
            (dst, dport, src)
        } else {
            (src, sport, dst)
        };
        if from_kdc && self.kdcs.len() < MAX_KEYS {
            self.kdcs.insert(kdc);
        }
        if !self.krb.contains_key(&client) && self.krb.len() >= MAX_KEYS {
            return;
        }
        let pending_key = (client, cport, kdc);
        let as_req = matches!(m, KrbMsg::AsReq(_));
        let tgs = matches!(m, KrbMsg::TgsRep(_));
        match m {
            KrbMsg::AsReq(r) | KrbMsg::TgsReq(r) if !from_kdc => {
                let c = self.krb.entry(client).or_default();
                c.span.see(ts);
                *c.kdcs.entry(kdc).or_default() += 1;
                if as_req {
                    if !r.preauthenticated() {
                        if let Some(n) = &r.cname {
                            insert_capped(&mut c.nopreauth_names, n);
                        }
                    }
                } else {
                    c.tgs_reqs += 1;
                    if let Some(spn) = r.sname.as_deref().filter(|s| is_user_spn(s)) {
                        insert_capped(&mut c.user_spns, spn);
                        if r.weak_etypes_only() {
                            insert_capped(&mut c.weak_req_spns, spn);
                        }
                    }
                }
                if self.pending.len() >= MAX_KEYS && !self.pending.contains_key(&pending_key) {
                    // Requests whose reply never came: drop the stale ones to make room.
                    self.pending
                        .retain(|_, p| ts.saturating_sub(p.ts) < IDLE_EVICT_NS);
                }
                if self.pending.len() < MAX_KEYS || self.pending.contains_key(&pending_key) {
                    self.pending.insert(
                        pending_key,
                        PendingReq {
                            as_req,
                            preauth: r.preauthenticated(),
                            cname: r.cname.clone(),
                            weak_only: r.weak_etypes_only(),
                            offers_aes: r.offers_aes(),
                            ts,
                        },
                    );
                }
            }
            KrbMsg::AsRep(rep) | KrbMsg::TgsRep(rep) if from_kdc => {
                let req = self.pending.remove(&pending_key);
                let c = self.krb.entry(client).or_default();
                c.span.see(ts);
                *c.kdcs.entry(kdc).or_default() += 1;
                let mut weak_des: Option<(String, i32)> = None;
                let mut weak_rc4: Option<String> = None;
                if tgs {
                    if let Some(u) = &rep.cname {
                        insert_capped(&mut c.tgs_users, u);
                    }
                    if let Some(spn) = rep.ticket_sname.as_deref() {
                        let user = is_user_spn(spn);
                        if user {
                            insert_capped(&mut c.user_spns, spn);
                        }
                        match rep.ticket_etype {
                            Some(e) if kerberos::is_des(e) => weak_des = Some((spn.to_string(), e)),
                            Some(e) if kerberos::is_rc4(e) => {
                                if user {
                                    insert_capped(&mut c.rc4_ticket_spns, spn);
                                }
                                // The client offered AES and still got RC4: the service account
                                // has no AES keys. A roaster asking for RC4 only is not posture.
                                if req.as_ref().is_some_and(|r| r.offers_aes && !r.weak_only) {
                                    weak_rc4 = Some(spn.to_string());
                                }
                            }
                            _ => {}
                        }
                    }
                } else {
                    let user = rep
                        .cname
                        .clone()
                        .or_else(|| req.as_ref().and_then(|r| r.cname.clone()));
                    if let (Some(r), Some(u)) = (&req, &user) {
                        if r.as_req && !r.preauth {
                            let etype = rep.enc_etype.unwrap_or(0);
                            if c.asrep_roasted.len() < MAX_NAMES {
                                c.asrep_roasted.insert(u.clone(), etype);
                            }
                        }
                    }
                    if let (Some(e), Some(u)) = (rep.enc_etype, &user) {
                        if kerberos::is_des(e) {
                            weak_des = Some((u.clone(), e));
                        }
                    }
                }
                if weak_des.is_some() || weak_rc4.is_some() {
                    if !self.kdc_weak.contains_key(&kdc) && self.kdc_weak.len() >= MAX_KEYS {
                        return;
                    }
                    let k = self.kdc_weak.entry(kdc).or_default();
                    k.span.see(ts);
                    if let Some((p, e)) = weak_des {
                        if k.des.len() < MAX_NAMES {
                            k.des.insert(p, e);
                        }
                    }
                    if let Some(spn) = weak_rc4 {
                        insert_capped(&mut k.rc4_despite_aes, &spn);
                    }
                }
            }
            KrbMsg::Error(e) if from_kdc => {
                self.pending.remove(&pending_key);
                let c = self.krb.entry(client).or_default();
                c.span.see(ts);
                *c.kdcs.entry(kdc).or_default() += 1;
                if e.code == kerberos::KDC_ERR_C_PRINCIPAL_UNKNOWN {
                    c.principal_unknown += 1;
                    if let Some(n) = &e.cname {
                        insert_capped(&mut c.unknown_names, n);
                    }
                }
            }
            _ => {}
        }
    }

    // ---- DCE-RPC ----------------------------------------------------------------------------

    /// Fold one DCE-RPC PDU. `contexts` is the presentation-context table for this channel: the
    /// whole connection for raw RPC, or one named-pipe handle for `over_smb` RPC (so two pipes
    /// on one SMB connection that both reuse context 0 do not shadow each other).
    #[allow(clippy::too_many_arguments)]
    fn on_rpc_pdu(
        &mut self,
        pdu: &[u8],
        contexts: &mut Vec<(u16, Iface)>,
        over_smb: bool,
        client: IpAddr,
        server: IpAddr,
        port: u16,
        ts: i64,
    ) {
        let Ok(h) = dcerpc::header(pdu) else {
            return;
        };
        let key = (client, server, port);
        match h.ptype {
            dcerpc::PTYPE_BIND | dcerpc::PTYPE_ALTER_CONTEXT => {
                let ctxs = dcerpc::bind_contexts(pdu, &h);
                if ctxs.is_empty() {
                    return;
                }
                for (id, iface) in &ctxs {
                    // A rebind of an existing context id replaces the mapping (an alter-context,
                    // or a fresh bind reusing the id on this handle).
                    if let Some(slot) = contexts.iter_mut().find(|(c, _)| c == id) {
                        slot.1 = *iface;
                    } else if contexts.len() < 64 {
                        contexts.push((*id, *iface));
                    }
                    if *iface == Iface::Drsuapi && self.drs_servers.len() < MAX_KEYS {
                        self.drs_servers.insert(server);
                    }
                }
                if !self.rpc.contains_key(&key) && self.rpc.len() >= MAX_KEYS {
                    return;
                }
                let p = self.rpc.entry(key).or_default();
                p.span.see(ts);
                p.over_smb |= over_smb;
                p.bound.extend(ctxs.iter().map(|(_, i)| *i));
            }
            dcerpc::PTYPE_REQUEST => {
                let Some((ctx, op)) = dcerpc::request_op(pdu, &h) else {
                    return;
                };
                let Some(&(_, iface)) = contexts.iter().find(|(c, _)| *c == ctx) else {
                    return;
                };
                if !self.rpc.contains_key(&key) && self.rpc.len() >= MAX_KEYS {
                    return;
                }
                let p = self.rpc.entry(key).or_default();
                p.span.see(ts);
                p.over_smb |= over_smb;
                if p.ops.len() < 256 || p.ops.contains_key(&(iface, op)) {
                    *p.ops.entry((iface, op)).or_default() += 1;
                }
            }
            _ => {}
        }
    }

    // ---- LDAP -------------------------------------------------------------------------------

    fn on_ldap(&mut self, msg: &[u8], client: IpAddr, server: IpAddr, port: u16, ts: i64) {
        let Some(ldap::LdapOp::Search(search)) = ldap::parse(msg) else {
            return;
        };
        let key = (client, server, port);
        if !self.ldap.contains_key(&key) && self.ldap.len() >= MAX_KEYS {
            return;
        }
        let p = self.ldap.entry(key).or_default();
        p.span.see(ts);
        p.searches = p.searches.saturating_add(1);
        for cat in ldap_recon_categories(&search.filter, &search.attrs) {
            p.recon.entry(cat).or_insert_with(|| search.filter.clone());
        }
    }

    // ---- SMB / NTLM -------------------------------------------------------------------------

    #[allow(clippy::too_many_arguments)]
    fn on_smb(
        &mut self,
        msg: &[u8],
        s: &mut Stream,
        src: IpAddr,
        sport: u16,
        dst: IpAddr,
        dport: u16,
        ts: i64,
    ) {
        let Some((is_response, ev)) = smb2::parse(msg) else {
            return;
        };
        // The client is whoever opened the session to the SMB port; direction comes from the
        // SMB header flag, not the port, so it is right even on an odd capture.
        let (client, cport, server) = if is_response {
            (dst, dport, src)
        } else {
            (src, sport, dst)
        };
        match ev {
            smb2::SmbEvent::Smb1 => {
                if let Some(a) = self.smb_entry(client, server) {
                    a.span.see(ts);
                    a.smb1 = true;
                }
            }
            smb2::SmbEvent::AuthBlob(blob) => {
                if let Some(ntlm::NtlmMsg::Authenticate(auth)) = ntlm::find(blob) {
                    let account = auth.account();
                    if account.is_empty() {
                        return;
                    }
                    let key = (client, cport, server);
                    if self.smb_pending.len() >= MAX_KEYS && !self.smb_pending.contains_key(&key) {
                        self.smb_pending
                            .retain(|_, p| ts.saturating_sub(p.ts) < IDLE_EVICT_NS);
                    }
                    if self.smb_pending.len() < MAX_KEYS || self.smb_pending.contains_key(&key) {
                        self.smb_pending.insert(
                            key,
                            SmbPend {
                                account,
                                ntlm_v1: auth.is_ntlm_v1(),
                                ts,
                            },
                        );
                    }
                }
            }
            smb2::SmbEvent::AuthResult(status) => {
                if status == STATUS_MORE_PROCESSING_REQUIRED {
                    return; // the challenge mid-handshake, not a verdict
                }
                let Some(pend) = self.smb_pending.remove(&(client, cport, server)) else {
                    return;
                };
                if let Some(a) = self.smb_entry(client, server) {
                    a.span.see(ts);
                    a.attempts = a.attempts.saturating_add(1);
                    if status == STATUS_SUCCESS {
                        insert_capped(&mut a.ok_users, &pend.account);
                        if pend.ntlm_v1 {
                            insert_capped(&mut a.ntlm_v1_users, &pend.account);
                        }
                    } else {
                        insert_capped(&mut a.failed_users, &pend.account);
                    }
                }
            }
            smb2::SmbEvent::TreeConnect(path) => {
                if let Some(share) = smb2::admin_share(&path) {
                    if let Some(a) = self.smb_entry(client, server) {
                        a.span.see(ts);
                        insert_capped(&mut a.admin_shares, &share);
                    }
                }
            }
            smb2::SmbEvent::PipeData { file_id, data } => {
                if !is_response {
                    self.on_pipe_rpc(file_id, data, s, client, server, 445, ts);
                }
            }
            smb2::SmbEvent::Other => {}
        }
    }

    /// `self.smb[(client, server)]`, or `None` when the map is full and the pair is new.
    fn smb_entry(&mut self, client: IpAddr, server: IpAddr) -> Option<&mut SmbAuth> {
        let key = (client, server);
        if !self.smb.contains_key(&key) && self.smb.len() >= MAX_KEYS {
            return None;
        }
        Some(self.smb.entry(key).or_default())
    }

    /// Feed DCE-RPC bytes a named pipe carried into the same RPC logic as raw-port RPC, keyed by
    /// the SMB file handle so two pipes on one connection keep separate context tables.
    #[allow(clippy::too_many_arguments)]
    fn on_pipe_rpc(
        &mut self,
        file_id: [u8; 16],
        data: &[u8],
        s: &mut Stream,
        client: IpAddr,
        server: IpAddr,
        port: u16,
        ts: i64,
    ) {
        let idx = match s.pipes.iter().position(|p| p.file_id == file_id) {
            Some(i) => i,
            None => {
                if s.pipes.len() >= MAX_PIPES {
                    return;
                }
                s.pipes.push(PipeState {
                    file_id,
                    contexts: Vec::new(),
                    buf: Vec::new(),
                });
                s.pipes.len() - 1
            }
        };
        if s.pipes[idx].buf.len() + data.len() > MAX_MSG {
            s.pipes[idx].buf.clear();
            if data.len() > MAX_MSG {
                return;
            }
        }
        s.pipes[idx].buf.extend_from_slice(data);
        loop {
            match dcerpc::header(&s.pipes[idx].buf) {
                Ok(h) => {
                    let n = usize::from(h.frag_len);
                    if s.pipes[idx].buf.len() < n {
                        break;
                    }
                    let pdu: Vec<u8> = s.pipes[idx].buf.drain(..n).collect();
                    self.on_rpc_pdu(
                        &pdu,
                        &mut s.pipes[idx].contexts,
                        true,
                        client,
                        server,
                        port,
                        ts,
                    );
                }
                Err(true) => break,
                Err(false) => {
                    s.pipes[idx].buf.clear();
                    break;
                }
            }
        }
    }

    // ---- Detection --------------------------------------------------------------------------

    /// Hosts treated as domain controllers: configured, answering Kerberos, or bound for DRSUAPI.
    fn domain_controllers(&self, params: &IdentityParams) -> BTreeSet<IpAddr> {
        let mut dcs: BTreeSet<IpAddr> = params.domain_controllers.iter().copied().collect();
        dcs.extend(self.kdcs.iter().copied());
        dcs.extend(self.drs_servers.iter().copied());
        dcs
    }

    /// Turn the aggregates into findings. Deterministic order.
    pub(crate) fn into_findings(self, params: &IdentityParams) -> Vec<Finding> {
        if !params.enabled {
            return Vec::new();
        }
        let ignored = |ip: &IpAddr| params.ignore_ips.contains(ip);
        let dcs = self.domain_controllers(params);
        let mut out = Vec::new();

        for (client, c) in &self.krb {
            if ignored(client) {
                continue;
            }
            let kdc = c
                .kdcs
                .iter()
                .max_by(|a, b| a.1.cmp(b.1).then(b.0.cmp(a.0)))
                .map(|(ip, _)| *ip);
            if let Some(f) = kerberoasting(*client, kdc, c, params) {
                out.push(f);
            }
            if let Some(f) = asrep_roasting(*client, kdc, c) {
                out.push(f);
            }
            if let Some(f) = kerberos_user_enum(*client, kdc, c, params) {
                out.push(f);
            }
        }
        for (kdc, k) in &self.kdc_weak {
            if !ignored(kdc) {
                out.push(legacy_auth(*kdc, k));
            }
        }
        for ((client, server, port), p) in &self.rpc {
            if ignored(client) || ignored(server) {
                continue;
            }
            if let Some(f) = dcsync(*client, *server, *port, p, &dcs, params) {
                out.push(f);
            }
            let smb = self.smb.get(&(*client, *server));
            if let Some(f) = remote_service_exec(*client, *server, *port, p, smb) {
                out.push(f);
            }
            if !dcs.contains(client) {
                if let Some(f) = rpc_recon(*client, *server, *port, p, params) {
                    out.push(f);
                }
            }
        }
        for ((client, server, port), p) in &self.ldap {
            if ignored(client) || ignored(server) || p.recon.is_empty() {
                continue;
            }
            out.push(ldap_recon(*client, *server, *port, p));
        }
        for ((client, server), a) in &self.smb {
            if ignored(client) || ignored(server) {
                continue;
            }
            if let Some(f) = password_spray(*client, *server, a, params) {
                out.push(f);
            }
            if let Some(f) = smb_legacy_auth(*client, *server, a) {
                out.push(f);
            }
        }

        // Recon followed by a credential attack from the same host is one story: raise the recon.
        // Only when the recon started before that attack activity ended — recon seen after the
        // attack did not lead to it.
        let mut attack_end: BTreeMap<String, i64> = BTreeMap::new();
        for f in &out {
            if matches!(
                f.kind,
                FindingKind::Kerberoasting | FindingKind::AsrepRoasting | FindingKind::DcSync
            ) {
                if let Some(last) = f.last_seen_ns {
                    let e = attack_end.entry(f.src_ip.clone()).or_insert(last);
                    *e = (*e).max(last);
                }
            }
        }
        for f in out.iter_mut() {
            let led_to_attack = match (f.first_seen_ns, attack_end.get(&f.src_ip)) {
                (Some(first), Some(end)) => first <= *end,
                _ => false,
            };
            if f.kind == FindingKind::AdRecon && led_to_attack && f.severity < Severity::High {
                f.severity = Severity::High;
                f.score = f.score.max(64);
                f.evidence.push(
                    "the same host went on to a Kerberos or replication credential attack"
                        .to_string(),
                );
            }
        }
        out
    }
}

/// SPN service classes that belong to computer accounts (random 120-character passwords, not
/// worth roasting) or to the KDC itself. Everything else may be a user/service account.
const MACHINE_SPN_CLASSES: &[&str] = &[
    "krbtgt",
    "kadmin",
    "host",
    "cifs",
    "ldap",
    "gc",
    "dns",
    "restrictedkrbhost",
    "wsman",
    "termsrv",
    "rpcss",
    "e3514235-4b06-11d1-ab04-00c04fc2dcd2",
];

/// Could this SPN belong to a user (service) account? Machine-account classes, the KDC, and
/// bare principals (no service class, e.g. `WS01$` in a user-to-user request) are excluded.
fn is_user_spn(spn: &str) -> bool {
    let Some((class, rest)) = spn.split_once('/') else {
        return false;
    };
    !rest.is_empty()
        && !MACHINE_SPN_CLASSES
            .iter()
            .any(|m| class.eq_ignore_ascii_case(m))
}

/// "a, b, c (+N more)" over a sorted set.
fn list<'a>(items: impl IntoIterator<Item = &'a String>) -> String {
    let v: Vec<&String> = items.into_iter().collect();
    let mut s = v
        .iter()
        .take(LIST_IN_EVIDENCE)
        .map(|x| x.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    if v.len() > LIST_IN_EVIDENCE {
        s.push_str(&format!(" (+{} more)", v.len() - LIST_IN_EVIDENCE));
    }
    s
}

#[allow(clippy::too_many_arguments)]
fn finding(
    kind: FindingKind,
    severity: Severity,
    score: u16,
    title: String,
    src: IpAddr,
    dst: Option<IpAddr>,
    port: Option<u16>,
    attack: &[&str],
    evidence: Vec<String>,
    contacts: Option<u64>,
    span: Span,
) -> Finding {
    Finding {
        kind,
        severity,
        score,
        title,
        src_ip: src.to_string(),
        dst_ip: dst.map(|d| d.to_string()),
        dst_port: port,
        attack: attack.iter().map(|s| s.to_string()).collect(),
        evidence,
        interval_ns: None,
        jitter_cv: None,
        contacts,
        first_seen_ns: span.first,
        last_seen_ns: span.last,
        victims: Vec::new(),
    }
}

fn kerberoasting(
    client: IpAddr,
    kdc: Option<IpAddr>,
    c: &ClientKrb,
    params: &IdentityParams,
) -> Option<Finding> {
    let weak_req = c.weak_req_spns.len();
    let rc4 = c.rc4_ticket_spns.len();
    let bulk = c.user_spns.len();
    let fires = weak_req >= 1
        || rc4 >= params.kerberoast_rc4_spns.max(1)
        || bulk >= params.kerberoast_bulk_spns.max(1);
    if !fires {
        return None;
    }
    let (severity, score) = if weak_req >= 10 {
        (Severity::Critical, 90)
    } else if weak_req >= 3 || rc4 >= params.kerberoast_rc4_spns.max(1) {
        (Severity::High, 75)
    } else {
        (Severity::Medium, 50)
    };
    let mut evidence = Vec::new();
    if weak_req > 0 {
        evidence.push(format!(
            "asked for RC4/DES-only service tickets (the downgrade roasting tools request) for {weak_req} user-account SPN{}: {}",
            if weak_req == 1 { "" } else { "s" },
            list(&c.weak_req_spns)
        ));
    }
    if rc4 > 0 {
        evidence.push(format!(
            "received RC4-encrypted service tickets — crackable offline — for {rc4} user-account SPN{}: {}",
            if rc4 == 1 { "" } else { "s" },
            list(&c.rc4_ticket_spns)
        ));
    }
    evidence.push(format!(
        "{bulk} distinct user-account SPN{} requested across {} TGS-REQ{}",
        if bulk == 1 { "" } else { "s" },
        c.tgs_reqs,
        if c.tgs_reqs == 1 { "" } else { "s" }
    ));
    if !c.tgs_users.is_empty() {
        evidence.push(format!("requesting account: {}", list(&c.tgs_users)));
    }
    evidence.push(
        "a service ticket is encrypted with the service account's password hash, so each one can be cracked offline without touching the account".to_string(),
    );
    Some(finding(
        FindingKind::Kerberoasting,
        severity,
        score,
        format!(
            "Kerberoasting: {client} pulled tickets for {} service account{}",
            bulk.max(weak_req).max(rc4),
            if bulk.max(weak_req).max(rc4) == 1 {
                ""
            } else {
                "s"
            }
        ),
        client,
        kdc,
        Some(KERBEROS_PORT),
        &["T1558.003"],
        evidence,
        Some(u64::from(c.tgs_reqs)),
        c.span,
    ))
}

fn asrep_roasting(client: IpAddr, kdc: Option<IpAddr>, c: &ClientKrb) -> Option<Finding> {
    if c.asrep_roasted.is_empty() {
        return None;
    }
    let n = c.asrep_roasted.len();
    let (severity, score) = if n >= 5 {
        (Severity::Critical, 88)
    } else {
        (Severity::High, 72)
    };
    let names: Vec<String> = c
        .asrep_roasted
        .iter()
        .map(|(u, e)| format!("{u} ({})", kerberos::etype_name(*e)))
        .collect();
    let rc4 = c
        .asrep_roasted
        .values()
        .filter(|e| kerberos::is_rc4(**e))
        .count();
    let mut evidence = vec![
        format!(
            "the KDC answered AS-REQs that carried no pre-authentication with a valid AS-REP for {n} account{}: {}",
            if n == 1 { "" } else { "s" },
            list(&names)
        ),
        "the AS-REP's encrypted part is keyed with the account's password hash, so it can be cracked offline".to_string(),
    ];
    if rc4 > 0 {
        evidence.push(format!(
            "{rc4} of them came back RC4-encrypted, the fastest form to crack"
        ));
    }
    evidence.push(
        "fix: enable \"Kerberos pre-authentication\" on these accounts (clear DONT_REQ_PREAUTH)"
            .to_string(),
    );
    Some(finding(
        FindingKind::AsrepRoasting,
        severity,
        score,
        format!(
            "AS-REP roasting: {client} roasted {n} account{} without pre-auth",
            if n == 1 { "" } else { "s" }
        ),
        client,
        kdc,
        Some(KERBEROS_PORT),
        &["T1558.004"],
        evidence,
        Some(n as u64),
        c.span,
    ))
}

fn kerberos_user_enum(
    client: IpAddr,
    kdc: Option<IpAddr>,
    c: &ClientKrb,
    params: &IdentityParams,
) -> Option<Finding> {
    let names = c.nopreauth_names.len();
    if names < params.user_enum_names.max(1)
        || (c.principal_unknown as usize) < params.user_enum_unknown.max(1)
    {
        return None;
    }
    Some(finding(
        FindingKind::AdRecon,
        Severity::Medium,
        50,
        format!("AD recon: {client} enumerated {names} usernames over Kerberos"),
        client,
        kdc,
        Some(KERBEROS_PORT),
        &["T1087.002"],
        vec![
            format!(
                "{names} distinct usernames tried in AS-REQs without pre-authentication; {} answered \"principal unknown\"",
                c.principal_unknown
            ),
            format!("examples of names that do not exist: {}", list(&c.unknown_names)),
            "the KDC's error code tells valid from invalid usernames without a single failed logon being recorded — the kerbrute userenum pattern".to_string(),
        ],
        Some(names as u64),
        c.span,
    ))
}

fn legacy_auth(kdc: IpAddr, k: &KdcWeak) -> Finding {
    let des = k.des.len();
    let rc4 = k.rc4_despite_aes.len();
    let (severity, score) = if des > 0 {
        (Severity::High, 65)
    } else {
        (Severity::Medium, 45)
    };
    let mut evidence = Vec::new();
    if des > 0 {
        let names: Vec<String> = k
            .des
            .iter()
            .map(|(p, e)| format!("{p} ({})", kerberos::etype_name(*e)))
            .collect();
        evidence.push(format!(
            "issued DES-encrypted Kerberos material for {des} principal{}: {} — DES keys are brute-forceable outright",
            if des == 1 { "" } else { "s" },
            list(&names)
        ));
    }
    if rc4 > 0 {
        evidence.push(format!(
            "issued RC4 service tickets although the client offered AES, so these service accounts have no AES keys: {}",
            list(&k.rc4_despite_aes)
        ));
    }
    evidence.push(
        "fix: reset the listed service-account passwords (creates AES keys) and remove DES/RC4 from msDS-SupportedEncryptionTypes".to_string(),
    );
    finding(
        FindingKind::LegacyAuth,
        severity,
        score,
        format!(
            "Legacy Kerberos crypto: KDC {kdc} issued {} weak ticket{}",
            des + rc4,
            if des + rc4 == 1 { "" } else { "s" }
        ),
        kdc,
        None,
        Some(KERBEROS_PORT),
        &["T1558"],
        evidence,
        Some((des + rc4) as u64),
        k.span,
    )
}

fn dcsync(
    client: IpAddr,
    server: IpAddr,
    port: u16,
    p: &RpcPair,
    dcs: &BTreeSet<IpAddr>,
    params: &IdentityParams,
) -> Option<Finding> {
    let calls = p.ops.get(&(Iface::Drsuapi, 3)).copied().unwrap_or(0);
    if calls == 0 || dcs.contains(&client) {
        return None;
    }
    let configured = params.domain_controllers.contains(&server);
    let evidence = vec![
        format!("bound the DRSUAPI (directory replication) interface on {server}:{port}"),
        format!(
            "called DRSGetNCChanges {calls} time{} — the replication call that returns password hashes, including krbtgt's",
            if calls == 1 { "" } else { "s" }
        ),
        format!(
            "{server} is a domain controller ({}); {client} never acted as one in this capture",
            if configured {
                "configured"
            } else {
                "inferred from Kerberos / DRSUAPI traffic"
            }
        ),
        "the RPC interface and operation number sit in the PDU header, so this is visible even when the call itself is encrypted".to_string(),
        "benign only for a real replication partner or a directory-sync server (e.g. Entra/Azure AD Connect): add it with --dc or mark this finding benign".to_string(),
    ];
    Some(finding(
        FindingKind::DcSync,
        Severity::Critical,
        95,
        format!("DCSync: {client} replicated secrets from DC {server}"),
        client,
        Some(server),
        Some(port),
        &["T1003.006"],
        evidence,
        Some(u64::from(calls)),
        p.span,
    ))
}

fn rpc_recon(
    client: IpAddr,
    server: IpAddr,
    port: u16,
    p: &RpcPair,
    params: &IdentityParams,
) -> Option<Finding> {
    let enum_ops: Vec<(Iface, u16, u32)> = p
        .ops
        .iter()
        .filter(|((i, op), _)| i.is_enumeration(*op))
        .map(|((i, op), n)| (*i, *op, *n))
        .collect();
    let total: u32 = enum_ops.iter().map(|(_, _, n)| n).sum();
    if total < params.rpc_enum_calls.max(1) {
        return None;
    }
    let calls: Vec<String> = enum_ops
        .iter()
        .map(|(i, op, n)| format!("{} {}×{n}", i.name(), i.op_name(*op).unwrap_or("call")))
        .collect();
    let groups = enum_ops
        .iter()
        .any(|(i, op, _)| *i == Iface::Samr && matches!(op, 11 | 15 | 25 | 33));
    let mut attack = vec!["T1087.002"];
    if groups {
        attack.push("T1069.002");
    }
    Some(finding(
        FindingKind::AdRecon,
        Severity::Medium,
        48,
        format!("AD recon: {client} enumerated accounts over RPC on {server}"),
        client,
        Some(server),
        Some(port),
        &attack,
        vec![
            format!("{total} directory enumeration calls: {}", list(&calls)),
            "bulk SAMR/LSA enumeration from a workstation is how BloodHound-style collectors and net user /domain map the domain".to_string(),
        ],
        Some(u64::from(total)),
        p.span,
    ))
}

fn ldap_recon(client: IpAddr, server: IpAddr, port: u16, p: &LdapPair) -> Finding {
    let n = p.recon.len();
    let score = if n >= 3 { 55 } else { 45 };
    let mut evidence: Vec<String> = p
        .recon
        .iter()
        .map(|(cat, filter)| format!("searched for {cat}: {filter}"))
        .collect();
    evidence.push(format!(
        "{} cleartext LDAP search{} in total",
        p.searches,
        if p.searches == 1 { "" } else { "es" }
    ));
    let groups = p.recon.keys().any(|c| c.contains("group"));
    let mut attack = vec!["T1087.002"];
    if groups {
        attack.push("T1069.002");
    }
    finding(
        FindingKind::AdRecon,
        Severity::Medium,
        score,
        format!(
            "AD recon: {client} ran {n} attack-prep LDAP quer{} on {server}",
            if n == 1 { "y" } else { "ies" }
        ),
        client,
        Some(server),
        Some(port),
        &attack,
        evidence,
        Some(u64::from(p.searches)),
        p.span,
    )
}

/// PsExec / schtasks-style remote execution: a service created and started, or a task registered,
/// over the RPC that rides an SMB named pipe.
fn remote_service_exec(
    client: IpAddr,
    server: IpAddr,
    port: u16,
    p: &RpcPair,
    smb: Option<&SmbAuth>,
) -> Option<Finding> {
    let op = |iface: Iface, opnum: u16| p.ops.get(&(iface, opnum)).copied().unwrap_or(0);
    let svc_create = op(Iface::Svcctl, 12) + op(Iface::Svcctl, 24);
    let svc_start = op(Iface::Svcctl, 19);
    let task_register = op(Iface::TaskScheduler, 0) + op(Iface::TaskScheduler, 1);
    let service_exec = svc_create > 0 && svc_start > 0;
    if !service_exec && task_register == 0 {
        return None;
    }

    // T1021.002 (SMB / Windows admin shares) applies only when the RPC rode an SMB named pipe;
    // the same calls over raw ncacn_ip_tcp are service/task execution without an admin-share hop.
    let mut attack = Vec::new();
    if p.over_smb {
        attack.push("T1021.002");
    }
    let channel = if p.over_smb {
        "over a named pipe"
    } else {
        "over RPC"
    };
    let mut evidence = Vec::new();
    if service_exec {
        attack.push("T1569.002"); // service execution
        evidence.push(format!(
            "created a Windows service on {server} {channel} (SVCCTL RCreateService) and started it (RStartServiceW) — the PsExec execution pattern"
        ));
    }
    if task_register > 0 {
        attack.push("T1053.005"); // scheduled task
        evidence.push(format!(
            "registered a scheduled task on {server} {channel} ({task_register} call{}) — the at / schtasks execution pattern",
            if task_register == 1 { "" } else { "s" }
        ));
    }
    if let Some(shares) = smb.filter(|s| !s.admin_shares.is_empty()) {
        evidence.push(format!(
            "reached the administrative share{} {} on the same host — where the payload is dropped",
            if shares.admin_shares.len() == 1 {
                ""
            } else {
                "s"
            },
            list(&shares.admin_shares)
        ));
    }
    evidence.push(
        "the interface and operation number are in the RPC header, so this is visible even when the call is encrypted; a payload body is never read".to_string(),
    );
    evidence.push(
        "benign for a software-deployment or remote-admin tool (SCCM, a configuration manager); mark it benign if that is what this host does".to_string(),
    );

    let how = if service_exec && task_register > 0 {
        "a service and a scheduled task"
    } else if service_exec {
        "a service"
    } else {
        "a scheduled task"
    };
    Some(finding(
        FindingKind::RemoteServiceExec,
        Severity::High,
        78,
        format!("Remote execution: {client} ran {how} on {server}"),
        client,
        Some(server),
        Some(port),
        &attack,
        evidence,
        Some(u64::from(svc_create + svc_start + task_register)),
        p.span,
    ))
}

/// Password spraying over SMB: logons failing across many distinct accounts from one host.
fn password_spray(
    client: IpAddr,
    server: IpAddr,
    a: &SmbAuth,
    params: &IdentityParams,
) -> Option<Finding> {
    let failed = a.failed_users.len();
    if failed < params.smb_spray_users.max(1) {
        return None;
    }
    let (severity, score) = if failed >= 10 {
        (Severity::High, 70)
    } else {
        (Severity::Medium, 52)
    };
    let mut evidence = vec![
        format!(
            "{failed} distinct account{} failed SMB logon from this host: {}",
            if failed == 1 { "" } else { "s" },
            list(&a.failed_users)
        ),
        format!(
            "{} session-setup attempt{} in total, {} succeeded",
            a.attempts,
            if a.attempts == 1 { "" } else { "s" },
            a.ok_users.len()
        ),
        "one or a few passwords tried against many accounts is the spray pattern that stays under each account's lockout threshold".to_string(),
    ];
    if !a.ok_users.is_empty() {
        evidence.push(format!(
            "accounts that then succeeded: {}",
            list(&a.ok_users)
        ));
    }
    Some(finding(
        FindingKind::PasswordSpray,
        severity,
        score,
        format!("Password spray: {client} failed SMB logon for {failed} accounts on {server}"),
        client,
        Some(server),
        Some(445),
        &["T1110.003"],
        evidence,
        Some(failed as u64),
        a.span,
    ))
}

/// Legacy SMB authentication: NTLMv1 / LM responses, or the obsolete SMB1 dialect.
fn smb_legacy_auth(client: IpAddr, server: IpAddr, a: &SmbAuth) -> Option<Finding> {
    let v1 = a.ntlm_v1_users.len();
    if v1 == 0 && !a.smb1 {
        return None;
    }
    let (severity, score) = if v1 > 0 {
        (Severity::High, 62)
    } else {
        (Severity::Medium, 45)
    };
    let mut evidence = Vec::new();
    if v1 > 0 {
        evidence.push(format!(
            "{v1} account{} authenticated to {server} over SMB with an NTLMv1/LM response — keyed directly from the password hash and crackable far faster than NTLMv2: {}",
            if v1 == 1 { "" } else { "s" },
            list(&a.ntlm_v1_users)
        ));
        evidence.push(
            "fix: set the domain \"LAN Manager authentication level\" to refuse LM and NTLMv1 (send NTLMv2 only)".to_string(),
        );
    }
    if a.smb1 {
        evidence.push(
            "the obsolete SMB1 dialect was negotiated — it has no modern signing or encryption and carries NTLMv1; fix: disable SMB1 on client and server".to_string(),
        );
    }
    finding(
        FindingKind::LegacyAuth,
        severity,
        score,
        if v1 > 0 {
            format!("Legacy SMB auth: NTLMv1 to {server} from {client}")
        } else {
            format!("Legacy SMB auth: SMB1 dialect to {server} from {client}")
        },
        client,
        Some(server),
        Some(445),
        &[],
        evidence,
        Some((v1 + usize::from(a.smb1)) as u64),
        a.span,
    )
    .into()
}

#[cfg(test)]
mod tests;
