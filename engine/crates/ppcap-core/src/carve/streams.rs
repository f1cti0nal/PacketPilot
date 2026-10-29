//! File carving beyond HTTP: FTP data transfers, SMTP and POP3 mail attachments, and SMB2 file
//! reads and writes.
//!
//! The rules are the HTTP carver's: TCP is followed strictly in order (a gap drops the file rather
//! than hashing wrong bytes), every table is capped, and each file streams through a
//! [`CarveSink`] (hash, content signatures, YARA, opt-in extraction) without being buffered.
//!
//! - **FTP** — the control channel (port 21) announces data endpoints (`PASV`/`EPSV` replies,
//!   `PORT`/`EPRT` commands) and names the transfer (`RETR`, `STOR`, `APPE`, `STOU`). The data
//!   connection must be seen from its SYN; the file is complete at the sender's FIN. Directory
//!   listings are not carved, and `AUTH TLS` ends the session.
//! - **SMTP** (25/587/2525) and **POP3** (110) — the message after `DATA`/`354`, or a `RETR`'s
//!   `+OK`, is dot-unstuffed and parsed as MIME: nested multiparts, base64 and quoted-printable.
//!   A part is carved when it has a filename, is an attachment, or is not text. `STARTTLS`/`STLS`
//!   and `BDAT` end the session.
//! - **SMB2** (445) — `CREATE` names a file (prefixed with its share), `READ` responses and `WRITE`
//!   requests carry its bytes, `CLOSE` finishes it. Only a file read or written contiguously from
//!   offset 0 to its end is emitted. `IPC$` pipes, encrypted and compressed messages are skipped.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;

use super::{finish_file, CarveObservation, CarveSink, FileInfo, Opener};
use crate::model::packet::PacketMeta;

const TCP_FIN: u8 = 0x01;
const TCP_SYN: u8 = 0x02;
const TCP_RST: u8 = 0x04;
const TCP_ACK: u8 = 0x10;

/// Concurrent sessions (control and data connections each).
const MAX_SESSIONS: usize = 256;
/// Announced FTP data endpoints waiting for their connection.
const MAX_EXPECT: usize = 256;
/// A session idle this long may be evicted when the table is full.
const IDLE_NS: i64 = 120_000_000_000;
/// Longest protocol line kept while waiting for its end.
const MAX_LINE: usize = 16 * 1024;
/// Largest MIME header block kept for one part.
const MAX_MIME_HEADER: usize = 16 * 1024;
/// Files carved from one mail message.
const MAX_PARTS: usize = 64;
/// Multipart nesting followed.
const MAX_DEPTH: usize = 8;
/// POP3 commands awaiting a reply.
const MAX_POP_QUEUE: usize = 64;
/// SMB2 bytes read before deciding how to handle a record.
const SMB_HEAD: usize = 112;
/// Largest SMB2 record buffered whole (anything bigger is a READ/WRITE stream or skipped).
const MAX_SMB_RECORD: usize = 16 * 1024;
/// Outstanding SMB2 requests remembered per connection.
const MAX_SMB_PENDING: usize = 1024;
/// Open SMB2 files and trees tracked per connection.
const MAX_SMB_FILES: usize = 256;

/// `(client, client port, server, server port)`.
type Key = (IpAddr, u16, IpAddr, u16);

const C2S: usize = 0;
const S2C: usize = 1;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Service {
    Ftp,
    Smtp,
    Pop3,
    Smb,
}

fn service(port: u16) -> Option<Service> {
    Some(match port {
        21 => Service::Ftp,
        25 | 587 | 2525 => Service::Smtp,
        110 => Service::Pop3,
        445 => Service::Smb,
        _ => return None,
    })
}

/// In-order position in one direction of a TCP stream.
#[derive(Default)]
struct Cursor {
    next: Option<u32>,
    dead: bool,
}

impl Cursor {
    fn syn(&mut self, seq: u32) {
        if self.next.is_none() {
            self.next = Some(seq.wrapping_add(1));
        }
    }

    /// The fresh in-order bytes of a segment: `None` for a pure retransmit, and after a gap (which
    /// also kills the cursor). Without a SYN the first segment starts the stream when `may_start`.
    fn take<'p>(&mut self, seq: u32, payload: &'p [u8], may_start: bool) -> Option<&'p [u8]> {
        if self.dead || payload.is_empty() {
            return None;
        }
        let next = match self.next {
            Some(n) => n,
            None if may_start => seq,
            None => {
                self.dead = true;
                return None;
            }
        };
        let ahead = seq.wrapping_sub(next);
        if ahead != 0 && ahead < 0x8000_0000 {
            self.dead = true;
            return None;
        }
        let behind = next.wrapping_sub(seq) as usize;
        if behind >= payload.len() {
            return None;
        }
        let fresh = &payload[behind..];
        self.next = Some(next.wrapping_add(fresh.len() as u32));
        Some(fresh)
    }

    /// Whether a FIN at `seq` (after `len` payload bytes) closes a stream seen without gaps.
    fn fin_complete(&self, seq: u32, len: usize) -> bool {
        !self.dead && self.next == Some(seq.wrapping_add(len as u32))
    }
}

/// Per-packet context handed to the protocol parsers.
struct Ctx<'o, 'a> {
    open: &'o mut Opener<'a>,
    done: &'o mut Vec<CarveObservation>,
    client: IpAddr,
    server: IpAddr,
    ts: i64,
    /// FTP data endpoints announced by this packet.
    expect: Vec<(IpAddr, u16)>,
}

/// A file being carved.
struct OpenFile {
    sink: CarveSink,
    name: Option<String>,
    upload: bool,
    first_ts: i64,
}

impl Ctx<'_, '_> {
    fn open(&mut self, name: Option<String>, upload: bool) -> OpenFile {
        OpenFile {
            sink: self.open.sink(),
            name,
            upload,
            first_ts: self.ts,
        }
    }

    fn close(&mut self, f: OpenFile, protocol: &'static str) {
        let info = FileInfo {
            client: self.client,
            server: self.server,
            protocol,
            filename: f.name,
            upload: f.upload,
            first_ts_ns: f.first_ts,
            last_ts_ns: self.ts,
        };
        if let Some(obs) = finish_file(f.sink, info) {
            self.done.push(obs);
        }
    }
}

/// FTP, SMTP, POP3 and SMB2 sessions of one analysis pass.
pub(super) struct StreamCarver {
    sessions: HashMap<Key, Session>,
    /// FTP data connections, keyed by `(initiator, port, acceptor, port)`.
    data: HashMap<Key, DataSession>,
    /// Announced FTP data endpoints → (their control session, when announced).
    expect: HashMap<(IpAddr, u16), (Key, i64)>,
}

struct Session {
    cur: [Cursor; 2],
    fin: [bool; 2],
    last_ts: i64,
    proto: Proto,
}

enum Proto {
    Ftp(FtpCtl),
    Smtp(Smtp),
    Pop3(Pop3),
    Smb(Box<Smb>),
}

impl Proto {
    fn new(svc: Service) -> Proto {
        match svc {
            Service::Ftp => Proto::Ftp(FtpCtl::default()),
            Service::Smtp => Proto::Smtp(Smtp::default()),
            Service::Pop3 => Proto::Pop3(Pop3::default()),
            Service::Smb => Proto::Smb(Box::default()),
        }
    }

    fn feed(&mut self, d: usize, bytes: &[u8], cx: &mut Ctx<'_, '_>) {
        match self {
            Proto::Ftp(p) => p.feed(d, bytes, cx),
            Proto::Smtp(p) => p.feed(d, bytes, cx),
            Proto::Pop3(p) => p.feed(d, bytes, cx),
            Proto::Smb(p) => p.feed(d, bytes, cx),
        }
    }

    fn dead(&self) -> bool {
        match self {
            Proto::Ftp(p) => p.dead,
            Proto::Smtp(p) => matches!(p.phase, SmtpPhase::Dead),
            Proto::Pop3(p) => p.dead,
            Proto::Smb(p) => p.dead,
        }
    }
}

impl StreamCarver {
    pub(super) fn new() -> StreamCarver {
        StreamCarver {
            sessions: HashMap::new(),
            data: HashMap::new(),
            expect: HashMap::new(),
        }
    }

    /// Whether a TCP packet belongs to a carved protocol (cheap: two port matches on the common
    /// path, map lookups only while FTP data connections are expected or open).
    pub(super) fn wants(
        &self,
        meta: &PacketMeta,
        src: IpAddr,
        sport: u16,
        dst: IpAddr,
        dport: u16,
    ) -> bool {
        service(dport).is_some()
            || service(sport).is_some()
            || (!self.data.is_empty()
                && (self.data.contains_key(&(src, sport, dst, dport))
                    || self.data.contains_key(&(dst, dport, src, sport))))
            || (meta.tcp_flags & TCP_SYN != 0 && self.expect.contains_key(&(dst, dport)))
    }

    pub(super) fn observe(
        &mut self,
        meta: &PacketMeta,
        (src, sport, dst, dport): Key,
        seq: u32,
        payload: &[u8],
        open: &mut Opener<'_>,
        done: &mut Vec<CarveObservation>,
    ) {
        let flags = meta.tcp_flags;
        let ts = meta.ts_ns;
        let (key, d, svc) = if let Some(s) = service(dport) {
            ((src, sport, dst, dport), C2S, s)
        } else if let Some(s) = service(sport) {
            ((dst, dport, src, sport), S2C, s)
        } else {
            self.observe_data(meta, (src, sport, dst, dport), seq, payload, open, done);
            return;
        };
        if !self.sessions.contains_key(&key) {
            if flags & TCP_RST != 0 || (payload.is_empty() && flags & TCP_SYN == 0) {
                return;
            }
            if !make_room(&mut self.sessions, ts, |s| s.last_ts) {
                return;
            }
            self.sessions.insert(
                key,
                Session {
                    cur: Default::default(),
                    fin: [false; 2],
                    last_ts: ts,
                    proto: Proto::new(svc),
                },
            );
        }
        let Some(s) = self.sessions.get_mut(&key) else {
            return;
        };
        s.last_ts = ts;
        if flags & TCP_RST != 0 {
            self.sessions.remove(&key);
            return;
        }
        if flags & TCP_SYN != 0 {
            s.cur[d].syn(seq);
        }
        let mut expect = Vec::new();
        // A dead session (TLS, lost framing) stays as a tombstone until it closes, so its later
        // packets don't restart parsing mid-stream.
        let fresh = if s.proto.dead() {
            None
        } else {
            s.cur[d].take(seq, payload, true)
        };
        if let Some(fresh) = fresh {
            let mut cx = Ctx {
                open,
                done,
                client: key.0,
                server: key.2,
                ts,
                expect: Vec::new(),
            };
            s.proto.feed(d, fresh, &mut cx);
            expect = cx.expect;
        }
        if flags & TCP_FIN != 0 {
            s.fin[d] = true;
        }
        if s.fin[C2S] && s.fin[S2C] {
            self.sessions.remove(&key);
        }
        for ep in expect {
            if self.expect.len() >= MAX_EXPECT {
                self.expect
                    .retain(|_, (_, t)| ts.saturating_sub(*t) <= IDLE_NS);
            }
            if self.expect.len() < MAX_EXPECT {
                self.expect.insert(ep, (key, ts));
            }
        }
    }

    /// An FTP data connection: opened by a SYN to an announced endpoint, bound to its control
    /// session's pending transfer when the first bytes arrive, complete at the sender's FIN.
    fn observe_data(
        &mut self,
        meta: &PacketMeta,
        (src, sport, dst, dport): Key,
        seq: u32,
        payload: &[u8],
        open: &mut Opener<'_>,
        done: &mut Vec<CarveObservation>,
    ) {
        let flags = meta.tcp_flags;
        let ts = meta.ts_ns;
        if flags & TCP_SYN != 0 && flags & TCP_ACK == 0 {
            if let Some((control, _)) = self.expect.remove(&(dst, dport)) {
                if make_room(&mut self.data, ts, |s| s.last_ts) {
                    self.data.insert(
                        (src, sport, dst, dport),
                        DataSession {
                            cur: Default::default(),
                            control,
                            last_ts: ts,
                            state: DataState::Unbound,
                        },
                    );
                }
            }
        }
        let (key, d) = if self.data.contains_key(&(src, sport, dst, dport)) {
            ((src, sport, dst, dport), C2S)
        } else if self.data.contains_key(&(dst, dport, src, sport)) {
            ((dst, dport, src, sport), S2C)
        } else {
            return;
        };
        if flags & TCP_RST != 0 {
            self.data.remove(&key);
            return;
        }
        let Some(s) = self.data.get_mut(&key) else {
            return;
        };
        s.last_ts = ts;
        if flags & TCP_SYN != 0 {
            s.cur[d].syn(seq);
        }
        if matches!(s.state, DataState::Unbound) && !payload.is_empty() {
            let control = s.control;
            let xfer = match self.sessions.get_mut(&control) {
                Some(Session {
                    proto: Proto::Ftp(c),
                    ..
                }) => c.pending.take(),
                _ => None,
            };
            let Some(s) = self.data.get_mut(&key) else {
                return;
            };
            s.state = match xfer {
                Some(x) if x.carve => {
                    let mut cx = Ctx {
                        open: &mut *open,
                        done: &mut *done,
                        client: control.0,
                        server: control.2,
                        ts,
                        expect: Vec::new(),
                    };
                    DataState::Carving {
                        sender: d,
                        file: Box::new(cx.open(x.name, x.upload)),
                    }
                }
                _ => DataState::Ignore,
            };
        }
        let Some(s) = self.data.get_mut(&key) else {
            return;
        };
        let remove = match &mut s.state {
            DataState::Unbound => false,
            DataState::Ignore => true,
            DataState::Carving { sender, file } => {
                if *sender != d {
                    false
                } else {
                    if let Some(fresh) = s.cur[d].take(seq, payload, false) {
                        file.sink.feed(fresh);
                    }
                    if s.cur[d].dead {
                        true
                    } else if flags & TCP_FIN != 0 {
                        if s.cur[d].fin_complete(seq, payload.len()) {
                            let control = s.control;
                            if let DataState::Carving { file, .. } =
                                std::mem::replace(&mut s.state, DataState::Ignore)
                            {
                                let mut cx = Ctx {
                                    open: &mut *open,
                                    done: &mut *done,
                                    client: control.0,
                                    server: control.2,
                                    ts,
                                    expect: Vec::new(),
                                };
                                cx.close(*file, "ftp");
                            }
                        }
                        true
                    } else {
                        false
                    }
                }
            }
        };
        if remove {
            self.data.remove(&key);
        }
    }
}

/// Free a slot in a full table by dropping its stalest entry idle past [`IDLE_NS`]; `false` when
/// the table stays full.
fn make_room<V>(map: &mut HashMap<Key, V>, now: i64, last: impl Fn(&V) -> i64) -> bool {
    if map.len() < MAX_SESSIONS {
        return true;
    }
    let stale = map
        .iter()
        .filter(|(_, v)| now.saturating_sub(last(v)) > IDLE_NS)
        .min_by_key(|(_, v)| last(v))
        .map(|(k, _)| *k);
    match stale {
        Some(k) => {
            map.remove(&k);
            true
        }
        None => false,
    }
}

// ── lines ───────────────────────────────────────────────────────────────────────────────────────

/// Splits a byte stream into lines (without their line ending), keeping one partial line.
#[derive(Default)]
struct LineBuf {
    buf: Vec<u8>,
}

impl LineBuf {
    /// Calls `f` on each complete line. `false` once a line outgrows [`MAX_LINE`].
    fn feed(&mut self, mut bytes: &[u8], mut f: impl FnMut(&[u8])) -> bool {
        while let Some(i) = bytes.iter().position(|&b| b == b'\n') {
            if self.buf.is_empty() {
                f(trim_cr(&bytes[..i]));
            } else {
                self.buf.extend_from_slice(&bytes[..i]);
                f(trim_cr(&self.buf));
                self.buf.clear();
            }
            bytes = &bytes[i + 1..];
        }
        self.buf.extend_from_slice(bytes);
        self.buf.len() <= MAX_LINE
    }
}

fn trim_cr(line: &[u8]) -> &[u8] {
    line.strip_suffix(b"\r").unwrap_or(line)
}

/// A command line's verb (upper-cased) and its argument.
fn split_cmd(line: &[u8]) -> (String, String) {
    let text = String::from_utf8_lossy(line);
    let text = text.trim();
    let (verb, arg) = text.split_once(' ').unwrap_or((text, ""));
    (verb.to_ascii_uppercase(), arg.trim().to_string())
}

/// A sender-supplied name made safe to show: control characters removed, at most 256 characters.
fn clean_name(s: &str) -> Option<String> {
    let t: String = s.chars().filter(|c| !c.is_control()).take(256).collect();
    let t = t.trim();
    (!t.is_empty()).then(|| t.to_string())
}

// ── FTP ─────────────────────────────────────────────────────────────────────────────────────────

#[derive(Default)]
struct FtpCtl {
    lines: [LineBuf; 2],
    /// The transfer the next data connection carries.
    pending: Option<Xfer>,
    dead: bool,
}

struct Xfer {
    name: Option<String>,
    upload: bool,
    /// `false` for a directory listing.
    carve: bool,
}

impl FtpCtl {
    fn feed(&mut self, d: usize, bytes: &[u8], cx: &mut Ctx<'_, '_>) {
        let FtpCtl {
            lines,
            pending,
            dead,
        } = self;
        let ok = lines[d].feed(bytes, |line| {
            if d == C2S {
                let (verb, arg) = split_cmd(line);
                let xfer = |upload, carve| {
                    Some(Xfer {
                        name: clean_name(&arg),
                        upload,
                        carve,
                    })
                };
                match verb.as_str() {
                    "RETR" => *pending = xfer(false, true),
                    "STOR" | "APPE" | "STOU" => *pending = xfer(true, true),
                    "LIST" | "NLST" | "MLSD" => *pending = xfer(false, false),
                    "PORT" => {
                        if let Some(ep) = port_tuple(&arg) {
                            cx.expect.push(ep);
                            cx.expect.push((cx.client, ep.1));
                        }
                    }
                    "EPRT" => {
                        if let Some(ep) = eprt(&arg) {
                            cx.expect.push(ep);
                            cx.expect.push((cx.client, ep.1));
                        }
                    }
                    "AUTH" | "CCC" => *dead = true,
                    _ => {}
                }
            } else if let Some(rest) = line.strip_prefix(b"227") {
                let text = String::from_utf8_lossy(rest);
                let inner = text.split_once('(').map_or(&*text, |(_, r)| r);
                if let Some(ep) = port_tuple(inner) {
                    cx.expect.push((cx.server, ep.1));
                    if ep.0 != cx.server {
                        cx.expect.push(ep);
                    }
                }
            } else if let Some(rest) = line.strip_prefix(b"229") {
                if let Some(port) = epsv_port(&String::from_utf8_lossy(rest)) {
                    cx.expect.push((cx.server, port));
                }
            }
        });
        if !ok {
            self.dead = true;
        }
    }
}

/// `h1,h2,h3,h4,p1,p2` (PORT and PASV) → its endpoint.
fn port_tuple(s: &str) -> Option<(IpAddr, u16)> {
    let nums: Vec<u8> = s
        .split(|c: char| !c.is_ascii_digit() && c != ',')
        .find(|t| t.matches(',').count() == 5)?
        .split(',')
        .map(|n| n.parse().ok())
        .collect::<Option<_>>()?;
    let ip = IpAddr::from([nums[0], nums[1], nums[2], nums[3]]);
    Some((ip, u16::from(nums[4]) << 8 | u16::from(nums[5])))
}

/// `|1|ip|port|` or `|2|ip6|port|` (EPRT).
fn eprt(s: &str) -> Option<(IpAddr, u16)> {
    let delim = s.chars().next()?;
    let f: Vec<&str> = s.split(delim).collect();
    Some((f.get(2)?.parse().ok()?, f.get(3)?.parse().ok()?))
}

/// The port of `229 Entering Extended Passive Mode (|||port|)`.
fn epsv_port(s: &str) -> Option<u16> {
    let inner = s.split_once('(')?.1;
    let delim = inner.chars().next()?;
    inner.split(delim).nth(3)?.parse().ok()
}

struct DataSession {
    cur: [Cursor; 2],
    control: Key,
    last_ts: i64,
    state: DataState,
}

enum DataState {
    /// No bytes yet: the transfer isn't known.
    Unbound,
    /// A listing, or no transfer was pending.
    Ignore,
    Carving {
        sender: usize,
        file: Box<OpenFile>,
    },
}

// ── SMTP / POP3 ─────────────────────────────────────────────────────────────────────────────────

#[derive(Default)]
struct Smtp {
    lines: [LineBuf; 2],
    phase: SmtpPhase,
    msg: Option<Mime>,
}

#[derive(Default, Clone, Copy, PartialEq, Eq)]
enum SmtpPhase {
    #[default]
    Cmd,
    /// `DATA` sent, waiting for `354`.
    AwaitData,
    Data,
    Dead,
}

impl Smtp {
    fn feed(&mut self, d: usize, bytes: &[u8], cx: &mut Ctx<'_, '_>) {
        let Smtp { lines, phase, msg } = self;
        let ok = lines[d].feed(bytes, |line| match (d, *phase) {
            (C2S, SmtpPhase::Cmd) => match split_cmd(line).0.as_str() {
                "DATA" => *phase = SmtpPhase::AwaitData,
                "BDAT" | "STARTTLS" => *phase = SmtpPhase::Dead,
                _ => {}
            },
            (C2S, SmtpPhase::Data) => {
                if line == b"." {
                    if let Some(m) = msg.take() {
                        m.end(cx);
                    }
                    *phase = SmtpPhase::Cmd;
                } else if let Some(m) = msg.as_mut() {
                    m.line(line.strip_prefix(b".").unwrap_or(line), cx);
                }
            }
            (S2C, SmtpPhase::AwaitData) => {
                if line.starts_with(b"354") {
                    *phase = SmtpPhase::Data;
                    *msg = Some(Mime::new("smtp", true));
                } else if matches!(line.first(), Some(b'4' | b'5')) {
                    *phase = SmtpPhase::Cmd;
                }
            }
            _ => {}
        });
        if !ok {
            self.phase = SmtpPhase::Dead;
        }
    }
}

#[derive(Default)]
struct Pop3 {
    lines: [LineBuf; 2],
    queue: VecDeque<PopCmd>,
    /// Inside a SASL exchange: client lines are not commands.
    auth: bool,
    /// Inside a multi-line reply; `Some(mime)` when it is a `RETR` being carved.
    multi: Option<Option<Mime>>,
    dead: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PopCmd {
    Single,
    Multi,
    Retr,
    Stls,
}

impl Pop3 {
    fn feed(&mut self, d: usize, bytes: &[u8], cx: &mut Ctx<'_, '_>) {
        let Pop3 {
            lines,
            queue,
            auth,
            multi,
            dead,
        } = self;
        let ok = lines[d].feed(bytes, |line| {
            if d == C2S {
                if *auth {
                    return;
                }
                let (verb, arg) = split_cmd(line);
                let cmd = match verb.as_str() {
                    "RETR" => PopCmd::Retr,
                    "TOP" | "CAPA" => PopCmd::Multi,
                    "LIST" | "UIDL" if arg.is_empty() => PopCmd::Multi,
                    "STLS" => PopCmd::Stls,
                    "AUTH" => {
                        *auth = true;
                        PopCmd::Single
                    }
                    _ => PopCmd::Single,
                };
                if queue.len() >= MAX_POP_QUEUE {
                    *dead = true;
                } else {
                    queue.push_back(cmd);
                }
                return;
            }
            if let Some(m) = multi.as_mut() {
                if line == b"." {
                    if let Some(Some(mime)) = multi.take() {
                        mime.end(cx);
                    }
                } else if let Some(mime) = m.as_mut() {
                    mime.line(line.strip_prefix(b".").unwrap_or(line), cx);
                }
            } else if line.starts_with(b"+OK") {
                if std::mem::take(auth) {
                    queue.pop_front();
                    return;
                }
                match queue.pop_front() {
                    Some(PopCmd::Retr) => *multi = Some(Some(Mime::new("pop3", false))),
                    Some(PopCmd::Multi) => *multi = Some(None),
                    Some(PopCmd::Stls) => *dead = true,
                    _ => {}
                }
            } else if line.starts_with(b"-ERR") {
                *auth = false;
                queue.pop_front();
            }
        });
        if !ok {
            self.dead = true;
        }
    }
}

/// A streaming MIME parser over one message's (dot-unstuffed) lines.
struct Mime {
    protocol: &'static str,
    upload: bool,
    /// Open multipart delimiters (`--boundary`), outermost first.
    bounds: Vec<Vec<u8>>,
    part: Part,
    files: usize,
}

enum Part {
    /// Collecting a header block (unfolded, `\n`-separated).
    Head(Vec<u8>),
    /// A body being carved.
    Leaf(Box<Leaf>),
    /// A preamble, epilogue, or body not carved.
    Skip,
}

struct Leaf {
    file: OpenFile,
    cte: Cte,
    /// A hard line break is owed before the next line (it belongs to the body only if one follows).
    crlf: bool,
    b64: B64,
}

#[derive(Clone, Copy, PartialEq, Eq, Default)]
enum Cte {
    #[default]
    Raw,
    Base64,
    Qp,
}

impl Mime {
    fn new(protocol: &'static str, upload: bool) -> Mime {
        Mime {
            protocol,
            upload,
            bounds: Vec::new(),
            part: Part::Head(Vec::new()),
            files: 0,
        }
    }

    fn line(&mut self, line: &[u8], cx: &mut Ctx<'_, '_>) {
        if !self.bounds.is_empty() && line.starts_with(b"--") {
            let t = trim_ws_end(line);
            if let Some(k) = self.bounds.iter().rposition(|b| t.starts_with(b)) {
                let rest = &t[self.bounds[k].len()..];
                if rest.is_empty() || rest == b"--" {
                    self.close_leaf(true, cx);
                    if rest.is_empty() {
                        self.bounds.truncate(k + 1);
                        self.part = Part::Head(Vec::new());
                    } else {
                        self.bounds.truncate(k);
                        self.part = Part::Skip;
                    }
                    return;
                }
            }
        }
        match &mut self.part {
            Part::Head(h) => {
                if line.is_empty() {
                    let h = std::mem::take(h);
                    self.begin_body(&h, cx);
                } else if h.len() + line.len() < MAX_MIME_HEADER {
                    if !h.is_empty() && !matches!(line[0], b' ' | b'\t') {
                        h.push(b'\n');
                    }
                    h.extend_from_slice(line);
                }
            }
            Part::Leaf(l) => {
                if !l.feed(line) {
                    self.part = Part::Skip; // bad base64: drop the file
                }
            }
            Part::Skip => {}
        }
    }

    /// The message ended. Only a single-part body is complete here; a multipart missing its
    /// closing delimiter was cut short.
    fn end(mut self, cx: &mut Ctx<'_, '_>) {
        let complete = self.bounds.is_empty();
        self.close_leaf(complete, cx);
    }

    fn close_leaf(&mut self, complete: bool, cx: &mut Ctx<'_, '_>) {
        if let Part::Leaf(mut l) = std::mem::replace(&mut self.part, Part::Skip) {
            if complete && (l.cte != Cte::Base64 || l.b64.finish(&mut l.file.sink)) {
                cx.close(l.file, self.protocol);
            }
        }
    }

    fn begin_body(&mut self, head: &[u8], cx: &mut Ctx<'_, '_>) {
        let h = MimeHeaders::parse(head);
        self.part = Part::Skip;
        if h.ctype.starts_with("multipart/") {
            if let Some(b) = h.boundary.filter(|_| self.bounds.len() < MAX_DEPTH) {
                self.bounds.push(format!("--{b}").into_bytes());
            }
            return;
        }
        let name = h.filename.or(h.name);
        let typed = !(h.ctype.is_empty()
            || h.ctype.starts_with("text/")
            || h.ctype.starts_with("message/"));
        if (name.is_some() || h.attachment || typed) && self.files < MAX_PARTS {
            self.files += 1;
            self.part = Part::Leaf(Box::new(Leaf {
                file: cx.open(name, self.upload),
                cte: h.cte,
                crlf: false,
                b64: B64::default(),
            }));
        }
    }
}

fn trim_ws_end(b: &[u8]) -> &[u8] {
    let n = b
        .iter()
        .rposition(|c| !matches!(c, b' ' | b'\t'))
        .map_or(0, |p| p + 1);
    &b[..n]
}

impl Leaf {
    /// Decode one body line into the file; `false` on malformed base64.
    fn feed(&mut self, line: &[u8]) -> bool {
        match self.cte {
            Cte::Base64 => return self.b64.feed(line, &mut self.file.sink),
            Cte::Qp => {
                if self.crlf {
                    self.file.sink.feed(b"\r\n");
                }
                let line = trim_ws_end(line);
                let (body, soft) = match line.strip_suffix(b"=") {
                    Some(b) => (b, true),
                    None => (line, false),
                };
                self.file.sink.feed(&qp_decode(body));
                self.crlf = !soft;
            }
            Cte::Raw => {
                if self.crlf {
                    self.file.sink.feed(b"\r\n");
                }
                self.file.sink.feed(line);
                self.crlf = true;
            }
        }
        true
    }
}

fn qp_decode(b: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'=' {
            if let Some(v) = b
                .get(i + 1..i + 3)
                .and_then(|h| std::str::from_utf8(h).ok())
                .and_then(|h| u8::from_str_radix(h, 16).ok())
            {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    out
}

/// Streaming base64: whitespace is skipped, padding ends a quantum (concatenated encodings
/// continue), anything else outside the alphabet is an error.
#[derive(Default)]
struct B64 {
    acc: u32,
    n: u8,
}

impl B64 {
    fn feed(&mut self, line: &[u8], sink: &mut CarveSink) -> bool {
        let mut out = Vec::with_capacity(line.len() / 4 * 3 + 3);
        let ok = line.iter().all(|&c| self.push(c, &mut out));
        sink.feed(&out);
        ok
    }

    /// Decode one character into `out`; `false` outside the alphabet.
    fn push(&mut self, c: u8, out: &mut Vec<u8>) -> bool {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => return self.flush(out),
            b' ' | b'\t' | b'\r' => return true,
            _ => return false,
        };
        self.acc = self.acc << 6 | u32::from(v);
        self.n += 1;
        if self.n == 4 {
            out.extend_from_slice(&self.acc.to_be_bytes()[1..]);
            self.acc = 0;
            self.n = 0;
        }
        true
    }

    /// Emit a partial final quantum; `false` if it can't be one (a single leftover character).
    fn flush(&mut self, out: &mut Vec<u8>) -> bool {
        match self.n {
            0 => {}
            2 => out.push((self.acc >> 4) as u8),
            3 => out.extend_from_slice(&((self.acc >> 2) as u16).to_be_bytes()),
            _ => return false,
        }
        self.acc = 0;
        self.n = 0;
        true
    }

    fn finish(&mut self, sink: &mut CarveSink) -> bool {
        let mut out = Vec::new();
        let ok = self.flush(&mut out);
        sink.feed(&out);
        ok
    }
}

#[derive(Default)]
struct MimeHeaders {
    /// Lower-cased `type/subtype`, empty when absent.
    ctype: String,
    boundary: Option<String>,
    /// `Content-Type` `name=`.
    name: Option<String>,
    /// `Content-Disposition` `filename=`.
    filename: Option<String>,
    attachment: bool,
    cte: Cte,
}

impl MimeHeaders {
    fn parse(head: &[u8]) -> MimeHeaders {
        let mut h = MimeHeaders::default();
        let text = String::from_utf8_lossy(head);
        for line in text.split('\n') {
            let Some((name, value)) = line.split_once(':') else {
                continue;
            };
            match name.trim().to_ascii_lowercase().as_str() {
                "content-type" => {
                    h.ctype = value
                        .split(';')
                        .next()
                        .unwrap_or("")
                        .trim()
                        .to_ascii_lowercase();
                    h.boundary = header_param(value, "boundary");
                    h.name = header_param(value, "name");
                }
                "content-disposition" => {
                    h.attachment = value
                        .trim_start()
                        .to_ascii_lowercase()
                        .starts_with("attachment");
                    h.filename = header_param(value, "filename");
                }
                "content-transfer-encoding" => {
                    h.cte = match value.trim().to_ascii_lowercase().as_str() {
                        "base64" => Cte::Base64,
                        "quoted-printable" => Cte::Qp,
                        _ => Cte::Raw,
                    }
                }
                _ => {}
            }
        }
        h
    }
}

/// A parameter of a structured header value (`type; key="value"; …`): quoted or bare, RFC 2231
/// `key*=charset''percent-encoded` preferred, RFC 2047 encoded words decoded. Cleaned for display.
pub(super) fn header_param(value: &str, key: &str) -> Option<String> {
    let mut plain = None;
    for part in split_params(value).into_iter().skip(1) {
        let Some((k, v)) = part.split_once('=') else {
            continue;
        };
        let k = k.trim().to_ascii_lowercase();
        let v = v.trim();
        if k.strip_suffix('*') == Some(key) {
            let encoded = v.splitn(3, '\'').nth(2).unwrap_or(v);
            return clean_name(&String::from_utf8_lossy(&percent_decode(
                unquote(encoded).as_bytes(),
            )));
        }
        if k == key && plain.is_none() {
            plain = Some(decode_words(&unquote(v)));
        }
    }
    plain.and_then(|p| clean_name(&p))
}

/// Split on `;` outside double quotes.
fn split_params(v: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let (mut start, mut quoted, mut escaped) = (0, false, false);
    for (i, c) in v.char_indices() {
        match c {
            _ if escaped => escaped = false,
            '\\' if quoted => escaped = true,
            '"' => quoted = !quoted,
            ';' if !quoted => {
                out.push(&v[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    out.push(&v[start..]);
    out
}

fn unquote(v: &str) -> String {
    match v.strip_prefix('"') {
        Some(inner) => {
            let inner = inner.strip_suffix('"').unwrap_or(inner);
            let mut out = String::with_capacity(inner.len());
            let mut esc = false;
            for c in inner.chars() {
                if c == '\\' && !esc {
                    esc = true;
                } else {
                    out.push(c);
                    esc = false;
                }
            }
            out
        }
        None => v.to_string(),
    }
}

fn percent_decode(b: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            if let Some(v) = b
                .get(i + 1..i + 3)
                .and_then(|h| std::str::from_utf8(h).ok())
                .and_then(|h| u8::from_str_radix(h, 16).ok())
            {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    out
}

/// Decode RFC 2047 encoded words (`=?charset?B|Q?text?=`); the charset is taken as UTF-8.
fn decode_words(s: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    let mut after_word = false;
    while let Some(start) = rest.find("=?") {
        let Some((word, _)) = rest[start + 2..].split_once("?=") else {
            break;
        };
        let mut f = word.splitn(3, '?');
        let (Some(_charset), Some(enc), Some(text)) = (f.next(), f.next(), f.next()) else {
            break;
        };
        let bytes = match enc {
            "B" | "b" => {
                let (mut b, mut out_b) = (B64::default(), Vec::new());
                if !(text.bytes().all(|c| b.push(c, &mut out_b)) && b.flush(&mut out_b)) {
                    break;
                }
                out_b
            }
            "Q" | "q" => qp_decode(text.replace('_', " ").as_bytes()),
            _ => break,
        };
        // Whitespace between adjacent encoded words is not part of the text.
        let gap = &rest[..start];
        if !(after_word && gap.trim().is_empty()) {
            out.push_str(gap);
        }
        out.push_str(&String::from_utf8_lossy(&bytes));
        after_word = true;
        rest = &rest[start + 2 + word.len() + 2..];
    }
    out.push_str(rest);
    out
}

// ── SMB2 ────────────────────────────────────────────────────────────────────────────────────────

const SMB2_MAGIC: &[u8; 4] = b"\xfeSMB";
const CMD_TREE_CONNECT: u16 = 3;
const CMD_CREATE: u16 = 5;
const CMD_CLOSE: u16 = 6;
const CMD_READ: u16 = 8;
const CMD_WRITE: u16 = 9;
const STATUS_PENDING: u32 = 0x0000_0103;

#[derive(Default)]
struct Smb {
    dirs: [SmbDir; 2],
    /// Requests awaiting their response, by MessageId.
    pending: HashMap<u64, SmbReq>,
    /// TreeId → share path; `None` for `IPC$`.
    trees: HashMap<u32, Option<String>>,
    files: HashMap<[u8; 16], SmbFile>,
    dead: bool,
}

enum SmbReq {
    Tree(Option<String>),
    Create { tree: u32, name: String },
    Read { fid: [u8; 16], offset: u64 },
}

struct SmbFile {
    name: String,
    /// End of file from the CREATE response.
    eof: u64,
    /// Bytes carved so far (the next offset expected).
    next: u64,
    file: Option<OpenFile>,
    dead: bool,
}

#[derive(Default)]
struct SmbDir {
    rec: Rec,
    buf: Vec<u8>,
}

#[derive(Default, Clone, Copy)]
enum Rec {
    /// Reading the 4-byte NetBIOS session header.
    #[default]
    Nbss,
    /// Reading the first `want` bytes of a `left`-byte record.
    Head {
        left: usize,
        want: usize,
    },
    /// Buffering a whole small record.
    Body {
        left: usize,
    },
    /// Streaming `data` file bytes, then `rest` more record bytes to skip.
    Data {
        fid: [u8; 16],
        data: usize,
        rest: usize,
    },
    Skip {
        left: usize,
    },
}

fn u16_at(b: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(o..o + 2)?.try_into().ok()?))
}
fn u32_at(b: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(o..o + 4)?.try_into().ok()?))
}
fn u64_at(b: &[u8], o: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(o..o + 8)?.try_into().ok()?))
}
fn fid_at(b: &[u8], o: usize) -> Option<[u8; 16]> {
    b.get(o..o + 16)?.try_into().ok()
}
fn utf16_at(msg: &[u8], off: usize, len: usize) -> Option<String> {
    let raw = msg.get(off..off.checked_add(len)?)?;
    let units: Vec<u16> = raw
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    clean_name(&String::from_utf16_lossy(&units))
}

impl Smb {
    fn feed(&mut self, d: usize, mut bytes: &[u8], cx: &mut Ctx<'_, '_>) {
        while !bytes.is_empty() && !self.dead {
            let dir = &mut self.dirs[d];
            match dir.rec {
                Rec::Nbss => {
                    let take = (4 - dir.buf.len()).min(bytes.len());
                    dir.buf.extend_from_slice(&bytes[..take]);
                    bytes = &bytes[take..];
                    if dir.buf.len() == 4 {
                        let len = usize::from(dir.buf[1]) << 16
                            | usize::from(dir.buf[2]) << 8
                            | usize::from(dir.buf[3]);
                        dir.rec = match (dir.buf[0], len) {
                            (_, 0) => Rec::Nbss,
                            (0, _) => Rec::Head {
                                left: len,
                                want: len.min(SMB_HEAD),
                            },
                            _ => Rec::Skip { left: len },
                        };
                        dir.buf.clear();
                    }
                }
                Rec::Head { left, want } => {
                    let take = (want - dir.buf.len()).min(bytes.len());
                    dir.buf.extend_from_slice(&bytes[..take]);
                    bytes = &bytes[take..];
                    if dir.buf.len() == want {
                        let head = std::mem::take(&mut dir.buf);
                        self.head(d, left, head, cx);
                    }
                }
                Rec::Body { left } => {
                    let take = (left - dir.buf.len()).min(bytes.len());
                    dir.buf.extend_from_slice(&bytes[..take]);
                    bytes = &bytes[take..];
                    if dir.buf.len() == left {
                        let rec = std::mem::take(&mut dir.buf);
                        dir.rec = Rec::Nbss;
                        self.record(d, &rec, cx);
                    }
                }
                Rec::Data { fid, data, rest } => {
                    let take = data.min(bytes.len());
                    dir.rec = match (data - take, rest) {
                        (0, 0) => Rec::Nbss,
                        (0, rest) => Rec::Skip { left: rest },
                        (data, rest) => Rec::Data { fid, data, rest },
                    };
                    self.write(fid, &bytes[..take]);
                    bytes = &bytes[take..];
                }
                Rec::Skip { left } => {
                    let take = left.min(bytes.len());
                    dir.rec = if left == take {
                        Rec::Nbss
                    } else {
                        Rec::Skip { left: left - take }
                    };
                    bytes = &bytes[take..];
                }
            }
        }
    }

    /// The first bytes of a `left`-byte record are in: buffer it, stream its file data, or skip.
    fn head(&mut self, d: usize, left: usize, head: Vec<u8>, cx: &mut Ctx<'_, '_>) {
        let skip = |n: usize| Rec::Skip { left: left - n };
        if head.get(..4) != Some(SMB2_MAGIC.as_slice()) {
            // Encrypted, compressed and SMB1 records are skipped; anything else means we lost the
            // record framing.
            let known = matches!(head.get(..4), Some(b"\xfdSMB" | b"\xfcSMB" | b"\xffSMB"));
            self.dead = !known;
            self.dirs[d].rec = skip(head.len());
            return;
        }
        if head.len() == left {
            self.dirs[d].rec = Rec::Nbss;
            self.record(d, &head, cx);
            return;
        }
        if let Some((fid, offset, data_off, data_len, upload)) = self.streamable(d, &head) {
            let end = data_off.saturating_add(data_len);
            if data_off < 64 || end > left {
                self.dirs[d].rec = skip(head.len());
                return;
            }
            if data_off > head.len() && data_off <= 1024 {
                // Padding before the data: read up to it first (the request is re-parsed then).
                self.restore_read(d, &head, fid, offset);
                self.dirs[d].buf = head;
                self.dirs[d].rec = Rec::Head {
                    left,
                    want: data_off,
                };
                return;
            }
            if data_off > head.len() || !self.begin(fid, offset, data_len as u64, upload, cx) {
                self.dirs[d].rec = skip(head.len());
                return;
            }
            let have = head.len().saturating_sub(data_off).min(data_len);
            self.write(fid, &head[data_off..data_off + have]);
            let rest = left - head.len().max(end);
            self.dirs[d].rec = match (data_len - have, rest) {
                (0, 0) => Rec::Nbss,
                (0, rest) => Rec::Skip { left: rest },
                (data, rest) => Rec::Data { fid, data, rest },
            };
            return;
        }
        if left <= MAX_SMB_RECORD {
            self.dirs[d].buf = head;
            self.dirs[d].rec = Rec::Body { left };
        } else {
            self.dirs[d].rec = skip(head.len());
        }
    }

    /// Put back a READ request `streamable` consumed, when the response is re-examined later.
    fn restore_read(&mut self, d: usize, head: &[u8], fid: [u8; 16], offset: u64) {
        if d == S2C {
            if let Some(id) = u64_at(head, 24) {
                self.pending.insert(id, SmbReq::Read { fid, offset });
            }
        }
    }

    /// A lone READ response or WRITE request too large to buffer: `(fid, offset, data offset in
    /// the record, data length, upload)`.
    fn streamable(&mut self, d: usize, h: &[u8]) -> Option<([u8; 16], u64, usize, usize, bool)> {
        let cmd = u16_at(h, 12)?;
        let response = u32_at(h, 16)? & 1 != 0;
        if u32_at(h, 20)? != 0 {
            return None; // compounded
        }
        match (d, cmd, response) {
            (S2C, CMD_READ, true) => {
                if u32_at(h, 8)? != 0 {
                    return None;
                }
                let Some(SmbReq::Read { fid, offset }) = self.pending.remove(&u64_at(h, 24)?)
                else {
                    return None;
                };
                Some((
                    fid,
                    offset,
                    usize::from(*h.get(66)?),
                    u32_at(h, 68)? as usize,
                    false,
                ))
            }
            (C2S, CMD_WRITE, false) => Some((
                fid_at(h, 80)?,
                u64_at(h, 72)?,
                usize::from(u16_at(h, 66)?),
                u32_at(h, 68)? as usize,
                true,
            )),
            _ => None,
        }
    }

    /// A whole buffered record: walk its compounded messages.
    fn record(&mut self, d: usize, rec: &[u8], cx: &mut Ctx<'_, '_>) {
        let mut off = 0;
        while let Some(h) = rec
            .get(off..)
            .filter(|h| h.len() >= 64 && h.starts_with(SMB2_MAGIC))
        {
            let next = u32_at(h, 20).unwrap_or(0) as usize;
            let len = if next == 0 { h.len() } else { next };
            if len < 64 || len > h.len() {
                return;
            }
            self.message(d, &h[..len], cx);
            if next == 0 {
                return;
            }
            off += next;
        }
    }

    fn message(&mut self, d: usize, msg: &[u8], cx: &mut Ctx<'_, '_>) {
        let (Some(cmd), Some(flags), Some(status), Some(id)) = (
            u16_at(msg, 12),
            u32_at(msg, 16),
            u32_at(msg, 8),
            u64_at(msg, 24),
        ) else {
            return;
        };
        let response = flags & 1 != 0;
        if response != (d == S2C) || (response && status == STATUS_PENDING) {
            return;
        }
        let tree = u32_at(msg, 36).unwrap_or(0);
        let body = &msg[64..];
        let remember = |pending: &mut HashMap<u64, SmbReq>, req| {
            if pending.len() < MAX_SMB_PENDING {
                pending.insert(id, req);
            }
        };
        match (cmd, response) {
            (CMD_TREE_CONNECT, false) => {
                if let (Some(o), Some(l)) = (u16_at(body, 4), u16_at(body, 6)) {
                    let path = utf16_at(msg, usize::from(o), usize::from(l));
                    let ipc = path
                        .as_deref()
                        .is_some_and(|p| p.to_ascii_uppercase().ends_with("\\IPC$"));
                    remember(&mut self.pending, SmbReq::Tree(path.filter(|_| !ipc)));
                }
            }
            (CMD_TREE_CONNECT, true) => {
                if let Some(SmbReq::Tree(path)) = self.pending.remove(&id) {
                    if status == 0 && self.trees.len() < MAX_SMB_FILES {
                        self.trees.insert(tree, path);
                    }
                }
            }
            (CMD_CREATE, false) => {
                if matches!(self.trees.get(&tree), Some(None)) {
                    return; // a named pipe on IPC$
                }
                if let (Some(o), Some(l)) = (u16_at(body, 44), u16_at(body, 46)) {
                    let name = utf16_at(msg, usize::from(o), usize::from(l)).unwrap_or_default();
                    remember(&mut self.pending, SmbReq::Create { tree, name });
                }
            }
            (CMD_CREATE, true) => {
                if let Some(SmbReq::Create { tree, name }) = self.pending.remove(&id) {
                    if let (0, Some(eof), Some(fid)) = (status, u64_at(body, 48), fid_at(body, 64))
                    {
                        if self.files.len() < MAX_SMB_FILES || self.files.contains_key(&fid) {
                            let name = match self.trees.get(&tree) {
                                Some(Some(share)) if name.is_empty() => share.clone(),
                                Some(Some(share)) => format!("{share}\\{name}"),
                                _ => name,
                            };
                            self.files.insert(
                                fid,
                                SmbFile {
                                    name,
                                    eof,
                                    next: 0,
                                    file: None,
                                    dead: false,
                                },
                            );
                        }
                    }
                }
            }
            (CMD_READ, false) => {
                if let (Some(offset), Some(fid)) = (u64_at(body, 8), fid_at(body, 16)) {
                    remember(&mut self.pending, SmbReq::Read { fid, offset });
                }
            }
            (CMD_READ, true) => {
                if let Some(SmbReq::Read { fid, offset }) = self.pending.remove(&id) {
                    if let (0, Some(o), Some(n)) = (status, body.get(2), u32_at(body, 4)) {
                        self.chunk(msg, fid, offset, usize::from(*o), n as usize, false, cx);
                    }
                }
            }
            (CMD_WRITE, false) => {
                if let (Some(o), Some(n), Some(offset), Some(fid)) = (
                    u16_at(body, 2),
                    u32_at(body, 4),
                    u64_at(body, 8),
                    fid_at(body, 16),
                ) {
                    self.chunk(msg, fid, offset, usize::from(o), n as usize, true, cx);
                }
            }
            (CMD_CLOSE, false) => {
                if let Some(fid) = fid_at(body, 8) {
                    self.close(fid, cx);
                }
            }
            (_, true) => {
                self.pending.remove(&id);
            }
            _ => {}
        }
    }

    /// File bytes carried inside a buffered message.
    #[allow(clippy::too_many_arguments)]
    fn chunk(
        &mut self,
        msg: &[u8],
        fid: [u8; 16],
        offset: u64,
        data_off: usize,
        len: usize,
        upload: bool,
        cx: &mut Ctx<'_, '_>,
    ) {
        let Some(data) = msg.get(data_off..data_off.saturating_add(len)) else {
            return;
        };
        if self.begin(fid, offset, len as u64, upload, cx) {
            self.write(fid, data);
        }
    }

    /// Whether `len` bytes at `offset` extend the file contiguously (opening it on its first
    /// bytes). A re-read of carved bytes is ignored; a hole or a switch between reading and
    /// writing ends the file.
    fn begin(
        &mut self,
        fid: [u8; 16],
        offset: u64,
        len: u64,
        upload: bool,
        cx: &mut Ctx<'_, '_>,
    ) -> bool {
        let Some(f) = self.files.get_mut(&fid) else {
            return false;
        };
        if f.dead || len == 0 || offset.saturating_add(len) <= f.next {
            return false;
        }
        if offset != f.next || f.file.as_ref().is_some_and(|o| o.upload != upload) {
            f.dead = true;
            f.file = None;
            return false;
        }
        if f.file.is_none() {
            f.file = Some(cx.open(Some(f.name.clone()).filter(|n| !n.is_empty()), upload));
        }
        true
    }

    fn write(&mut self, fid: [u8; 16], bytes: &[u8]) {
        if let Some(f) = self.files.get_mut(&fid) {
            if let Some(o) = f.file.as_mut() {
                o.sink.feed(bytes);
                f.next += bytes.len() as u64;
            }
        }
    }

    /// CLOSE: emit the file if it was read to its end, or written at least to its old end.
    fn close(&mut self, fid: [u8; 16], cx: &mut Ctx<'_, '_>) {
        let Some(f) = self.files.remove(&fid) else {
            return;
        };
        if let Some(o) = f.file.filter(|_| !f.dead) {
            let complete = if o.upload {
                f.next >= f.eof
            } else {
                f.next == f.eof
            };
            if complete {
                cx.close(o, "smb");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::sync::Arc;

    use super::super::{CarveObservation, FileCarver};
    use super::*;
    use crate::gen::frames::{
        build_ethernet, build_ipv4, build_tcp, ETHERTYPE_IPV4, IP_PROTO_TCP, TCP_PSH,
    };

    const CLI: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 5);
    const SRV: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 9);

    /// One TCP connection driven packet by packet into a carver.
    struct Conn {
        ends: [(Ipv4Addr, u16); 2],
        seq: [u32; 2],
        ts: i64,
        /// Drop the next segment sent (to make a gap).
        lose_next: bool,
    }

    impl Conn {
        fn new(client: (Ipv4Addr, u16), server: (Ipv4Addr, u16)) -> Conn {
            Conn {
                ends: [client, server],
                seq: [1000, 900_000],
                ts: 1_000_000_000,
                lose_next: false,
            }
        }

        fn packet(&mut self, k: &mut FileCarver, d: usize, flags: u8, payload: &[u8]) {
            let ((src, sp), (dst, dp)) = (self.ends[d], self.ends[1 - d]);
            let mut tcp = build_tcp(src, dst, sp, dp, flags, payload);
            tcp[4..8].copy_from_slice(&self.seq[d].to_be_bytes());
            let ip = build_ipv4(src, dst, IP_PROTO_TCP, 64, tcp.len());
            let mut f = build_ethernet([2, 0, 0, 0, 0, 1], [2, 0, 0, 0, 0, 2], ETHERTYPE_IPV4);
            f.extend_from_slice(&ip);
            f.extend_from_slice(&tcp);
            self.ts += 1_000_000;
            let fr = crate::reader::RawFrame {
                index: 0,
                ts_ns: self.ts,
                ts_known: true,
                iface_id: 0,
                wire_len: f.len() as u32,
                cap_len: f.len() as u32,
                link_type: crate::reader::LinkType::Ethernet,
                data: &f,
            };
            let meta = crate::decode::decode_frame(&fr).expect("decode");
            if !std::mem::take(&mut self.lose_next) {
                k.observe(&meta, &fr);
            }
            let used = payload.len() as u32 + u32::from(flags & (TCP_SYN | TCP_FIN) != 0);
            self.seq[d] = self.seq[d].wrapping_add(used);
        }

        fn open(&mut self, k: &mut FileCarver) {
            self.packet(k, C2S, TCP_SYN, b"");
            self.packet(k, S2C, TCP_SYN | TCP_ACK, b"");
        }

        fn send(&mut self, k: &mut FileCarver, d: usize, bytes: &[u8]) {
            for chunk in bytes.chunks(700) {
                self.packet(k, d, TCP_PSH | TCP_ACK, chunk);
            }
        }

        fn fin(&mut self, k: &mut FileCarver, d: usize) {
            self.packet(k, d, TCP_FIN | TCP_ACK, b"");
        }
    }

    fn sha(b: &[u8]) -> [u8; 32] {
        crate::analyze::sha256(b)
    }

    fn pe(len: usize) -> Vec<u8> {
        let mut v = b"MZ\x90\x00".to_vec();
        v.extend((0..len - 4).map(|i| (i * 7 % 251) as u8));
        v
    }

    fn results(k: FileCarver) -> Vec<CarveObservation> {
        k.into_results()
    }

    #[test]
    fn ftp_passive_download_listing_and_active_upload() {
        let mut k = FileCarver::new();
        let mut ctl = Conn::new((CLI, 50000), (SRV, 21));
        ctl.open(&mut k);
        ctl.send(&mut k, S2C, b"220 ready\r\n");
        ctl.send(&mut k, C2S, b"USER a\r\nPASS b\r\nPASV\r\n");
        ctl.send(
            &mut k,
            S2C,
            b"227 Entering Passive Mode (192,168,1,9,19,137).\r\n",
        );
        // A NATed server announces its private address; the client dials the public one.
        let mut data = Conn::new((CLI, 50001), (SRV, 5001));
        data.open(&mut k);
        ctl.send(&mut k, C2S, b"RETR /pub/tool.exe\r\n");
        let file = pe(5000);
        data.send(&mut k, S2C, &file);
        data.fin(&mut k, S2C);

        // A listing is not a file.
        ctl.send(&mut k, C2S, b"EPSV\r\n");
        ctl.send(
            &mut k,
            S2C,
            b"229 Entering Extended Passive Mode (|||6000|)\r\n",
        );
        let mut list = Conn::new((CLI, 50002), (SRV, 6000));
        list.open(&mut k);
        ctl.send(&mut k, C2S, b"LIST\r\n");
        list.send(&mut k, S2C, b"-rw-r--r-- 1 ftp ftp 5000 tool.exe\r\n");
        list.fin(&mut k, S2C);

        // Active mode upload: the server dials back from port 20.
        ctl.send(&mut k, C2S, b"PORT 10,0,0,5,200,10\r\nSTOR loot.zip\r\n");
        let mut up = Conn::new((SRV, 20), (CLI, 51210));
        up.open(&mut k);
        let zip = b"PK\x03\x04 stolen data".repeat(100);
        up.send(&mut k, S2C, &zip);
        up.fin(&mut k, S2C);

        let r = results(k);
        assert_eq!(r.len(), 2, "{r:?}");
        assert_eq!(r[0].protocol, "ftp");
        assert_eq!(r[0].sha256, sha(&file));
        assert_eq!(r[0].filename.as_deref(), Some("/pub/tool.exe"));
        assert!(!r[0].upload);
        assert_eq!(r[0].client.to_string(), "10.0.0.5");
        assert_eq!(r[0].server.to_string(), "203.0.113.9");
        assert!(r[0].signatures.iter().any(|s| s.executable));
        assert_eq!(r[1].sha256, sha(&zip));
        assert_eq!(r[1].filename.as_deref(), Some("loot.zip"));
        assert!(r[1].upload);
    }

    #[test]
    fn a_gap_or_a_missing_fin_drops_the_ftp_file() {
        let mut k = FileCarver::new();
        let mut ctl = Conn::new((CLI, 50000), (SRV, 21));
        ctl.open(&mut k);
        for (port, lose, fin) in [(5001u16, true, true), (5002, false, false)] {
            let pasv = format!(
                "227 Entering Passive Mode (203,0,113,9,{},{})\r\n",
                port >> 8,
                port & 0xff
            );
            ctl.send(&mut k, C2S, b"PASV\r\n");
            ctl.send(&mut k, S2C, pasv.as_bytes());
            let mut data = Conn::new((CLI, port), (SRV, port));
            data.open(&mut k);
            ctl.send(&mut k, C2S, b"RETR x.bin\r\n");
            data.send(&mut k, S2C, &[1u8; 700]);
            data.lose_next = lose;
            data.send(&mut k, S2C, &[2u8; 700]);
            data.send(&mut k, S2C, &[3u8; 700]);
            if fin {
                data.fin(&mut k, S2C);
            }
        }
        assert!(results(k).is_empty());
    }

    fn b64(data: &[u8]) -> String {
        const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for c in data.chunks(3) {
            let n = c.iter().fold(0u32, |a, &b| a << 8 | u32::from(b)) << (8 * (3 - c.len()));
            for i in 0..4 {
                out.push(if i <= c.len() {
                    char::from(A[(n >> (18 - 6 * i) & 63) as usize])
                } else {
                    '='
                });
            }
        }
        out.as_bytes()
            .chunks(76)
            .map(|l| String::from_utf8_lossy(l).into_owned())
            .collect::<Vec<_>>()
            .join("\r\n")
    }

    fn mail(attachment: &[u8]) -> String {
        format!(
            "From: a@example.com\r\n\
             Subject: invoice\r\n\
             MIME-Version: 1.0\r\n\
             Content-Type: multipart/mixed;\r\n boundary=\"outer\"\r\n\
             \r\n\
             preamble\r\n\
             --outer\r\n\
             Content-Type: multipart/alternative; boundary=inner\r\n\
             \r\n\
             --inner\r\n\
             Content-Type: text/plain\r\n\
             \r\n\
             see attached\r\n\
             --inner--\r\n\
             --outer\r\n\
             Content-Type: application/octet-stream; name=\"ignored.bin\"\r\n\
             Content-Disposition: attachment; filename*=UTF-8''Invoice%20%E2%82%AC.exe\r\n\
             Content-Transfer-Encoding: base64\r\n\
             \r\n\
             {}\r\n\
             --outer\r\n\
             Content-Type: text/plain; name=\"=?UTF-8?B?bm90ZXM=?= =?UTF-8?Q?_v2.txt?=\"\r\n\
             Content-Transfer-Encoding: quoted-printable\r\n\
             \r\n\
             .a dotted line, soft=\r\n\
             wrapped =3D done\r\n\
             last\r\n\
             --outer--\r\n\
             epilogue\r\n",
            b64(attachment)
        )
    }

    /// SMTP dot-stuffing of a message body.
    fn stuff(msg: &str) -> String {
        msg.split("\r\n")
            .map(|l| {
                if l.starts_with('.') {
                    format!(".{l}")
                } else {
                    l.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join("\r\n")
    }

    #[test]
    fn smtp_attachments_decode_and_match_yara() {
        let rules = YaraRulesFixture::new(
            r#"rule evil_invoice : mail { meta: severity = "critical" strings: $a = "EVILMARK" condition: $a and uint16(0) == 0x5A4D }"#,
        );
        let mut k = FileCarver::new().with_yara(Some(rules.0));
        let mut c = Conn::new((CLI, 40000), (SRV, 25));
        c.open(&mut k);
        c.send(&mut k, S2C, b"220 mx ESMTP\r\n");
        c.send(
            &mut k,
            C2S,
            b"EHLO me\r\nMAIL FROM:<a@example.com>\r\nRCPT TO:<b@example.com>\r\n",
        );
        c.send(&mut k, S2C, b"250 ok\r\n250 ok\r\n250 ok\r\n");
        // A refused DATA is not a message.
        c.send(&mut k, C2S, b"DATA\r\n");
        c.send(&mut k, S2C, b"554 no\r\n");
        c.send(&mut k, C2S, b"RSET\r\nDATA\r\n");
        c.send(&mut k, S2C, b"250 reset\r\n354 go ahead\r\n");
        let mut exe = pe(3000);
        exe.extend_from_slice(b"EVILMARK");
        let body = format!("{}\r\n.\r\n", stuff(&mail(&exe)));
        c.send(&mut k, C2S, body.as_bytes());
        c.send(&mut k, S2C, b"250 queued\r\n");
        c.send(&mut k, C2S, b"QUIT\r\n");

        let r = results(k);
        assert_eq!(r.len(), 2, "{r:?}");
        let att = &r[0];
        assert_eq!(att.protocol, "smtp");
        assert!(att.upload);
        assert_eq!(att.filename.as_deref(), Some("Invoice €.exe"));
        assert_eq!(att.sha256, sha(&exe));
        assert_eq!(att.yara.len(), 1);
        assert_eq!(att.yara[0].rule, "evil_invoice");
        let notes = &r[1];
        assert_eq!(notes.filename.as_deref(), Some("notes v2.txt"));
        assert_eq!(
            notes.sha256,
            sha(b".a dotted line, softwrapped = done\r\nlast"),
            "dot-unstuffed and quoted-printable decoded"
        );
        assert!(notes.yara.is_empty());
    }

    struct YaraRulesFixture(Arc<crate::carve::yara::YaraRules>);

    impl YaraRulesFixture {
        fn new(text: &str) -> YaraRulesFixture {
            let p = crate::carve::yara::YaraRules::parse(text);
            assert!(p.skipped.is_empty(), "{:?}", p.skipped);
            YaraRulesFixture(Arc::new(p.rules))
        }
    }

    #[test]
    fn starttls_ends_an_smtp_session() {
        let mut k = FileCarver::new();
        let mut c = Conn::new((CLI, 40000), (SRV, 587));
        c.open(&mut k);
        c.send(&mut k, C2S, b"STARTTLS\r\n");
        c.send(&mut k, S2C, b"220 go\r\n");
        c.send(&mut k, C2S, b"DATA\r\n");
        c.send(&mut k, S2C, b"354 go\r\n");
        let body = format!("{}\r\n.\r\n", mail(b"MZ hidden"));
        c.send(&mut k, C2S, body.as_bytes());
        assert!(results(k).is_empty());
    }

    #[test]
    fn pop3_retr_after_multiline_replies() {
        let mut k = FileCarver::new();
        let mut c = Conn::new((CLI, 40000), (SRV, 110));
        c.open(&mut k);
        c.send(&mut k, S2C, b"+OK POP3 ready\r\n");
        // Pipelined commands, a SASL exchange, and multi-line replies before the RETR.
        c.send(&mut k, C2S, b"AUTH PLAIN\r\n");
        c.send(&mut k, S2C, b"+ \r\n");
        c.send(&mut k, C2S, b"AGFsaWNlAHNlY3JldA==\r\n");
        c.send(&mut k, S2C, b"+OK logged in\r\n");
        c.send(&mut k, C2S, b"LIST\r\nUIDL 1\r\nRETR 1\r\n");
        c.send(
            &mut k,
            S2C,
            b"+OK 1 messages\r\n1 2000\r\n.\r\n+OK 1 abc\r\n",
        );
        let pdf = b"%PDF-1.7\n.line that starts with a dot\n%%EOF".to_vec();
        let msg = format!(
            "+OK 2000 octets\r\n{}\r\n.\r\n",
            stuff(&format!(
                "Subject: x\r\nContent-Type: application/pdf\r\nContent-Disposition: attachment; filename=statement.pdf\r\n\r\n{}",
                String::from_utf8_lossy(&pdf).replace('\n', "\r\n")
            ))
        );
        c.send(&mut k, S2C, msg.as_bytes());
        let r = results(k);
        assert_eq!(r.len(), 1, "{r:?}");
        assert_eq!(r[0].protocol, "pop3");
        assert!(!r[0].upload);
        assert_eq!(r[0].filename.as_deref(), Some("statement.pdf"));
        assert_eq!(
            r[0].sha256,
            sha(&String::from_utf8_lossy(&pdf)
                .replace('\n', "\r\n")
                .into_bytes())
        );
    }

    // ── SMB2 ──

    fn smb(cmd: u16, response: bool, id: u64, tree: u32, body: &[u8]) -> Vec<u8> {
        let mut h = vec![0u8; 64];
        h[..4].copy_from_slice(SMB2_MAGIC);
        h[4..6].copy_from_slice(&64u16.to_le_bytes());
        h[12..14].copy_from_slice(&cmd.to_le_bytes());
        h[16..20].copy_from_slice(&u32::from(response).to_le_bytes());
        h[24..32].copy_from_slice(&id.to_le_bytes());
        h[36..40].copy_from_slice(&tree.to_le_bytes());
        h.extend_from_slice(body);
        let mut rec = vec![
            0,
            (h.len() >> 16) as u8,
            (h.len() >> 8) as u8,
            h.len() as u8,
        ];
        rec.extend_from_slice(&h);
        rec
    }

    fn utf16(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    fn tree_connect(c: &mut Conn, k: &mut FileCarver, id: u64, tree: u32, path: &str) {
        let p = utf16(path);
        let mut body = vec![9, 0, 0, 0];
        body.extend_from_slice(&72u16.to_le_bytes());
        body.extend_from_slice(&(p.len() as u16).to_le_bytes());
        body.extend_from_slice(&p);
        c.send(k, C2S, &smb(CMD_TREE_CONNECT, false, id, 0, &body));
        c.send(k, S2C, &smb(CMD_TREE_CONNECT, true, id, tree, &[0u8; 16]));
    }

    fn create(c: &mut Conn, k: &mut FileCarver, id: u64, tree: u32, name: &str, fid: u8, eof: u64) {
        let n = utf16(name);
        let mut body = vec![0u8; 56];
        body[44..46].copy_from_slice(&120u16.to_le_bytes());
        body[46..48].copy_from_slice(&(n.len() as u16).to_le_bytes());
        body.extend_from_slice(&n);
        c.send(k, C2S, &smb(CMD_CREATE, false, id, tree, &body));
        let mut resp = vec![0u8; 88];
        resp[48..56].copy_from_slice(&eof.to_le_bytes());
        resp[64..80].copy_from_slice(&[fid; 16]);
        c.send(k, S2C, &smb(CMD_CREATE, true, id, tree, &resp));
    }

    fn read(c: &mut Conn, k: &mut FileCarver, id: u64, fid: u8, offset: u64, data: &[u8]) {
        let mut req = vec![0u8; 48];
        req[4..8].copy_from_slice(&(data.len() as u32).to_le_bytes());
        req[8..16].copy_from_slice(&offset.to_le_bytes());
        req[16..32].copy_from_slice(&[fid; 16]);
        c.send(k, C2S, &smb(CMD_READ, false, id, 1, &req));
        let mut resp = vec![17, 0, 80, 0];
        resp.extend_from_slice(&(data.len() as u32).to_le_bytes());
        resp.extend_from_slice(&[0u8; 8]);
        resp.extend_from_slice(data);
        c.send(k, S2C, &smb(CMD_READ, true, id, 1, &resp));
    }

    fn write(c: &mut Conn, k: &mut FileCarver, id: u64, fid: u8, offset: u64, data: &[u8]) {
        let mut req = vec![0u8; 48];
        req[2..4].copy_from_slice(&112u16.to_le_bytes());
        req[4..8].copy_from_slice(&(data.len() as u32).to_le_bytes());
        req[8..16].copy_from_slice(&offset.to_le_bytes());
        req[16..32].copy_from_slice(&[fid; 16]);
        req.extend_from_slice(data);
        c.send(k, C2S, &smb(CMD_WRITE, false, id, 1, &req));
    }

    fn close(c: &mut Conn, k: &mut FileCarver, id: u64, fid: u8) {
        let mut req = vec![0u8; 24];
        req[8..24].copy_from_slice(&[fid; 16]);
        c.send(k, C2S, &smb(CMD_CLOSE, false, id, 1, &req));
    }

    #[test]
    fn smb2_reads_and_writes_carve_whole_files_only() {
        let mut k = FileCarver::new();
        let mut c = Conn::new((CLI, 49800), (SRV, 445));
        c.open(&mut k);
        tree_connect(&mut c, &mut k, 1, 1, "\\\\fs01\\C$");
        tree_connect(&mut c, &mut k, 2, 2, "\\\\fs01\\IPC$");

        // Read in two chunks: the first streams (bigger than a buffered record), the second is
        // buffered.
        let file = pe(40_000);
        create(
            &mut c,
            &mut k,
            3,
            1,
            "Windows\\Temp\\svc.exe",
            7,
            file.len() as u64,
        );
        read(&mut c, &mut k, 4, 7, 0, &file[..32_768]);
        read(&mut c, &mut k, 5, 7, 32_768, &file[32_768..]);
        close(&mut c, &mut k, 6, 7);

        // A named pipe on IPC$ is not a file.
        create(&mut c, &mut k, 7, 2, "srvsvc", 8, 0);
        write(&mut c, &mut k, 8, 8, 0, b"\x05\x00\x0b\x03 dcerpc bind");
        close(&mut c, &mut k, 9, 8);

        // A new file written in one piece.
        let doc = b"%PDF-1.4 dropped".repeat(200);
        create(&mut c, &mut k, 10, 1, "Users\\Public\\a.pdf", 9, 0);
        write(&mut c, &mut k, 11, 9, 0, &doc);
        close(&mut c, &mut k, 12, 9);

        // Reading only part of a file, or with a hole, emits nothing.
        create(&mut c, &mut k, 13, 1, "partial.bin", 10, 10_000);
        read(&mut c, &mut k, 14, 10, 0, &[1u8; 4000]);
        close(&mut c, &mut k, 15, 10);
        create(&mut c, &mut k, 16, 1, "holey.bin", 11, 8000);
        read(&mut c, &mut k, 17, 11, 0, &[1u8; 4000]);
        read(&mut c, &mut k, 18, 11, 6000, &[1u8; 2000]);
        close(&mut c, &mut k, 19, 11);

        let r = results(k);
        assert_eq!(r.len(), 2, "{r:?}");
        assert_eq!(r[0].protocol, "smb");
        assert_eq!(r[0].sha256, sha(&file));
        assert_eq!(
            r[0].filename.as_deref(),
            Some("\\\\fs01\\C$\\Windows\\Temp\\svc.exe")
        );
        assert!(!r[0].upload);
        assert_eq!(r[1].sha256, sha(&doc));
        assert!(r[1].upload);
    }

    #[test]
    fn smb2_garbage_and_encryption_never_panic() {
        let mut k = FileCarver::new();
        let mut c = Conn::new((CLI, 49801), (SRV, 445));
        c.open(&mut k);
        let mut enc = vec![0, 0, 0, 80];
        enc.extend_from_slice(b"\xfdSMB");
        enc.extend_from_slice(&[0u8; 76]);
        c.send(&mut k, S2C, &enc);
        for seed in 0..200u32 {
            let junk: Vec<u8> = (0..300).map(|i| (i * 31 + seed * 17) as u8).collect();
            c.send(&mut k, (seed % 2) as usize, &junk);
        }
        assert!(results(k).is_empty());
    }

    #[test]
    fn header_params_quoting_and_encodings() {
        assert_eq!(
            header_param("attachment; filename=\"a \\\"b\\\"; c.exe\"", "filename").as_deref(),
            Some("a \"b\"; c.exe")
        );
        assert_eq!(
            header_param("attachment; FILENAME=plain.txt; size=3", "filename").as_deref(),
            Some("plain.txt")
        );
        assert_eq!(
            header_param(
                "inline; filename=x.txt; filename*=utf-8'en'%C3%A9t%C3%A9.doc",
                "filename"
            )
            .as_deref(),
            Some("été.doc")
        );
        assert_eq!(
            header_param("text/plain; name=\"=?utf-8?B?w6l0w6k=?=.txt\"", "name").as_deref(),
            Some("été.txt")
        );
        assert_eq!(
            header_param("attachment; filename=\"bad\u{7}\r\nname\"", "filename").as_deref(),
            Some("badname")
        );
        assert_eq!(header_param("attachment", "filename"), None);
    }
}
