//! SMB2/3 parser: just enough of the request/response headers to see the identity events that
//! matter — who authenticated and whether it worked, which shares were reached, and the DCE-RPC
//! traffic carried on named pipes.
//!
//! SMB runs over NetBIOS session-service framing (a 4-byte length prefix). An SMB3 message whose
//! body is encrypted (`\xFDSMB`) is framed but not read. From the cleartext we take: the security
//! blob of a SESSION_SETUP (handed to the NTLM parser), the NTSTATUS of its response, the UNC
//! path of a TREE_CONNECT, and the bytes a WRITE or a pipe-transceive IOCTL carries — which, on
//! `IPC$`, is the DCE-RPC the lateral-movement and DCSync detectors already understand. File
//! contents are never read.

/// NetBIOS session message (the only session-service type SMB uses on 445).
const NBSS_SESSION_MESSAGE: u8 = 0x00;
const SMB2_SIG: &[u8] = b"\xfeSMB";
const SMB1_SIG: &[u8] = b"\xffSMB";
const SMB3_ENCRYPTED_SIG: &[u8] = b"\xfdSMB";
const HEADER_LEN: usize = 64;

/// SMB2 commands we read.
const CMD_SESSION_SETUP: u16 = 1;
const CMD_TREE_CONNECT: u16 = 3;
const CMD_WRITE: u16 = 9;
const CMD_IOCTL: u16 = 11;

/// A response (server -> client) rather than a request.
const FLAGS_SERVER_TO_REDIR: u32 = 0x0000_0001;

/// FSCTL_PIPE_TRANSCEIVE: the IOCTL that carries a named-pipe RPC round trip.
const FSCTL_PIPE_TRANSCEIVE: u32 = 0x0011_C017;

/// Length of the SMB message (including its 4-byte NBSS prefix) at the front of `buf`.
/// `Err(true)` = need more bytes, `Err(false)` = not SMB.
pub(crate) fn record_len(buf: &[u8]) -> Result<usize, bool> {
    if buf.len() < 4 {
        if !buf.is_empty() && buf[0] != NBSS_SESSION_MESSAGE {
            return Err(false);
        }
        return Err(true);
    }
    if buf[0] != NBSS_SESSION_MESSAGE {
        return Err(false);
    }
    let len = (usize::from(buf[1]) << 16) | (usize::from(buf[2]) << 8) | usize::from(buf[3]);
    if len < 4 {
        return Err(false);
    }
    if buf.len() >= 8 {
        let sig = &buf[4..8];
        if sig != SMB2_SIG && sig != SMB1_SIG && sig != SMB3_ENCRYPTED_SIG {
            return Err(false);
        }
    }
    Ok(4 + len)
}

/// What one SMB2 message tells us. `msg` is the SMB payload (NBSS prefix already stripped).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SmbEvent<'a> {
    /// SESSION_SETUP request: the GSS/NTLM security blob.
    AuthBlob(&'a [u8]),
    /// SESSION_SETUP response: the NTSTATUS that says whether the logon succeeded.
    AuthResult(u32),
    /// TREE_CONNECT request: the UNC path reached (e.g. `\\host\ADMIN$`).
    TreeConnect(String),
    /// WRITE / pipe-transceive request payload: DCE-RPC written to a named pipe, tagged with the
    /// SMB file handle it was written to (distinct pipes keep distinct RPC context tables).
    PipeData {
        file_id: [u8; 16],
        data: &'a [u8],
    },
    /// An SMB1 message using a real command (not the multi-protocol NEGOTIATE an SMB2 client also
    /// sends) — the legacy dialect actually in use.
    Smb1,
    Other,
}

fn u16le(b: &[u8], off: usize) -> Option<u16> {
    let s = b.get(off..off + 2)?;
    Some(u16::from_le_bytes([s[0], s[1]]))
}

fn u32le(b: &[u8], off: usize) -> Option<u32> {
    let s = b.get(off..off + 4)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

/// SMB1 command byte that an SMB2-capable client uses for the multi-protocol NEGOTIATE.
const SMB1_COM_NEGOTIATE: u8 = 0x72;
/// SMB1 header flag (offset 9) set on a response.
const SMB1_FLAGS_REPLY: u8 = 0x80;

/// Parse one SMB message. Returns `(is_response, event)`.
pub(crate) fn parse(msg: &[u8]) -> Option<(bool, SmbEvent<'_>)> {
    if msg.len() >= 5 && &msg[..4] == SMB1_SIG {
        let is_response = msg.get(9).is_some_and(|f| f & SMB1_FLAGS_REPLY != 0);
        // An SMB2-capable client offers SMB2 dialects in one SMB1-format NEGOTIATE *request*
        // (command 0x72); that alone is not legacy use. But an SMB1-format NEGOTIATE *response*
        // means the server actually selected an SMB1 dialect (an SMB2 server would answer in
        // `\xfeSMB`), and any other SMB1 command is real SMB1 traffic — both are legacy use.
        let only_a_dialect_offer = msg[4] == SMB1_COM_NEGOTIATE && !is_response;
        let event = if only_a_dialect_offer {
            SmbEvent::Other
        } else {
            SmbEvent::Smb1
        };
        return Some((is_response, event));
    }
    if msg.len() < HEADER_LEN || &msg[..4] != SMB2_SIG {
        return None;
    }
    let command = u16le(msg, 12)?;
    let flags = u32le(msg, 16)?;
    let status = u32le(msg, 8)?;
    let is_response = flags & FLAGS_SERVER_TO_REDIR != 0;
    let body = &msg[HEADER_LEN..];

    let event = match (command, is_response) {
        (CMD_SESSION_SETUP, false) => session_setup_blob(msg, body)
            .map(SmbEvent::AuthBlob)
            .unwrap_or(SmbEvent::Other),
        (CMD_SESSION_SETUP, true) => SmbEvent::AuthResult(status),
        (CMD_TREE_CONNECT, false) => tree_connect_path(msg, body)
            .map(SmbEvent::TreeConnect)
            .unwrap_or(SmbEvent::Other),
        (CMD_WRITE, false) => write_data(msg).unwrap_or(SmbEvent::Other),
        (CMD_IOCTL, false) => ioctl_pipe_input(msg).unwrap_or(SmbEvent::Other),
        _ => SmbEvent::Other,
    };
    Some((is_response, event))
}

/// A 16-byte SMB file handle at `off`.
fn file_id_at(msg: &[u8], off: usize) -> Option<[u8; 16]> {
    msg.get(off..off + 16)?.try_into().ok()
}

/// SESSION_SETUP request: security buffer at `SecurityBufferOffset` (from the header start).
fn session_setup_blob<'a>(msg: &'a [u8], body: &[u8]) -> Option<&'a [u8]> {
    let off = usize::from(u16le(body, 12)?);
    let len = usize::from(u16le(body, 14)?);
    msg.get(off..off.checked_add(len)?)
}

/// TREE_CONNECT request: the UNC path (UTF-16LE) at `PathOffset`/`PathLength`.
fn tree_connect_path(msg: &[u8], body: &[u8]) -> Option<String> {
    let off = usize::from(u16le(body, 4)?);
    let len = usize::from(u16le(body, 6)?);
    let bytes = msg.get(off..off.checked_add(len)?)?;
    Some(super::ber::clean_str(
        &bytes
            .chunks_exact(2)
            .take(super::ber::MAX_STR)
            .map(|c| c[0])
            .collect::<Vec<u8>>(),
    ))
}

/// WRITE request: the data at `DataOffset`/`Length`, tagged with its file handle (body offset 16).
fn write_data(msg: &[u8]) -> Option<SmbEvent<'_>> {
    let body = msg.get(HEADER_LEN..)?;
    let off = usize::from(u16le(body, 2)?);
    let len = u32le(body, 4)? as usize;
    let data = msg.get(off..off.checked_add(len)?)?;
    let file_id = file_id_at(body, 16)?;
    Some(SmbEvent::PipeData { file_id, data })
}

/// IOCTL request: the input buffer, but only for FSCTL_PIPE_TRANSCEIVE (a pipe RPC round trip).
/// The file handle is at body offset 8.
fn ioctl_pipe_input(msg: &[u8]) -> Option<SmbEvent<'_>> {
    let body = msg.get(HEADER_LEN..)?;
    if u32le(body, 4)? != FSCTL_PIPE_TRANSCEIVE {
        return None;
    }
    let off = u32le(body, 24)? as usize;
    let len = u32le(body, 28)? as usize;
    let data = msg.get(off..off.checked_add(len)?)?;
    let file_id = file_id_at(body, 8)?;
    Some(SmbEvent::PipeData { file_id, data })
}

/// Is this UNC path an administrative share used for remote execution (`ADMIN$`, `C$`, …)?
pub(crate) fn admin_share(path: &str) -> Option<String> {
    let leaf = path.rsplit(['\\', '/']).find(|s| !s.is_empty())?;
    let upper = leaf.to_ascii_uppercase();
    // ADMIN$ and the drive shares (C$, D$, …) are the ones used to drop and run a payload.
    // IPC$ is excluded: every named-pipe session reaches it, so it is not by itself a signal.
    let is_admin = upper == "ADMIN$"
        || (upper.len() == 2 && upper.ends_with('$') && upper.as_bytes()[0].is_ascii_alphabetic());
    is_admin.then_some(upper)
}

#[cfg(test)]
pub(crate) mod build {
    use super::*;

    fn u16le(v: u16) -> [u8; 2] {
        v.to_le_bytes()
    }

    /// Wrap an SMB message in its NBSS session-message prefix.
    pub fn nbss(msg: &[u8]) -> Vec<u8> {
        let mut v = vec![NBSS_SESSION_MESSAGE];
        let len = msg.len() as u32;
        v.extend_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8]);
        v.extend_from_slice(msg);
        v
    }

    fn header(command: u16, flags: u32, status: u32) -> Vec<u8> {
        let mut h = Vec::new();
        h.extend_from_slice(SMB2_SIG);
        h.extend_from_slice(&u16le(HEADER_LEN as u16)); // StructureSize
        h.extend_from_slice(&u16le(0)); // CreditCharge
        h.extend_from_slice(&status.to_le_bytes()); // Status / Reserved
        h.extend_from_slice(&u16le(command));
        h.extend_from_slice(&u16le(0)); // Credits
        h.extend_from_slice(&flags.to_le_bytes());
        h.extend_from_slice(&0u32.to_le_bytes()); // NextCommand
        h.extend_from_slice(&0u64.to_le_bytes()); // MessageId
        h.extend_from_slice(&0u32.to_le_bytes()); // Reserved
        h.extend_from_slice(&0u32.to_le_bytes()); // TreeId
        h.extend_from_slice(&0u64.to_le_bytes()); // SessionId
        h.extend_from_slice(&[0u8; 16]); // Signature
        debug_assert_eq!(h.len(), HEADER_LEN);
        h
    }

    pub fn session_setup_req(blob: &[u8]) -> Vec<u8> {
        let mut m = header(CMD_SESSION_SETUP, 0, 0);
        let sec_off = (HEADER_LEN + 24) as u16;
        let mut body = Vec::new();
        body.extend_from_slice(&u16le(25)); // StructureSize
        body.push(0); // Flags
        body.push(0); // SecurityMode
        body.extend_from_slice(&0u32.to_le_bytes()); // Capabilities
        body.extend_from_slice(&0u32.to_le_bytes()); // Channel
        body.extend_from_slice(&u16le(sec_off)); // SecurityBufferOffset
        body.extend_from_slice(&u16le(blob.len() as u16)); // SecurityBufferLength
        body.extend_from_slice(&0u64.to_le_bytes()); // PreviousSessionId
        body.extend_from_slice(blob);
        m.extend_from_slice(&body);
        m
    }

    pub fn session_setup_resp(status: u32) -> Vec<u8> {
        let mut m = header(CMD_SESSION_SETUP, FLAGS_SERVER_TO_REDIR, status);
        m.extend_from_slice(&u16le(9)); // StructureSize
        m.extend_from_slice(&u16le(0));
        m.extend_from_slice(&u16le(0));
        m.extend_from_slice(&u16le(0));
        m
    }

    pub fn tree_connect_req(path: &str) -> Vec<u8> {
        let mut m = header(CMD_TREE_CONNECT, 0, 0);
        let p: Vec<u8> = path.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        let path_off = (HEADER_LEN + 8) as u16;
        m.extend_from_slice(&u16le(9)); // StructureSize
        m.extend_from_slice(&u16le(0)); // Flags
        m.extend_from_slice(&u16le(path_off));
        m.extend_from_slice(&u16le(p.len() as u16));
        m.extend_from_slice(&p);
        m
    }

    pub fn write_req(data: &[u8]) -> Vec<u8> {
        write_req_h([0u8; 16], data)
    }

    /// A WRITE request on a specific file handle.
    pub fn write_req_h(file_id: [u8; 16], data: &[u8]) -> Vec<u8> {
        let mut m = header(CMD_WRITE, 0, 0);
        let data_off = (HEADER_LEN + 48) as u16;
        m.extend_from_slice(&u16le(49)); // StructureSize
        m.extend_from_slice(&u16le(data_off)); // DataOffset
        m.extend_from_slice(&(data.len() as u32).to_le_bytes()); // Length
        m.extend_from_slice(&0u64.to_le_bytes()); // Offset
        m.extend_from_slice(&file_id); // FileId
        m.extend_from_slice(&0u32.to_le_bytes()); // Channel
        m.extend_from_slice(&0u32.to_le_bytes()); // RemainingBytes
        m.extend_from_slice(&u16le(0)); // WriteChannelInfoOffset
        m.extend_from_slice(&u16le(0)); // WriteChannelInfoLength
        m.extend_from_slice(&0u32.to_le_bytes()); // Flags
        m.extend_from_slice(data);
        m
    }

    pub fn ioctl_transceive(data: &[u8]) -> Vec<u8> {
        ioctl_transceive_h([0u8; 16], data)
    }

    /// A pipe-transceive IOCTL on a specific file handle.
    pub fn ioctl_transceive_h(file_id: [u8; 16], data: &[u8]) -> Vec<u8> {
        let mut m = header(CMD_IOCTL, 0, 0);
        let in_off = (HEADER_LEN + 56) as u32;
        m.extend_from_slice(&u16le(57)); // StructureSize
        m.extend_from_slice(&u16le(0)); // Reserved
        m.extend_from_slice(&FSCTL_PIPE_TRANSCEIVE.to_le_bytes()); // CtlCode
        m.extend_from_slice(&file_id); // FileId
        m.extend_from_slice(&in_off.to_le_bytes()); // InputOffset
        m.extend_from_slice(&(data.len() as u32).to_le_bytes()); // InputCount
        m.extend_from_slice(&0u32.to_le_bytes()); // MaxInputResponse
        m.extend_from_slice(&0u32.to_le_bytes()); // OutputOffset
        m.extend_from_slice(&0u32.to_le_bytes()); // OutputCount
        m.extend_from_slice(&0u32.to_le_bytes()); // MaxOutputResponse
        m.extend_from_slice(&0u32.to_le_bytes()); // Flags
        m.extend_from_slice(&0u32.to_le_bytes()); // Reserved2
        m.extend_from_slice(data);
        m
    }

    /// SMB1 with an arbitrary command byte and reply flag.
    fn smb1(command: u8, reply: bool) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(SMB1_SIG);
        m.push(command);
        m.extend_from_slice(&[0, 0, 0, 0]); // NTStatus
        m.push(if reply { 0x80 } else { 0 }); // Flags (offset 9)
        m.extend_from_slice(&[0u8; 22]);
        m
    }

    /// The multi-protocol NEGOTIATE an SMB2 client sends (command 0x72) — not legacy use.
    pub fn smb1_negotiate() -> Vec<u8> {
        smb1(0x72, false)
    }

    /// A server's SMB1 NEGOTIATE response (command 0x72, reply) — it selected an SMB1 dialect.
    pub fn smb1_negotiate_resp() -> Vec<u8> {
        smb1(0x72, true)
    }

    /// A genuine SMB1 request (SESSION_SETUP_ANDX, 0x73) — the legacy dialect actually in use.
    pub fn smb1_session_setup() -> Vec<u8> {
        smb1(0x73, false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_and_reads_session_setup() {
        let req = build::session_setup_req(b"\x60blob-here");
        let framed = build::nbss(&req);
        assert_eq!(record_len(&framed), Ok(framed.len()));
        let (resp, ev) = parse(&req).unwrap();
        assert!(!resp);
        assert_eq!(ev, SmbEvent::AuthBlob(b"\x60blob-here"));

        let r = build::session_setup_resp(0xC000_006D);
        let (resp, ev) = parse(&r).unwrap();
        assert!(resp);
        assert_eq!(ev, SmbEvent::AuthResult(0xC000_006D));
    }

    #[test]
    fn reads_tree_connect_and_admin_share() {
        let m = build::tree_connect_req("\\\\dc01\\ADMIN$");
        let (_, ev) = parse(&m).unwrap();
        let SmbEvent::TreeConnect(p) = ev.clone() else {
            panic!("{ev:?}")
        };
        assert_eq!(p, "\\\\dc01\\ADMIN$");
        assert_eq!(admin_share(&p).as_deref(), Some("ADMIN$"));
        assert_eq!(admin_share("\\\\dc01\\C$").as_deref(), Some("C$"));
        assert_eq!(admin_share("\\\\dc01\\IPC$"), None);
        assert_eq!(admin_share("\\\\srv\\Finance"), None);
    }

    #[test]
    fn carries_pipe_rpc_over_write_and_ioctl() {
        let rpc = b"\x05\x00\x0b\x03rpc-bind";
        let w = build::write_req(rpc);
        assert_eq!(
            parse(&w).unwrap().1,
            SmbEvent::PipeData {
                file_id: [0; 16],
                data: rpc
            }
        );
        let i = build::ioctl_transceive(rpc);
        assert_eq!(
            parse(&i).unwrap().1,
            SmbEvent::PipeData {
                file_id: [0; 16],
                data: rpc
            }
        );
    }

    #[test]
    fn detects_smb1_use_but_not_the_smb2_negotiate() {
        // An SMB2 client's multi-protocol NEGOTIATE *request* (0x72) is not legacy use.
        assert_eq!(parse(&build::smb1_negotiate()).unwrap().1, SmbEvent::Other);
        // But a server's SMB1 NEGOTIATE *response* means it selected an SMB1 dialect.
        assert_eq!(
            parse(&build::smb1_negotiate_resp()).unwrap().1,
            SmbEvent::Smb1
        );
        // And any other SMB1 command is real SMB1 traffic.
        assert_eq!(
            parse(&build::smb1_session_setup()).unwrap().1,
            SmbEvent::Smb1
        );
    }

    #[test]
    fn framing_rejects_non_smb() {
        assert_eq!(record_len(b"GET "), Err(false));
        assert_eq!(record_len(&[0x00, 0x00]), Err(true));
        // NBSS session message whose body is not SMB: not ours.
        assert_eq!(
            record_len(&[0x00, 0, 0, 8, b'J', b'U', b'N', b'K']),
            Err(false)
        );
    }

    #[test]
    fn garbage_never_panics() {
        let mut x: u32 = 0x1357_9bdf;
        for len in 0..400 {
            let buf: Vec<u8> = (0..len)
                .map(|_| {
                    x ^= x << 13;
                    x ^= x >> 17;
                    x ^= x << 5;
                    x as u8
                })
                .collect();
            let _ = record_len(&buf);
            let _ = parse(&buf);
        }
    }
}
