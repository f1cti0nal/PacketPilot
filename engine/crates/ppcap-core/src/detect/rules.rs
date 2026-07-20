// Suricata rule subset: types, parser, and content matcher.
// Implements `parse_rules` (never panics, never errors — unsupported/malformed rules go to
// `skipped`) and `Rule::matches` (proto + port + substring content check).
// `apply_rules` is the single-pass pcap scanner that emits `Finding`s for matched rules.

use crate::model::finding::{Finding, FindingKind};
use crate::model::packet::Transport;
use crate::model::severity::Severity;

/// The transport-layer protocol extracted from a Suricata rule header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleProto {
    Tcp,
    Udp,
    /// `ip` in Suricata — matches any transport.
    Ip,
}

/// A parsed, supported Suricata rule that can be matched against a flow's payload.
#[derive(Debug, Clone)]
pub struct Rule {
    pub action: String,
    pub proto: RuleProto,
    /// `None` means the rule matched `any` source port.
    pub src_port: Option<u16>,
    /// `None` means the rule matched `any` destination port.
    pub dst_port: Option<u16>,
    /// `true` for a bidirectional (`<>`) rule: the src/dst port constraints may be satisfied in
    /// either orientation, so the rule matches content in both directions of a conversation.
    /// `false` for a unidirectional (`->`) rule.
    pub bidirectional: bool,
    /// Decoded content bytes (ASCII + hex runs). Never empty for a rule that reached `rules`.
    pub content: Vec<u8>,
    pub msg: String,
    pub sid: u32,
    /// ATT&CK technique IDs extracted from `metadata` / `reference` fields.
    pub mitre: Vec<String>,
    pub severity: Severity,
}

impl Rule {
    /// Returns `true` when `(transport, src_port, dst_port, payload)` satisfies every condition in
    /// this rule: protocol match, port match (honoring both the source-port constraint and the
    /// `->`/`<>` direction operator), and a non-empty content substring match.
    pub fn matches(
        &self,
        transport: Transport,
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> bool {
        let proto_ok = match self.proto {
            RuleProto::Tcp => transport == Transport::Tcp,
            RuleProto::Udp => transport == Transport::Udp,
            RuleProto::Ip => true,
        };
        proto_ok
            && self.ports_match(src_port, dst_port)
            && !self.content.is_empty()
            && payload
                .windows(self.content.len())
                .any(|w| w == self.content.as_slice())
    }

    /// Whether a frame's `(src_port, dst_port)` satisfies this rule's port constraints. A `None`
    /// constraint is `any` (always satisfied). For a unidirectional (`->`) rule the frame's source
    /// must satisfy the rule's source constraint and its dest the dest constraint. A bidirectional
    /// (`<>`) rule also accepts the reversed orientation, so it matches either half of the flow.
    fn ports_match(&self, src_port: u16, dst_port: u16) -> bool {
        let sat = |constraint: Option<u16>, actual: u16| constraint.is_none_or(|p| p == actual);
        let forward = sat(self.src_port, src_port) && sat(self.dst_port, dst_port);
        if !self.bidirectional {
            return forward;
        }
        let reverse = sat(self.src_port, dst_port) && sat(self.dst_port, src_port);
        forward || reverse
    }
}

/// A rule line that was not admitted to `rules` — either malformed, unsupported, or missing
/// required fields. `sid` is `None` when the line did not contain a parseable `sid` option.
#[derive(Debug, Clone)]
pub struct SkippedRule {
    /// 1-based line number in the input text.
    pub line: u32,
    pub sid: Option<u32>,
    pub reason: String,
}

/// Result of `parse_rules`: admitted rules + every skipped line with its reason.
#[derive(Debug, Clone, Default)]
pub struct RuleParse {
    pub rules: Vec<Rule>,
    pub skipped: Vec<SkippedRule>,
}

// ---------------------------------------------------------------------------
// Option keywords we refuse to approximate: if any of these appear as an
// option key the rule is skipped rather than silently mishandled.
// ---------------------------------------------------------------------------
const UNSUPPORTED: &[&str] = &[
    "pcre",
    "byte_test",
    "byte_jump",
    "flowbits",
    "dsize",
    "nocase",
    "depth",
    "offset",
    "distance",
    "within",
    // Matching-affecting keywords: direction/state, TCP flags, L7 protocol scope.
    // Silently ignoring these would cause mis-matches; skip the rule instead.
    "flow",
    "flags",
    "app-layer-protocol",
    // HTTP sticky-buffer / normalization keywords.
    "http_uri",
    "http_header",
    "http_method",
    "http_client_body",
    "http_server_body",
    "http_raw_uri",
    "http_raw_header",
    "http_cookie",
    "http_request_line",
    "http_response_line",
    "http_stat_code",
    "http_stat_msg",
    "http_accept",
    "http_accept_enc",
    "http_accept_lang",
    "http_connection",
    "http_content_type",
    "http_referer",
    "http_start",
];

/// Parse every line of `text` as a Suricata rule.
///
/// - Empty lines and `#`-comment lines are silently skipped (no `SkippedRule` entry).
/// - Lines that are malformed, use unsupported options, or fail content decoding are added to
///   `RuleParse::skipped` with a human-readable reason.
/// - This function never panics and never returns an error.
pub fn parse_rules(text: &str) -> RuleParse {
    let mut out = RuleParse::default();
    for (idx, raw_line) in text.lines().enumerate() {
        let lineno = (idx + 1) as u32;
        let line = raw_line.trim();
        // Silent skip: empty line or comment.
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Err(reason) = parse_one(line, &mut out.rules) {
            // Attempt to salvage the sid for the SkippedRule record.
            let sid = salvage_sid(line);
            out.skipped.push(SkippedRule {
                line: lineno,
                sid,
                reason,
            });
        }
    }
    out
}

/// Parse one non-empty, non-comment line. On success pushes a `Rule`; on failure returns the
/// skip reason.
fn parse_one(line: &str, rules: &mut Vec<Rule>) -> Result<(), String> {
    // ── 1. Split header / options block ─────────────────────────────────────
    let paren_open = line.find('(').ok_or("malformed: no options block")?;
    let header = &line[..paren_open];
    // The options block is everything after the first `(` up to and including the last `)`.
    let rest = &line[paren_open + 1..];
    let paren_close = rest.rfind(')').ok_or("malformed: no options block")?;
    let opts_raw = &rest[..paren_close];

    // ── 2. Parse header tokens ───────────────────────────────────────────────
    // Expected: action proto src_ip src_port -> dst_ip dst_port
    //           t[0]  t[1]  t[2]   t[3]     t[4] t[5]   t[6]
    let tokens: Vec<&str> = header.split_whitespace().collect();
    if tokens.len() < 7 {
        return Err("malformed: too few header tokens".into());
    }
    let action = tokens[0].to_string();
    let proto_str = tokens[1];
    let sport_str = tokens[3];
    let direction_str = tokens[4];
    let dport_str = tokens[6];

    let proto = match proto_str {
        "tcp" => RuleProto::Tcp,
        "udp" => RuleProto::Udp,
        "ip" => RuleProto::Ip,
        other => return Err(format!("unsupported proto: {other}")),
    };

    // The direction operator affects matching, so an unrecognized one must skip the rule rather
    // than be silently treated as `->` (mirrors the UNSUPPORTED-option policy below).
    let bidirectional = match direction_str {
        "->" => false,
        "<>" => true,
        other => return Err(format!("unsupported direction: {other}")),
    };

    // A port token is `any` (no constraint) or a single number. Port lists (`[80,443]`), ranges
    // (`1024:`), variables (`$HTTP_PORTS`) and negation (`!80`) fail the parse → the rule is
    // skipped rather than admitted with the wrong (over-broad) semantics.
    let parse_port = |s: &str| -> Result<Option<u16>, String> {
        if s == "any" {
            Ok(None)
        } else {
            s.parse::<u16>()
                .map(Some)
                .map_err(|_| format!("bad port: {s}"))
        }
    };
    let src_port = parse_port(sport_str)?;
    let dst_port = parse_port(dport_str)?;

    // ── 3. Parse options ─────────────────────────────────────────────────────
    let opts = split_options(opts_raw);

    let mut msg = String::new();
    let mut content_raw: Option<String> = None;
    let mut content_count = 0usize;
    let mut sid: Option<u32> = None;
    let mut mitre: Vec<String> = Vec::new();
    let mut severity = Severity::Medium;

    for (key, val) in &opts {
        let k = key.as_str();

        // Reject any unsupported keyword immediately.
        if UNSUPPORTED.contains(&k) || k.starts_with("http_") {
            return Err(format!("unsupported option: {k}"));
        }

        match k {
            "msg" => msg = unquote(val),
            "content" => {
                content_count += 1;
                if content_count == 1 {
                    content_raw = Some(unquote(val));
                }
            }
            "sid" => {
                sid = Some(
                    val.trim()
                        .parse::<u32>()
                        .map_err(|_| format!("bad sid: {val}"))?,
                );
            }
            "metadata" | "reference" => {
                // Scan for ATT&CK technique IDs like T1071 or T1021.004.
                collect_mitre(val, &mut mitre);
            }
            "classtype" => {
                severity = classtype_to_severity(val.trim());
            }
            "priority" => {
                if let Ok(p) = val.trim().parse::<u8>() {
                    severity = priority_to_severity(p);
                }
            }
            // Recognised but not processed keywords we do not need to model.
            // (flow / flags / app-layer-protocol are now in UNSUPPORTED — they affect matching.)
            "threshold" | "tag" | "rev" | "gid" => {}
            _ => {
                // Unknown keyword: if it looks like it could be a modifier or sticky buffer, skip.
                // We allow unknown keywords that don't look dangerous to be forward-compatible,
                // but any that look like content modifiers / application-layer matchers are unsafe.
                // For now: be conservative — skip on any unknown keyword that has no value (bare
                // option, i.e. modifier) if it isn't in our allow-list above.
                // But do NOT skip the rule for an unknown keyword that has a value — we may just
                // be ignoring metadata. This keeps the parser forward-compatible while still
                // catching the modifiers (which appear as bare options with no colon).
                if val.is_empty() {
                    // Bare option that we don't know — could be a content modifier → skip.
                    return Err(format!("unsupported option: {k}"));
                }
                // Unknown key with a value: silently ignore (forward-compatible metadata).
            }
        }
    }

    // ── 4. Validation ────────────────────────────────────────────────────────
    let sid = sid.ok_or("missing sid")?;

    if content_count == 0 {
        return Err("no content".into());
    }
    if content_count > 1 {
        return Err(format!(
            "unsupported: not exactly one content (found {content_count})"
        ));
    }

    let raw = content_raw.unwrap();
    let content = decode_content(&raw).ok_or_else(|| format!("bad content: {raw:?}"))?;

    rules.push(Rule {
        action,
        proto,
        src_port,
        dst_port,
        bidirectional,
        content,
        msg,
        sid,
        mitre,
        severity,
    });
    Ok(())
}

// ---------------------------------------------------------------------------
// Options splitter
// ---------------------------------------------------------------------------

/// Split the options string (everything inside the outer `(...)`) into `(key, value)` pairs.
/// Values may be quoted strings; semicolons inside quotes are not delimiters.
fn split_options(opts_raw: &str) -> Vec<(String, String)> {
    let mut result = Vec::new();
    let mut remaining = opts_raw;

    loop {
        // Skip leading whitespace / semicolons.
        remaining = remaining.trim_start_matches(|c: char| c == ';' || c.is_whitespace());
        if remaining.is_empty() {
            break;
        }

        // Find where this option token ends (the next unquoted semicolon).
        let end = find_option_end(remaining);
        let token = remaining[..end].trim();
        remaining = &remaining[end..];

        if token.is_empty() {
            continue;
        }

        // Split key:value — the colon may be escaped (\:) inside a quoted value, but the first
        // unescaped `:` after the key name is the key/value separator.
        if let Some(colon) = token.find(':') {
            let key = token[..colon].trim().to_lowercase();
            let val = token[colon + 1..].trim().to_string();
            result.push((key, val));
        } else {
            // Bare option (no colon) — key only, no value.
            result.push((token.to_lowercase(), String::new()));
        }
    }
    result
}

/// Find the index of the next unquoted semicolon in `s` (or `s.len()`).
fn find_option_end(s: &str) -> usize {
    let mut in_quote = false;
    let mut escape = false;
    for (i, c) in s.char_indices() {
        if escape {
            escape = false;
            continue;
        }
        match c {
            '\\' => escape = true,
            '"' => in_quote = !in_quote,
            ';' if !in_quote => return i,
            _ => {}
        }
    }
    s.len()
}

// ---------------------------------------------------------------------------
// Content decoder
// ---------------------------------------------------------------------------

/// Decode a Suricata `content` value (the string inside the quotes — after `unquote` strips the
/// outer `"`). Handles:
/// - `|41 42|` hex runs (space-separated byte pairs).
/// - Outside hex mode: `\"`, `\\`, `\:`, `\|` escape sequences.
/// - Literal ASCII bytes outside of hex mode.
///
/// Returns `None` on any decoding error (unbalanced `|`, bad hex, etc.).
fn decode_content(raw: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut chars = raw.chars().peekable();
    let mut hex_mode = false;
    let mut hex_buf = String::new();

    while let Some(c) = chars.next() {
        if hex_mode {
            if c == '|' {
                // End of hex run — flush the hex buffer.
                if !hex_buf.trim().is_empty() {
                    // Parse any remaining hex digits.
                    for pair in hex_buf.split_whitespace() {
                        if pair.len() != 2 {
                            return None; // odd nibble
                        }
                        let b = u8::from_str_radix(pair, 16).ok()?;
                        out.push(b);
                    }
                }
                hex_buf.clear();
                hex_mode = false;
            } else {
                hex_buf.push(c);
            }
        } else {
            match c {
                '|' => {
                    hex_mode = true;
                    hex_buf.clear();
                }
                '\\' => {
                    // Escape sequence.
                    match chars.next()? {
                        '"' => out.push(b'"'),
                        '\\' => out.push(b'\\'),
                        ':' => out.push(b':'),
                        '|' => out.push(b'|'),
                        _ => {
                            // Unknown escape: not a valid Suricata escape sequence.
                            // Per the spec only \", \\, \:, \| are valid — return
                            // None so the rule is skipped rather than mis-matched.
                            return None;
                        }
                    }
                }
                _ => {
                    // Literal ASCII byte (Suricata content strings are byte-oriented).
                    let s = c.to_string();
                    out.extend_from_slice(s.as_bytes());
                }
            }
        }
    }

    // Unbalanced `|` is a parse error.
    if hex_mode {
        return None;
    }

    Some(out)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Strip outer double-quotes from an option value if present.
fn unquote(s: &str) -> String {
    let t = s.trim();
    if t.starts_with('"') && t.ends_with('"') && t.len() >= 2 {
        t[1..t.len() - 1].to_string()
    } else {
        t.to_string()
    }
}

/// Scan `text` for ATT&CK technique IDs of the form `T\d{4}` (optionally with `.NNN` subtechnique
/// suffix) and append any found to `out`.
fn collect_mitre(text: &str, out: &mut Vec<String>) {
    // Walk char-by-char looking for `T` followed by ≥4 digits.
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'T' {
            let start = i;
            i += 1;
            let mut digit_count = 0;
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                digit_count += 1;
                i += 1;
            }
            if digit_count >= 4 {
                // Optionally consume a `.NNN` sub-technique suffix.
                let mut end = i;
                if i < bytes.len() && bytes[i] == b'.' {
                    let dot = i;
                    i += 1;
                    let sub_start = i;
                    while i < bytes.len() && bytes[i].is_ascii_digit() {
                        i += 1;
                    }
                    if i > sub_start {
                        end = i;
                    } else {
                        // The dot was not followed by digits; don't include it.
                        i = dot;
                        end = dot;
                    }
                }
                let id = &text[start..end];
                if !out.contains(&id.to_string()) {
                    out.push(id.to_string());
                }
                continue;
            }
        }
        i += 1;
    }
}

/// Map a Suricata `classtype` value to a rough severity level.
fn classtype_to_severity(classtype: &str) -> Severity {
    match classtype {
        "trojan-activity"
        | "attempted-admin"
        | "shellcode-detect"
        | "successful-admin"
        | "successful-dos"
        | "successful-recon-largescale"
        | "web-application-attack" => Severity::High,
        "bad-unknown"
        | "attempted-dos"
        | "attempted-recon"
        | "attempted-user"
        | "denial-of-service"
        | "misc-attack"
        | "misc-activity"
        | "network-scan"
        | "suspicious-login"
        | "unusual-client-port-connection" => Severity::Medium,
        "not-suspicious" | "policy-violation" | "protocol-command-decode" => Severity::Low,
        _ => Severity::Medium,
    }
}

/// Map a Suricata numeric `priority` (1=highest) to a severity level.
fn priority_to_severity(p: u8) -> Severity {
    match p {
        1 => Severity::Critical,
        2 => Severity::High,
        3 => Severity::Medium,
        _ => Severity::Low,
    }
}

/// Try to extract a sid from a raw rule line without a full parse (for the SkippedRule record).
fn salvage_sid(line: &str) -> Option<u32> {
    // Look for `sid:NNN` anywhere in the line.
    let lower = line;
    let pat = "sid:";
    let start = lower.find(pat)? + pat.len();
    let rest = lower[start..].trim_start();
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse::<u32>().ok()
}

// ---------------------------------------------------------------------------
// apply_rules — single-pass pcap scanner
// ---------------------------------------------------------------------------

/// Maximum number of rule-match findings returned from a single `apply_rules` call.
const MAX_RULE_FINDINGS: usize = 5000;

/// Map a `Severity` to a representative score in its band (mirrors the bands used across detectors).
///
/// Bands: Info 0–14, Low 15–34, Medium 35–59, High 60–84, Critical 85–100.
fn score_for_severity(sev: Severity) -> u16 {
    match sev {
        Severity::Info => 7,
        Severity::Low => 25,
        Severity::Medium => 47,
        Severity::High => 70,
        Severity::Critical => 90,
    }
}

/// Stream `reader` once; for each matching `(rule, src_ip, dst_ip, dst_port)` tuple emit one
/// [`Finding`] of kind [`FindingKind::RuleMatch`]. Duplicate hits on the same 4-tuple are
/// deduped. Returns at most `MAX_RULE_FINDINGS` findings.
///
/// Never panics and never returns an error — individual frame decode failures are silently
/// skipped, matching the contract of `extract_flow_packets` and `carve_pcap`.
pub fn apply_rules<R: std::io::Read + 'static>(
    reader: R,
    len: Option<u64>,
    rules: &[Rule],
) -> Vec<Finding> {
    use std::collections::HashSet;

    let mut out: Vec<Finding> = Vec::new();
    if rules.is_empty() {
        return out;
    }

    let mut src = match crate::reader::open_reader(reader, len) {
        Ok(s) => s,
        Err(_) => return out,
    };

    // Dedup key: (sid, src_ip_string, dst_ip_string, dst_port)
    let mut seen: HashSet<(u32, String, String, u16)> = HashSet::new();

    loop {
        let frame = match src.next_frame() {
            Ok(Some(f)) => f,
            Ok(None) => break,
            Err(_) => break,
        };

        let meta = match crate::decode::decode_frame(&frame) {
            Ok(m) => m,
            Err(_) => continue,
        };

        let payload: &[u8] = crate::decode::l4_payload(&frame)
            .map(|x| x.payload)
            .unwrap_or(&[]);
        if payload.is_empty() {
            continue;
        }

        let sport = meta.src_port;
        let dport = meta.dst_port;

        // Skip frames with no IP (ARP, non-IP); we need string keys for dedup + Finding.
        let (src_str, dst_str) = match (meta.src_ip, meta.dst_ip) {
            (Some(s), Some(d)) => (s.to_string(), d.to_string()),
            _ => continue,
        };

        for r in rules {
            if r.matches(meta.transport, sport, dport, payload) {
                let key = (r.sid, src_str.clone(), dst_str.clone(), dport);
                if seen.insert(key) {
                    out.push(rule_finding(r, &src_str, &dst_str, dport));
                    if out.len() >= MAX_RULE_FINDINGS {
                        return out;
                    }
                }
            }
        }
    }
    out
}

/// Build a `Finding` for a single rule match.
fn rule_finding(r: &Rule, src_ip: &str, dst_ip: &str, dport: u16) -> Finding {
    Finding {
        kind: FindingKind::RuleMatch,
        severity: r.severity,
        score: score_for_severity(r.severity),
        title: if r.msg.is_empty() {
            format!("sid:{}", r.sid)
        } else {
            r.msg.clone()
        },
        src_ip: src_ip.to_string(),
        dst_ip: Some(dst_ip.to_string()),
        dst_port: Some(dport),
        attack: r.mitre.clone(),
        evidence: vec![
            format!("rule sid:{}", r.sid),
            format!("matched content ({} bytes)", r.content.len()),
        ],
        interval_ns: None,
        jitter_cv: None,
        contacts: None,
        first_seen_ns: None,
        last_seen_ns: None,
        victims: Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// Tests (RED → GREEN)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_canonical_rule() {
        let p = parse_rules(
            r#"alert tcp any any -> any 443 (msg:"C2 hello"; content:"abc"; sid:1001; metadata:mitre T1071;)"#,
        );
        assert_eq!(p.skipped.len(), 0);
        let r = &p.rules[0];
        assert_eq!(r.proto, RuleProto::Tcp);
        assert_eq!(r.dst_port, Some(443));
        assert_eq!(r.content, b"abc");
        assert_eq!(r.msg, "C2 hello");
        assert_eq!(r.sid, 1001);
        assert_eq!(r.mitre, vec!["T1071".to_string()]);
    }

    #[test]
    fn decodes_hex_and_mixed_content() {
        let p = parse_rules(r#"alert udp any any -> any any (content:"|41 42|C"; sid:2;)"#);
        assert_eq!(p.rules[0].content, b"ABC");
        assert_eq!(p.rules[0].dst_port, None); // "any" port
        assert_eq!(p.rules[0].proto, RuleProto::Udp);
    }

    #[test]
    fn skips_unsupported_with_reasons() {
        let text = [
            r#"alert tcp any any -> any 80 (content:"a"; pcre:"/x/"; sid:3;)"#, // pcre
            r#"alert tcp any any -> any 80 (content:"a"; content:"b"; sid:4;)"#, // 2 contents
            r#"alert tcp any any -> any 80 (content:"a"; nocase; sid:5;)"#,     // modifier
            r#"alert tcp any any -> any 80 (msg:"no content"; sid:6;)"#,        // no content
            r#"alert sctp any any -> any 80 (content:"a"; sid:7;)"#,            // proto
            "garbage line",                                                     // unparseable
            r#"alert tcp any any -> any 80 (content:"ok"; sid:8;)"#,            // valid
        ]
        .join("\n");
        let p = parse_rules(&text);
        assert_eq!(p.rules.len(), 1); // only sid 8 survives
        assert_eq!(p.rules[0].sid, 8);
        assert_eq!(p.skipped.len(), 6);
        assert!(p.skipped.iter().any(|s| s.reason.contains("pcre")));
        assert!(p
            .skipped
            .iter()
            .any(|s| s.reason.contains("content") && s.sid == Some(4)));
    }

    #[test]
    fn ignores_comments_and_blanks() {
        let p =
            parse_rules("# a comment\n\n  \nalert tcp any any -> any 9 (content:\"z\"; sid:9;)\n");
        assert_eq!(p.rules.len(), 1);
        assert_eq!(p.skipped.len(), 0);
    }

    #[test]
    fn matches_proto_port_content() {
        let r = &parse_rules(r#"alert tcp any any -> any 443 (content:"abc"; sid:1;)"#).rules[0];
        assert!(r.matches(Transport::Tcp, 55555, 443, b"xx abc yy"));
        assert!(!r.matches(Transport::Tcp, 55555, 80, b"xx abc yy")); // wrong dst port
        assert!(!r.matches(Transport::Udp, 55555, 443, b"xx abc yy")); // wrong proto
        assert!(!r.matches(Transport::Tcp, 55555, 443, b"no match")); // content absent
                                                                      // A `->` rule on dst 443 must NOT match the reversed direction (src 443).
        assert!(!r.matches(Transport::Tcp, 443, 55555, b"xx abc yy"));
        let any = &parse_rules(r#"alert ip any any -> any any (content:"z"; sid:2;)"#).rules[0];
        assert!(any.matches(Transport::Udp, 40000, 12345, b"zzz")); // ip+any-port
    }

    // ── Regression: source-port constraint must be enforced, not dropped ─────
    // `alert tcp any 443 -> any any` matches ONLY traffic sourced from port 443.
    #[test]
    fn enforces_src_port() {
        let r = &parse_rules(r#"alert tcp any 443 -> any any (content:"banner"; sid:5;)"#).rules[0];
        assert_eq!(r.src_port, Some(443));
        assert_eq!(r.dst_port, None);
        assert!(!r.bidirectional);
        assert!(r.matches(Transport::Tcp, 443, 50000, b"xx banner yy")); // sourced from 443
        assert!(!r.matches(Transport::Tcp, 50000, 80, b"xx banner yy")); // sourced from 50000 → no
    }

    // ── Regression: bidirectional `<>` rules match either direction ──────────
    #[test]
    fn bidirectional_matches_either_direction() {
        let r = &parse_rules(r#"alert tcp any any <> any 443 (content:"SECRET"; sid:9;)"#).rules[0];
        assert!(r.bidirectional);
        assert_eq!(r.dst_port, Some(443));
        // client → server:443 (forward)
        assert!(r.matches(Transport::Tcp, 50000, 443, b"aa SECRET bb"));
        // server:443 → client (reverse half of the same conversation)
        assert!(r.matches(Transport::Tcp, 443, 50000, b"aa SECRET bb"));
        // an unrelated flow on neither side of 443 must not match
        assert!(!r.matches(Transport::Tcp, 50000, 80, b"aa SECRET bb"));
    }

    // ── Regression: an unrecognized direction operator is skipped, not coerced to `->` ──
    #[test]
    fn skips_unknown_direction() {
        let p = parse_rules(r#"alert tcp any any => any 443 (content:"a"; sid:6;)"#);
        assert!(
            p.rules.is_empty(),
            "rule with bad direction must not be admitted"
        );
        assert_eq!(p.skipped.len(), 1);
        assert!(p.skipped[0].reason.contains("direction"));
    }

    // ── Regression: I-1 ─────────────────────────────────────────────────────
    // flow, flags, app-layer-protocol affect matching → must be skipped, not silently ignored.
    #[test]
    fn skips_flow_option() {
        let p = parse_rules(
            r#"alert tcp any any -> any 80 (msg:"test"; content:"GET"; flow:to_server,established; sid:100;)"#,
        );
        assert!(p.rules.is_empty(), "rule with flow: must not be admitted");
        assert_eq!(p.skipped.len(), 1);
        assert!(
            p.skipped[0].reason.contains("flow"),
            "skip reason should mention 'flow'"
        );
        assert_eq!(p.skipped[0].sid, Some(100));
    }

    #[test]
    fn skips_flags_option() {
        let p = parse_rules(r#"alert tcp any any -> any any (content:"abc"; flags:S; sid:101;)"#);
        assert!(p.rules.is_empty(), "rule with flags: must not be admitted");
        assert_eq!(p.skipped.len(), 1);
        assert!(p.skipped[0].reason.contains("flags"));
    }

    #[test]
    fn skips_app_layer_protocol_option() {
        let p = parse_rules(
            r#"alert tcp any any -> any any (content:"abc"; app-layer-protocol:http; sid:102;)"#,
        );
        assert!(
            p.rules.is_empty(),
            "rule with app-layer-protocol: must not be admitted"
        );
        assert_eq!(p.skipped.len(), 1);
        assert!(p.skipped[0].reason.contains("app-layer-protocol"));
    }

    // ── Regression: M-1 ─────────────────────────────────────────────────────
    // Unknown content escape sequence → rule must be skipped, not silently approximated.
    #[test]
    fn skips_unknown_content_escape() {
        // \n is not a valid Suricata escape (only \", \\, \:, \| are).
        let p = parse_rules(r#"alert tcp any any -> any 80 (content:"a\nb"; sid:200;)"#);
        assert!(
            p.rules.is_empty(),
            "rule with unknown escape in content must not be admitted"
        );
        assert_eq!(p.skipped.len(), 1);
        assert!(
            p.skipped[0].reason.contains("content"),
            "skip reason should mention 'content'"
        );
        assert_eq!(p.skipped[0].sid, Some(200));
    }

    // ── Regression: metadata-only options still parse ────────────────────────
    // rev, gid, threshold, tag are genuine metadata that don't affect matching → keep ignored.
    #[test]
    fn metadata_options_still_parse() {
        let p = parse_rules(
            r#"alert tcp any any -> any 443 (msg:"ok"; content:"hello"; rev:3; gid:1; classtype:trojan-activity; sid:300;)"#,
        );
        assert_eq!(p.skipped.len(), 0, "metadata options must not cause a skip");
        assert_eq!(p.rules.len(), 1);
        assert_eq!(p.rules[0].sid, 300);
    }

    // ── apply_rules: dedup + match ───────────────────────────────────────────

    /// Build a minimal classic pcap with two TCP/443 data packets from the same flow,
    /// both carrying a payload that contains "abc" (so dedup must collapse them to 1 finding).
    fn crafted_tcp_pcap_with_abc() -> Vec<u8> {
        use crate::gen::{container, frames};
        use crate::reader::LinkType;
        use std::io::Write as _;
        use std::net::Ipv4Addr;

        let client = Ipv4Addr::new(10, 0, 0, 1);
        let server = Ipv4Addr::new(93, 184, 216, 34);

        let mk = |src: Ipv4Addr,
                  dst: Ipv4Addr,
                  sp: u16,
                  dp: u16,
                  flags: u8,
                  payload: &[u8],
                  ts: i64,
                  buf: &mut Vec<u8>| {
            let tcp = frames::build_tcp(src, dst, sp, dp, flags, payload);
            let ip = frames::build_ipv4(src, dst, 6, 64, tcp.len());
            let eth = frames::build_ethernet([2; 6], [4; 6], 0x0800);
            let frame: Vec<u8> = eth.into_iter().chain(ip).chain(tcp).collect();
            container::write_legacy_record(buf, ts, frame.len() as u32, frame.len() as u32)
                .unwrap();
            buf.write_all(&frame).unwrap();
        };

        let mut buf = Vec::new();
        container::write_pcap_header(&mut buf, LinkType::Ethernet).unwrap();
        // Packet 1: payload "GET abc HTTP" — contains "abc"
        mk(
            client,
            server,
            1234,
            443,
            frames::TCP_PSH | frames::TCP_ACK,
            b"GET abc HTTP",
            1_000_000_000,
            &mut buf,
        );
        // Packet 2: second packet from same flow, also contains "abc" → must be deduped
        mk(
            client,
            server,
            1234,
            443,
            frames::TCP_PSH | frames::TCP_ACK,
            b"abc again",
            1_000_000_100,
            &mut buf,
        );
        buf
    }

    #[test]
    fn apply_rules_emits_one_deduped_finding_per_flow() {
        let pcap = crafted_tcp_pcap_with_abc();
        let rules = parse_rules(
            r#"alert tcp any any -> any 443 (msg:"hit"; content:"abc"; sid:77; metadata:mitre T1071;)"#,
        )
        .rules;
        assert_eq!(rules.len(), 1, "rule must parse successfully");

        let findings = apply_rules(
            std::io::Cursor::new(pcap.clone()),
            Some(pcap.len() as u64),
            &rules,
        );

        // Two packets from the same flow both match, but dedup collapses them → exactly 1 finding.
        assert_eq!(findings.len(), 1, "dedup must collapse same-flow hits to 1");
        let f = &findings[0];
        assert_eq!(f.kind, FindingKind::RuleMatch);
        assert_eq!(f.title, "hit");
        assert_eq!(f.attack, vec!["T1071".to_string()]);
        assert!(
            f.evidence.iter().any(|e| e.contains("77")),
            "sid 77 must appear in evidence"
        );

        // No-match rule → empty.
        let none = parse_rules(r#"alert tcp any any -> any 443 (content:"zzz"; sid:78;)"#).rules;
        assert!(
            apply_rules(
                std::io::Cursor::new(pcap.clone()),
                Some(pcap.len() as u64),
                &none
            )
            .is_empty(),
            "non-matching rule must produce no findings"
        );
    }
}
