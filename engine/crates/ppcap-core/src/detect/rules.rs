// Suricata rule subset: types, parser, and content matcher.
// Implements `parse_rules` (never panics, never errors — unsupported/malformed rules go to
// `skipped`) and `Rule::matches` (proto + port + substring content check).

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
    /// `None` means the rule matched `any` port.
    pub dst_port: Option<u16>,
    /// Decoded content bytes (ASCII + hex runs). Never empty for a rule that reached `rules`.
    pub content: Vec<u8>,
    pub msg: String,
    pub sid: u32,
    /// ATT&CK technique IDs extracted from `metadata` / `reference` fields.
    pub mitre: Vec<String>,
    pub severity: Severity,
}

impl Rule {
    /// Returns `true` when `(transport, dst_port, payload)` satisfies every condition in this
    /// rule: protocol match, optional port match, and a non-empty content substring match.
    pub fn matches(&self, transport: Transport, dst_port: u16, payload: &[u8]) -> bool {
        let proto_ok = match self.proto {
            RuleProto::Tcp => transport == Transport::Tcp,
            RuleProto::Udp => transport == Transport::Udp,
            RuleProto::Ip => true,
        };
        let port_ok = self.dst_port.is_none_or(|p| p == dst_port);
        proto_ok
            && port_ok
            && !self.content.is_empty()
            && payload
                .windows(self.content.len())
                .any(|w| w == self.content.as_slice())
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
    let dport_str = tokens[6];

    let proto = match proto_str {
        "tcp" => RuleProto::Tcp,
        "udp" => RuleProto::Udp,
        "ip" => RuleProto::Ip,
        other => return Err(format!("unsupported proto: {other}")),
    };

    let dst_port: Option<u16> = if dport_str == "any" {
        None
    } else {
        Some(
            dport_str
                .parse::<u16>()
                .map_err(|_| format!("bad port: {dport_str}"))?,
        )
    };

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
            "flow" | "flags" | "threshold" | "tag" | "rev" | "gid" | "app-layer-protocol" => {}
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
        dst_port,
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
                        other => {
                            // Unknown escape: treat both chars literally.
                            out.push(b'\\');
                            let s = other.to_string();
                            out.extend_from_slice(s.as_bytes());
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
        assert!(r.matches(Transport::Tcp, 443, b"xx abc yy"));
        assert!(!r.matches(Transport::Tcp, 80, b"xx abc yy")); // wrong port
        assert!(!r.matches(Transport::Udp, 443, b"xx abc yy")); // wrong proto
        assert!(!r.matches(Transport::Tcp, 443, b"no match")); // content absent
        let any = &parse_rules(r#"alert ip any any -> any any (content:"z"; sid:2;)"#).rules[0];
        assert!(any.matches(Transport::Udp, 12345, b"zzz")); // ip+any-port
    }
}
