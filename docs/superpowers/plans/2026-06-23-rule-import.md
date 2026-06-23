# Suricata-style rule import (phase A) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Load a minimal Suricata-style ruleset and apply content matches as `Finding`s, via a decoupled pcap pass + a CLI `--rules` flag.

**Architecture:** `detect/rules.rs` parses the rule subset + matches payloads; `apply_rules` re-reads the pcap (via `open_reader`) and returns `Finding`s; the CLI folds them through `apply_findings`. Engine + CLI; no new deps; pure compute (wasm-safe for phase B).

**Tech Stack:** Rust (ppcap-core + ppcap-cli). No new deps.

## Global Constraints

- **No new deps.** C-free gate (ppcap-core) empty; `rules` pure compute (no `std::{net,time}`).
- **Never panics; never silently mis-matches.** Malformed/unsupported rules → `skipped` with a reason (no hard error, no approximate match).
- **RuleMatch findings behave like built-ins** — through `apply_findings` (threat-card uplift) + `summary.findings`.
- Run cargo from `engine/` (PATH `/c/Users/ravid/.cargo/bin`); `cargo fmt` before commit.

## Reference: the seams (verified)

```
// model/finding.rs  Finding{ kind:FindingKind, severity, score:u16, title, src_ip, dst_ip:Option<String>, dst_port:Option<u16>, attack:Vec<String>, evidence:Vec<String>, interval_ns, jitter_cv, contacts }
//   enum FindingKind { Beacon, HostSweep, BruteForce, CleartextCreds, PiiExposure, LateralMovement, DataExfil, DnsTunnel }  ← add RuleMatch
// stats/mod.rs:386 pub fn apply_findings(&mut self, findings:&[Finding])  (uplifts IpThreat cards)
// reader/mod.rs open_reader(reader, len) → frames of RawFrame{ data, link_type, ts_ns, cap_len, wire_len }
// decode/mod.rs decode_frame(&RawFrame)->Result<PacketMeta{ transport:Transport, src_ip, dst_ip, src_port, dst_port,.. }>
// packets.rs extract_flow_packets / carve_pcap — the open_reader re-read + per-frame decode + L4-payload-slice pattern to MIRROR
// model/packet.rs enum Transport { Tcp, Udp, ... }
// cli.rs the Analyze subcommand + --reputation (:63 flag, :133 destructure, :191 the `if reputation` block, :225 apply_X fold)
```

---

### Task 1: `detect/rules.rs` — types, `parse_rules`, `Rule::matches`

**Files:**
- Create: `engine/crates/ppcap-core/src/detect/rules.rs`
- Modify: `engine/crates/ppcap-core/src/detect/mod.rs` (`pub mod rules;`)

**Interfaces:**
- Produces: `Rule`, `RuleProto`, `RuleParse`, `SkippedRule`, `parse_rules`, `Rule::matches`.

- [ ] **Step 1: Write the failing tests** — in `rules.rs` `#[cfg(test)]` (these cases ARE the parser contract):
```rust
#[test]
fn parses_canonical_rule() {
    let p = parse_rules(r#"alert tcp any any -> any 443 (msg:"C2 hello"; content:"abc"; sid:1001; metadata:mitre T1071;)"#);
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
        r#"alert tcp any any -> any 80 (content:"a"; pcre:"/x/"; sid:3;)"#,       // pcre
        r#"alert tcp any any -> any 80 (content:"a"; content:"b"; sid:4;)"#,      // 2 contents
        r#"alert tcp any any -> any 80 (content:"a"; nocase; sid:5;)"#,           // modifier
        r#"alert tcp any any -> any 80 (msg:"no content"; sid:6;)"#,             // no content
        r#"alert sctp any any -> any 80 (content:"a"; sid:7;)"#,                  // proto
        "garbage line",                                                          // unparseable
        r#"alert tcp any any -> any 80 (content:"ok"; sid:8;)"#,                  // valid
    ].join("\n");
    let p = parse_rules(&text);
    assert_eq!(p.rules.len(), 1);          // only sid 8 survives
    assert_eq!(p.rules[0].sid, 8);
    assert_eq!(p.skipped.len(), 6);
    assert!(p.skipped.iter().any(|s| s.reason.contains("pcre")));
    assert!(p.skipped.iter().any(|s| s.reason.contains("content") && s.sid == Some(4)));
}
#[test]
fn ignores_comments_and_blanks() {
    let p = parse_rules("# a comment\n\n  \nalert tcp any any -> any 9 (content:\"z\"; sid:9;)\n");
    assert_eq!(p.rules.len(), 1);
    assert_eq!(p.skipped.len(), 0);
}
#[test]
fn matches_proto_port_content() {
    let r = &parse_rules(r#"alert tcp any any -> any 443 (content:"abc"; sid:1;)"#).rules[0];
    assert!(r.matches(Transport::Tcp, 443, b"xx abc yy"));
    assert!(!r.matches(Transport::Tcp, 80, b"xx abc yy"));   // wrong port
    assert!(!r.matches(Transport::Udp, 443, b"xx abc yy"));  // wrong proto
    assert!(!r.matches(Transport::Tcp, 443, b"no match"));   // content absent
    let any = &parse_rules(r#"alert ip any any -> any any (content:"z"; sid:2;)"#).rules[0];
    assert!(any.matches(Transport::Udp, 12345, b"zzz"));     // ip+any-port
}
```

- [ ] **Step 2: Run to verify they fail** — `cd engine && cargo test -p ppcap-core rules` → FAIL.

- [ ] **Step 3: Implement** `rules.rs`. Types:
```rust
use crate::model::packet::Transport;
use crate::model::severity::Severity; // confirm the Severity import path

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleProto { Tcp, Udp, Ip }

#[derive(Debug, Clone)]
pub struct Rule {
    pub action: String,
    pub proto: RuleProto,
    pub dst_port: Option<u16>,
    pub content: Vec<u8>,
    pub msg: String,
    pub sid: u32,
    pub mitre: Vec<String>,
    pub severity: Severity,
}

#[derive(Debug, Clone)]
pub struct SkippedRule { pub line: u32, pub sid: Option<u32>, pub reason: String }

#[derive(Debug, Clone, Default)]
pub struct RuleParse { pub rules: Vec<Rule>, pub skipped: Vec<SkippedRule> }
```
Implement `parse_rules(text) -> RuleParse`:
- For each line (1-indexed): trim; skip empty or `#`-comment lines.
- Split header (before the first `(`) and options (inside the outer `(...)`). No `(` / no closing `)` → skip (`reason: "malformed: no options block"`).
- Header tokens (whitespace): need ≥7; `action=t[0]`, `proto=t[1]`, `dport=t[6]` (and `t[4]` should be `->`/`<>`). `proto` → `RuleProto` (`tcp`/`udp`/`ip`; else skip `"unsupported proto: X"`). `dport`: `"any"` → `None`; else `parse::<u16>()` (fail → skip `"bad port"`).
- Options: split on `;`, trim each; `key:value` (value may be quoted). Collect `msg`, `content` (count them), `sid`, and scan `metadata`/`reference` values for `T\d{4,}` ATT&CK ids; `classtype`/`priority` → `severity` (optional; default `Severity::Medium`).
- **Skip rules (with the listed reason)** when: option list contains `pcre`, `byte_test`, `byte_jump`, `flowbits`, `dsize`, or a content modifier (`nocase`/`depth`/`offset`/`distance`/`within`) or an `http_*`/sticky-buffer keyword; OR there is not exactly one `content`; OR there is no `sid`. The check is "does the rule use a construct we don't model" — keep a `const UNSUPPORTED: &[&str]` list; if any option key is in it → skip `format!("unsupported option: {key}")`.
- `content` decode (`decode_content(raw: &str) -> Option<Vec<u8>>`): walk the string; `|` toggles hex mode; in hex mode read pairs of hex digits (space-separated) → bytes; outside, handle `\"`,`\\`,`\:`,`\|` escapes, else the literal byte. Unbalanced `|` or bad hex → `None` (skip the rule).
- Build `Rule`; push to `rules`. Any internal parse failure → `skipped` with the reason (never panic).

`impl Rule { pub fn matches(&self, transport: Transport, dst_port: u16, payload: &[u8]) -> bool }`:
```rust
let proto_ok = match self.proto {
    RuleProto::Tcp => transport == Transport::Tcp,
    RuleProto::Udp => transport == Transport::Udp,
    RuleProto::Ip => true,
};
let port_ok = self.dst_port.map_or(true, |p| p == dst_port);
proto_ok && port_ok && !self.content.is_empty()
    && payload.windows(self.content.len()).any(|w| w == self.content.as_slice())
```
(`detect/mod.rs`: add `pub mod rules;`.)

- [ ] **Step 4: Run to verify they pass** — `cd engine && cargo test -p ppcap-core rules` → PASS. `cargo fmt`.

- [ ] **Step 5: Commit**
```bash
git add engine/crates/ppcap-core/src/detect/rules.rs engine/crates/ppcap-core/src/detect/mod.rs
git commit -m "feat(rules): parse a minimal Suricata rule subset + content matcher"
```

---

### Task 2: `FindingKind::RuleMatch` + `apply_rules` (the pcap pass)

**Files:**
- Modify: `engine/crates/ppcap-core/src/model/finding.rs` (`RuleMatch` variant + exhaustive `match` sites), `engine/crates/ppcap-core/src/detect/rules.rs` (`apply_rules`), `engine/crates/ppcap-core/src/lib.rs` (re-exports)

**Interfaces:**
- Consumes: `Rule`/`Rule::matches` (T1); `open_reader`, `decode_frame`, `apply_findings`.
- Produces: `apply_rules(reader, len, &[Rule]) -> Vec<Finding>`; `FindingKind::RuleMatch`.

- [ ] **Step 1: Add the variant** — `model/finding.rs`: add `RuleMatch` to `FindingKind` (doc: "User signature-rule match (imported Suricata-style ruleset)."). Then `cargo build -p ppcap-core` and fix EVERY non-exhaustive `match FindingKind` the compiler flags (serialization, report labels, category/severity mapping) — grep `FindingKind::` to find them; map `RuleMatch` consistently (e.g. a `"rule_match"` serde tag / a report label like "Signature match" / its MITRE-derived category). Do NOT add a catch-all `_` arm that hides future variants.

- [ ] **Step 2: Write the failing test** — in `rules.rs`:
```rust
#[test]
fn apply_rules_emits_one_deduped_finding_per_flow() {
    // a crafted pcap: a TCP/443 flow whose payload contains "abc" across 2 packets
    let pcap = crafted_tcp_pcap_with_payload(b"GET abc HTTP"); // build via the gen/container writer or a fixture
    let rules = parse_rules(r#"alert tcp any any -> any 443 (msg:"hit"; content:"abc"; sid:77; metadata:mitre T1071;)"#).rules;
    let findings = apply_rules(std::io::Cursor::new(&pcap), Some(pcap.len() as u64), &rules);
    assert_eq!(findings.len(), 1);                  // deduped across packets
    let f = &findings[0];
    assert_eq!(f.kind, FindingKind::RuleMatch);
    assert_eq!(f.title, "hit");
    assert_eq!(f.attack, vec!["T1071".to_string()]);
    assert!(f.evidence.iter().any(|e| e.contains("77")));   // sid in evidence
    // no-match rule → empty
    let none = parse_rules(r#"alert tcp any any -> any 443 (content:"zzz"; sid:78;)"#).rules;
    assert!(apply_rules(std::io::Cursor::new(&pcap), Some(pcap.len() as u64), &none).is_empty());
}
```
> NOTE: build the test pcap by mirroring an existing engine test fixture (e.g. the `tcp_pcap()` helper used in `packets.rs` tests at :373, or the `gen/container` writer) so the payload bytes land in the L4 payload. Reuse the SAME L4-payload-offset extraction `extract_flow_packets`/`carve_pcap` use.

- [ ] **Step 3: Run to verify it fails** — `cd engine && cargo test -p ppcap-core rules::` → FAIL.

- [ ] **Step 4: Implement `apply_rules`** in `rules.rs`:
```rust
use crate::model::finding::{Finding, FindingKind};
use crate::reader::open_reader;
use crate::decode::decode_frame;
use std::collections::HashSet;

const MAX_RULE_FINDINGS: usize = 5000;

pub fn apply_rules<R: std::io::Read>(reader: R, len: Option<u64>, rules: &[Rule]) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut seen: HashSet<(u32, String, String, u16)> = HashSet::new();
    let mut src = match open_reader(reader, len) { Ok(s) => s, Err(_) => return out };
    while let Some(frame) = src.next_frame() {           // mirror the carve/extract loop's iteration API
        let frame = match frame { Ok(f) => f, Err(_) => continue };
        let meta = match decode_frame(&frame) { Ok(m) => m, Err(_) => continue };
        let payload = l4_payload(&frame, &meta);          // mirror extract_flow_packets/carve_pcap slicing
        if payload.is_empty() { continue; }
        let dport = meta.dst_port.unwrap_or(0);
        for r in rules {
            if r.matches(meta.transport, dport, payload) {
                let key = (r.sid, meta.src_ip.clone(), meta.dst_ip.clone(), dport);
                if seen.insert(key) {
                    out.push(rule_finding(r, &meta, dport));
                    if out.len() >= MAX_RULE_FINDINGS { return out; }
                }
            }
        }
    }
    out
}
```
- `rule_finding(rule, meta, dport) -> Finding`: `kind: RuleMatch`, `severity: rule.severity`, `score: score_for(rule.severity)` (reuse the band the other detectors use), `title: rule.msg` (or `"sid:{sid}"` if msg empty), `src_ip`, `dst_ip: Some`, `dst_port: Some(dport)`, `attack: rule.mitre.clone()`, `evidence: vec![format!("rule sid:{}", rule.sid), format!("matched content ({} bytes)", rule.content.len())]`, the beacon fields `None`.
- `l4_payload(&frame, &meta)`: extract the L4 payload slice from `frame.data` exactly as `extract_flow_packets`/`carve_pcap` compute it (read those + reuse the helper if one exists; else replicate the offset math).
- **Confirm the reader iteration API** (`next_frame()` vs an iterator) by reading `carve_pcap`/`extract_flow_packets` and match it.

- [ ] **Step 5: lib.rs re-exports** — `pub use detect::rules::{apply_rules, parse_rules, Rule, RuleProto, RuleParse, SkippedRule};`.

- [ ] **Step 6: Run to verify it passes** — `cd engine && cargo test -p ppcap-core rules` → PASS. `cargo fmt`; `cargo clippy -p ppcap-core --all-targets -- -D warnings` → clean.

- [ ] **Step 7: Commit**
```bash
git add engine/crates/ppcap-core/src/model/finding.rs engine/crates/ppcap-core/src/detect/rules.rs engine/crates/ppcap-core/src/lib.rs
git commit -m "feat(rules): apply_rules pcap pass + FindingKind::RuleMatch"
```

---

### Task 3: CLI `--rules` flag + fold (+ full gate)

**Files:**
- Modify: `engine/crates/ppcap-cli/src/cli.rs`

**Interfaces:**
- Consumes: `parse_rules`/`apply_rules` (T1/T2).

- [ ] **Step 1: Write the failing test** — in `cli.rs` tests (mirror `reputation_flag_parses` at :371):
```rust
#[test]
fn rules_flag_parses() {
    let cli = Cli::try_parse_from(["ppcap", "analyze", "x.pcap", "--rules", "r.rules"]).unwrap();
    match cli.command { Command::Analyze { rules, .. } => assert_eq!(rules.as_deref(), Some("r.rules".as_ref())), _ => panic!() }
}
```
(Match the actual `rules` field type — `Option<PathBuf>` or `Option<String>`; mirror how the existing flags are typed.)

- [ ] **Step 2: Run to verify it fails** — `cd engine && cargo test -p ppcap-cli rules_flag` → FAIL.

- [ ] **Step 3: Implement** — in `cli.rs`:
  - Add to `Command::Analyze`: `/// Apply a Suricata-style ruleset (content matches → findings). \n #[arg(long)] rules: Option<PathBuf>,` (mirror `--reputation` at :63).
  - Destructure `rules` (:133).
  - After `analyze` builds `out` (and before/after the reputation block), if `let Some(path) = rules`: `std::fs::read_to_string(path)` (map_err → anyhow usage error); `let parsed = ppcap_core::parse_rules(&text)`; open the pcap (`File::open` + len) and `let rf = ppcap_core::apply_rules(reader, len, &parsed.rules)`; `out.summary.apply_findings(&rf); out.summary.findings.extend(rf.clone());` then `eprintln!("rules: {} loaded, {} skipped, {} matches", parsed.rules.len(), parsed.skipped.len(), rf.len());` (+ optionally one stderr line per skipped sid/reason). Confirm `summary.findings` is the right field + that `apply_findings` is `pub`.

- [ ] **Step 4: Run to verify it passes** — `cd engine && cargo test -p ppcap-cli rules_flag` → PASS.

- [ ] **Step 5: Commit**
```bash
git add engine/crates/ppcap-cli/src/cli.rs
git commit -m "feat(cli): --rules flag applies an imported ruleset to the summary"
```

- [ ] **Step 6: Full gate** — `cd engine && export PATH="/c/Users/ravid/.cargo/bin:$PATH"`:
```bash
cargo fmt --all -- --check; echo "fmt: $?"
cargo clippy --workspace --all-targets -- -D warnings 2>&1 | tail -6; echo "clippy EXIT: ${PIPESTATUS[0]}"
cargo test -p ppcap-core -p ppcap-cli 2>&1 | tail -12; echo "test EXIT: ${PIPESTATUS[0]}"
cargo tree -p ppcap-core -e no-dev | grep -Ei "zstd-sys|lz4-sys|cc |cmake|bzip2-sys|openssl-sys|zlib-sys" || echo "C-FREE OK"
cd engine/crates/ppcap-wasm && cargo build --target x86_64-pc-windows-gnu 2>&1 | tail -5; echo "wasm build EXIT: ${PIPESTATUS[0]}"
```
All green. `git diff --stat engine/Cargo.lock engine/crates/ppcap-wasm/Cargo.lock` → expect empty (no new deps). If changed, commit both.

- [ ] **Step 7: Commit any fmt/lockfile fixups** (only if changed).

---

## Self-Review

**1. Spec coverage:** the parser + matcher (T1) → spec §1; `apply_rules` + `RuleMatch` (T2) → §2-3; the CLI flag + gate (T3) → §5. Skip-unsupported, dedupe, no-panic, apply_findings uplift, no-deps, wasm-safe — all covered. WASM/Tauri/UI + full DSL out of scope. ✓

**2. Placeholder scan:** complete code for the types, `matches`, `apply_rules` skeleton + `rule_finding`, the CLI flag; the parser body is specified concretely with the option list + decode rules and is pinned by the T1 test contract. The NOTEs (the exact L4-payload-offset extraction + the reader iteration API → mirror `extract_flow_packets`/`carve_pcap`; the exhaustive `FindingKind` match sites → grep; the CLI field type → mirror `--reputation`; the `Severity` import path) are concrete in-repo verifications. ✓

**3. Type consistency:** `Rule{proto:RuleProto, dst_port:Option<u16>, content:Vec<u8>, …}` (T1) ⇄ `Rule::matches(Transport, u16, &[u8])` ⇄ `apply_rules(reader, len, &[Rule]) -> Vec<Finding>` (T2) ⇄ `FindingKind::RuleMatch` ⇄ `apply_findings(&[Finding])` ⇄ CLI `parse_rules`/`apply_rules`/`apply_findings` (T3). `RuleParse{rules, skipped}` consistent throughout. ✓
