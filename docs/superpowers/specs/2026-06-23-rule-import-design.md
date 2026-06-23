# Suricata-style rule import (phase A) — Design Spec

**Status:** approved design, pre-plan
**Date:** 2026-06-23
**Branch:** `feat/rule-import`

## Goal

Bring-your-own detection: load a user-supplied Suricata/Snort-style ruleset and apply matches as `Finding`s, extending detection beyond the built-in behavioral detectors. Phase A ships an engine rule parser + a content matcher + a decoupled pcap pass + a CLI `--rules` flag. WASM/Tauri/UI surfacing is deferred to phase B.

## Architecture

Rule matching needs packet payloads, which the analysis summary does not retain. Rather than thread user rules through the per-packet `decode` (invasive — `decode_frame` is a pure, config-free per-frame fn), rule matching runs as a **decoupled second pass over the pcap**: `apply_rules` re-reads the capture via the existing `open_reader` (the same re-read pattern carve/drilldown use), decodes each frame for proto/ports, extracts the L4 payload, matches it against the rules, and returns `Finding`s. The summary's existing `apply_findings` folds them in (uplifting the per-IP threat cards), exactly like the built-in findings. This mirrors the reputation/SNI enrichment seam (`apply_X(&mut summary, …)`).

**Tech stack:** Rust (ppcap-core engine + ppcap-cli). No new deps. Pure compute — C-free + wasm-safe (so phase B can reuse the parser/matcher unchanged).

## Global Constraints

- **No new deps.** C-free gate (ppcap-core) stays empty; `rules` is pure compute (wasm-safe — no `std::{net,time}`; `apply_rules` reads via the already-used `open_reader`).
- **Never panics / never silently mis-matches.** A malformed rule line → skipped with a reason (never a hard error). A rule using matching constructs we do NOT model (pcre, multiple/relative contents, content modifiers) → **skipped with a reason**, never matched approximately.
- **Findings behave like built-ins** — `FindingKind::RuleMatch` flows through `apply_findings` (threat-card uplift) + `summary.findings` + the report/JSON, with the standard `Finding` fields.
- Run cargo from `engine/`; `cargo fmt` before commit. Gate: `cargo test` (core + cli), clippy `-D warnings`, C-free, ppcap-wasm build.

## Reference: the seams (verified)

```
// engine/crates/ppcap-core/src/model/finding.rs  Finding { kind: FindingKind, severity, score, title, src_ip, dst_ip: Option<String>, dst_port: Option<u16>, attack: Vec<String>, evidence: Vec<String>, interval_ns, jitter_cv, contacts }
//   enum FindingKind { Beacon, HostSweep, BruteForce, CleartextCreds, PiiExposure, LateralMovement, DataExfil, DnsTunnel }  ← add RuleMatch
// engine/crates/ppcap-core/src/stats/mod.rs:386  pub fn apply_findings(&mut self, findings: &[Finding])  (uplifts IpThreat cards; never lowers)
// engine/crates/ppcap-core/src/reader/mod.rs  open_reader(reader, len) -> Reader yielding RawFrame { data, link_type, ts_ns, cap_len, wire_len }
// engine/crates/ppcap-core/src/decode/mod.rs  decode_frame(&RawFrame) -> Result<PacketMeta { transport: Transport, src_ip, dst_ip, src_port, dst_port, ... }> ; the L4 payload is computed from RawFrame.data (see extract_flow_packets/carve_pcap in packets.rs for the offset pattern)
// engine/crates/ppcap-core/src/packets.rs  carve_pcap/extract_flow_packets — the open_reader re-read + per-frame decode + payload-slice pattern to mirror
// engine/crates/ppcap-cli/src/cli.rs  the Analyze subcommand + the `--reputation` flag (:63/:133/:191) + the apply_X fold (:225) — mirror for `--rules`
// engine/crates/ppcap-core/src/lib.rs  re-export apply_rules / parse_rules / Rule / RuleParse
```

## Components

### 1. `engine/crates/ppcap-core/src/detect/rules.rs` (new) — parser + matcher
```rust
pub struct Rule {
    pub action: String,        // "alert" (others accepted, treated the same in phase A)
    pub proto: RuleProto,      // Tcp | Udp | Ip (Ip = any transport)
    pub dst_port: Option<u16>, // None = any
    pub content: Vec<u8>,      // the (single) content match, ASCII + |hex| decoded
    pub msg: String,
    pub sid: u32,
    pub mitre: Vec<String>,    // ATT&CK ids parsed from metadata, e.g. ["T1071"]
    pub severity: Severity,    // default Medium; from a classtype/priority if present, else Medium
}
pub enum RuleProto { Tcp, Udp, Ip }

pub struct RuleParse { pub rules: Vec<Rule>, pub skipped: Vec<SkippedRule> }
pub struct SkippedRule { pub line: u32, pub sid: Option<u32>, pub reason: String }

/// Parse a ruleset (one rule per non-comment line). Never errors; unparseable or
/// unsupported rules go to `skipped` with a reason.
pub fn parse_rules(text: &str) -> RuleParse;

impl Rule {
    /// Match a packet by transport, destination port, and a content substring in the payload.
    pub fn matches(&self, transport: Transport, dst_port: u16, payload: &[u8]) -> bool;
}
```
- Grammar: `<action> <proto> <src> <sport> <dir> <dst> <dport> ( <opts> )`. Phase A parses `action`, `proto` (tcp/udp/ip; else skip), and `dport` (a `u16` or `any`; ignore `src`/`sport`/`dst`/`dir`). Options: `msg:"…"`, `content:"…"` (ASCII with `\"`,`\\`,`\:` escapes + `|00 1a ff|` hex runs), `sid:N`, `metadata:…` / `reference:…` scanned for `Txxxx` ATT&CK ids, `classtype`/`priority` → severity (optional; default Medium).
- **Skip (with reason)** any rule that: has no `content` (phase A is content-only); has `pcre:`; has MORE than one `content:`; has relative/modifier keywords that change matching (`nocase`, `depth`, `offset`, `distance`, `within`, `http_*`, `byte_test`, `flowbits`, `dsize`); has an unparseable `sid`/port; or whose proto isn't tcp/udp/ip. (Honest: we never approximate a rule we can't honor exactly. `nocase` could be supported later — phase A is case-sensitive only, so a `nocase` rule is skipped rather than mis-matched.)

### 2. `apply_rules` (in `detect/rules.rs` or `detect/mod.rs`)
```rust
/// Re-read the capture and return one Finding per (sid, src, dst, dst_port) whose payload
/// matched a rule. Bounded; never panics; no payloads retained.
pub fn apply_rules<R: Read>(reader: R, len: Option<u64>, rules: &[Rule]) -> Vec<Finding>;
```
- `open_reader(reader, len)` → for each `RawFrame`: `decode_frame` → `(transport, src_ip, dst_ip, dst_port)`; compute the L4 payload slice from `RawFrame.data` (mirror `extract_flow_packets`/`carve_pcap`); for each rule, `rule.matches(transport, dst_port, payload)` → insert into a dedupe set keyed `(sid, src_ip, dst_ip, dst_port)`; first hit builds a `Finding { kind: RuleMatch, severity: rule.severity, score: <band of severity>, title: rule.msg, src_ip, dst_ip: Some, dst_port: Some, attack: rule.mitre, evidence: ["rule sid:N", "matched content …(escaped/elided)"] }`.
- Bound the work: cap total rule-findings (e.g. `MAX_RULE_FINDINGS = 5000`) to avoid pathological output; cap the per-payload scan to the captured bytes.

### 3. `model/finding.rs`
Add `FindingKind::RuleMatch` (doc: "User signature-rule match (imported Suricata-style ruleset)."). Ensure any exhaustive `match FindingKind` (serialization, report labels, category mapping) handles the new variant — grep + update each.

### 4. `lib.rs`
Re-export `parse_rules`, `apply_rules`, `Rule`, `RuleProto`, `RuleParse`.

### 5. `engine/crates/ppcap-cli/src/cli.rs`
Add `--rules <PATH>` to `Analyze` (mirror `--reputation`). After `analyze`: read the file; `parse_rules`; `apply_rules(File::open(path), len, &rules)`; `summary.apply_findings(&rule_findings)` + `summary.findings.extend(rule_findings)`; print to **stderr** "rules: N loaded, M skipped, K matches" (+ each skipped sid/reason at a verbose level or concisely). Errors reading the file → an `anyhow` usage error (CLI-only).

## Data flow & error handling

`analyze(pcap)` → summary. If `--rules`: parse the ruleset (valid → `rules`, rest → `skipped`+reported) → `apply_rules` re-reads the pcap, matches payloads, returns deduped `Finding`s → `apply_findings` uplifts threat cards + `findings.extend` → the JSON/report surfaces them. A malformed rule never aborts; a pcap read error in the rules pass is reported but does not corrupt the already-built summary. No payloads stored.

## Testing

- **`parse_rules`:** a canonical `alert tcp any any -> any 443 (msg:"x"; content:"abc"; sid:1; metadata:mitre T1071;)` → the struct (proto Tcp, dst_port Some(443), content `abc`, mitre `["T1071"]`); `content:"|41 42|C"` → bytes `AB` + `C`; `-> any any` → dst_port None; a `pcre:` rule, a two-`content` rule, a `nocase` rule, a no-`content` rule → each `skipped` with a distinct reason; a junk line → skipped, the next valid rule still parses.
- **`Rule::matches`:** payload contains content + right proto + right port → true; wrong port / wrong proto / content absent → false; `dst_port None` matches any port.
- **`apply_rules`:** a crafted 1-flow pcap whose TCP payload contains `"abc"` + a `content:"abc"` sid:1 rule → exactly one `Finding` (RuleMatch, sid in evidence, msg as title, src/dst/port set); repeated across many packets of the same flow → still ONE (dedupe); no-match pcap → empty.
- **`apply_findings` integration:** a RuleMatch finding uplifts the endpoint threat cards (reuse the existing apply_findings test pattern).
- **CLI:** `--rules <tmpfile>` parses + the analyzed summary gains the finding (or a parse test like the `--reputation` flag test). Gate: `cargo test` (core + cli) green, clippy `-D warnings`, C-free empty, ppcap-wasm builds.

## Out of scope (phase B)

WASM/Tauri/UI load-rules + consent + a "rules" panel; the full Suricata DSL (pcre, flowbits, byte_test/byte_jump, thresholds/detection_filter, http/tls/dns sticky buffers, IP/port lists/ranges/negation, content modifiers `nocase`/`depth`/`offset`/`distance`/`within`, multiple contents); YARA on carved files; rule-source management/update. Phase A is a single content match per rule, TCP/UDP/IP + dst-port, CLI-only.

## File manifest

**Engine — create:** `engine/crates/ppcap-core/src/detect/rules.rs` (parser + matcher + `apply_rules` + tests).
**Engine — modify:** `engine/crates/ppcap-core/src/detect/mod.rs` (`pub mod rules;`), `engine/crates/ppcap-core/src/model/finding.rs` (`RuleMatch` variant + exhaustive `match` sites), `engine/crates/ppcap-core/src/lib.rs` (re-exports), `engine/crates/ppcap-cli/src/cli.rs` (`--rules` flag + fold).
**No new deps; no WASM-export/Tauri/UI change (phase B).**
