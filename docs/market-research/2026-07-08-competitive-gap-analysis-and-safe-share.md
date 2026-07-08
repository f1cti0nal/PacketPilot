# Market research & feature plan — Safe Share (PCAP sanitization)

*Date: 2026-07-08 · Status: **proposal, awaiting approval** · Owner: product/eng*

This document (1) summarizes competitive market research into the PCAP-triage /
network-forensics landscape, (2) identifies the gaps PacketPilot could address next, and
(3) proposes a concrete, feasible flagship feature — **Safe Share**, one-click PCAP
sanitization — with scope, implementation approach, and success criteria.

> **Approval gate:** this is a research + planning artifact. No implementation, merge, or
> deploy has been done. Items 6–8 of the originating request (implement → merge to
> production → announce) are intentionally **not** executed autonomously and are pending
> human sign-off.

---

## 1. Market & competitive landscape

The market splits into three tiers, and PacketPilot occupies a real gap between them:

- **Manual protocol analyzers** — Wireshark/tshark, NetworkMiner, A-Packets, CloudShark.
  Powerful dissection but *no automated verdict*; "requires manual examination and expert
  interpretation to detect threats." No severity, no triage.
- **Heavy NDR / full-packet infra** — Arkime, Zeek, Suricata, Malcolm, Corelight, ExtraHop,
  Vectra. Automated detection but demand significant deployment, storage, tuning (Arkime
  wants 64–128 GB RAM/node and a "steep learning curve").
- **Emerging local-LLM PCAP tools** — AI-PCAP-Analyzer, mcpcap, TracePcap, MCP-based
  analyzers. Validate the "local LLM + pcap" thesis but are early and thin. This is the
  fastest-moving competitive threat and the "AI + local pcap" positioning is no longer
  unclaimed.

PacketPilot's **local-first, one-click, no-infra, explainable-scoring** position is
defensible, but the window on the AI-pcap angle is not indefinite.

## 2. Gaps & unmet needs (what users ask for / struggle with)

Ranked by strategic value × feasibility for a local-first Rust/React tool. Full evidence
with URLs is in the research appendix at the end.

| # | Gap / unmet need | Segment | Demand | Feasibility | PacketPilot status |
|---|---|---|---|---|---|
| 1 | Large-pcap ingest without OOM/crash | All | Very high | High | ✅ Core moat (streaming engine) |
| 2 | Automated **explainable** verdict/severity | SOC/MSSP | Very high | High | ✅ Shipped (report cards, ATT&CK) |
| 3 | **Keyless encrypted-traffic** analysis (QUIC/HTTP3, TLS 1.3/ECH) | Hunters/neteng | High, rising | Medium | ⚠️ JA4/JA4+/HASSH yes; no QUIC/HTTP3 decode |
| 4 | **Retrospective re-scan** vs new intel ("time machine") | DFIR/hunters | Med-high | Med-high | ❌ Not offered by any local tool |
| 5 | **PCAP anonymization/sanitization** for safe sharing | DFIR/MSSP | Medium | **High** | ❌ Absent |
| 6 | Collaboration / annotation / shareable reporting | Teams/MSSP | Med-high | Medium | ◐ HTML/JSON/CSV/STIX export; single-user |
| 7 | Natural-language querying (escape display-filter learning curve) | Tier-1/students | Rising | High | ✅ AI analyst assist |
| 8 | Behavioral detections (beaconing/DNS-tunnel/DGA/scan/exfil) | Hunters/DFIR | High | High | ✅ Shipped (12+ detections) |
| 9 | IoT/OT/ICS protocol triage (Modbus/DNP3/S7comm/BACnet) | OT security | Med (niche) | Medium | ◐ `IotOt` category, no dissectors |
| 10 | No-silent-failure reliability + file carving | All (Brim users) | Medium | High | ✅ Carving shipped; never-panic engine |
| 11 | Remote / PCAP-over-IP / live capture | SOC/neteng | Medium | Medium | ◐ live-traffic planned |
| 12 | Cross-platform + zero-install access | Mac/Linux/consultants | Low-med | High | ✅ Tauri (all-OS) + web build |

**Interpretation:** PacketPilot already answers the biggest universal pains (#1, #2, #8, and
much of #7/#10/#12). The open, high-leverage opportunities are **#5, #4, and #3**, in
ascending order of build cost.

## 3. Recommendation — flagship: **Safe Share** (Gap #5)

**Pick: one-click PCAP sanitization/anonymization.** Chosen over #4 and #3 because it has the
best value-to-effort ratio, is self-contained in the Rust engine (a deterministic
read→transform→write pass), is highly testable, carries low architectural risk, and turns
PacketPilot's flagship "captures never leave the device" promise into an *active, marketable*
feature. It serves a real, recurring, compliance-driven need (GDPR / NIST IR 8053) that is
today met only by clunky standalone tools (TraceWrangler, SafePcap, `editcap` slicing), and
it unlocks the DFIR/MSSP escalation workflow: **sanitize → share → escalate to vendor/CERT**.

Feasibility is already grounded in the codebase: the engine has pcap/pcapng readers
(`reader/pcap.rs`, `reader/pcapng.rs`, gzip) *and* a pcap container **writer**
(`gen/container.rs`), plus a clean CLI `Subcommand` enum. Sanitize slots in as a new pass
reusing all of it.

### Scope (v1)

**In scope**
- New engine capability + CLI subcommand `ppcap sanitize <in> --out <out.pcap> [options]`.
- Deterministic, **consistent** anonymization (same input value → same output value within a
  run, so flows/conversations remain analyzable after scrubbing):
  - **IP addresses** — prefix-preserving pseudonymization (Crypto-PAn-style) for IPv4 and
    IPv6, keyed by a per-run secret; option to preserve/scrub subnet structure.
  - **MAC addresses** — pseudonymize, preserving OUI optionally.
  - **Layer-4 payloads** — zero/scrub by default; keep headers so protocol/flow structure
    and severity heuristics still apply. Option to retain first N bytes for protocol ID.
  - **Selective L7 field redaction** — DNS query names, HTTP Host/URI/auth headers, TLS SNI,
    cleartext credentials → replaced with stable tokens.
  - **Checksum recompute** for L3/L4 so the output is a valid, tool-loadable pcap.
- **Sanitization manifest** — a JSON sidecar recording *what* was transformed (counts by
  category, options used, SHA-256 of input and output) for chain-of-custody, **without**
  leaking the original values or the mapping key.
- UI: an **"Export sanitized capture"** action alongside the existing report export, with a
  small options panel (payload scrub level, preserve-prefix toggle) and a preview of what
  will be redacted.
- Round-trips through both pcap and pcapng; preserves timestamps by default (with an
  optional time-shift/jitter to blunt timing correlation).

**Out of scope (v1)**
- Reversible/re-identifiable mapping export (deliberately omitted — keeps the tool from
  becoming a de-anonymization oracle).
- Deep per-application payload rewriting beyond the listed L7 fields.
- OT/ICS-specific field redaction (revisit if Gap #9 is pursued).

### Implementation approach

1. **`engine/crates/ppcap-core/src/sanitize/`** — new module: an `Anonymizer` that owns the
   keyed transforms (IP/MAC/payload/L7) and a `sanitize_stream(reader, writer, opts)` that
   walks packets via the existing streaming reader, mutates in place, recomputes checksums,
   and writes via the `gen/container.rs` writer path. Bounded memory, single pass — same
   discipline as `analyze`.
2. **Crypto-PAn** prefix-preserving IP transform (well-specified; ~150 LOC, no external C
   deps) keyed by a random per-run 128-bit secret held only in memory.
3. **CLI** — extend the `Subcommand` enum with `Sanitize { input, out, manifest, payload,
   preserve_prefix, time_shift, .. }`.
4. **Tauri command + React UI** — `sanitize_capture` command mirroring the analyze/export
   commands; wire the export button and options panel; gate advanced options behind Pro if
   product wants (align with existing Free/Pro split — TBD with product).
5. **Manifest** emitted next to the output; surface a summary toast in the UI.

### Success criteria

- **Correctness:** output pcap/pcapng loads cleanly in Wireshark and re-analyzes in
  PacketPilot; L3/L4 checksums valid; packet/flow counts preserved.
- **Consistency:** identical input addresses map to identical outputs within a run; distinct
  inputs stay distinct (no collisions on the test corpus); prefix relationships preserved
  when the option is on.
- **Privacy:** no original IP/MAC/SNI/DNS-name/credential string appears anywhere in the
  output pcap or the manifest (verified by a scanning test over the fixtures).
- **Performance:** sanitize throughput within ~2× of `analyze` on the same file; bounded
  peak heap (same streaming budget, ~<64 MiB working set).
- **Tests:** engine unit tests (each transform + checksum), a golden round-trip integration
  test on generated + real-ish fixtures, and a UI e2e for the export flow. All existing CI
  gates (fmt, clippy, typecheck, unit, e2e) stay green.
- **Docs:** README quickstart snippet + a short "Sharing captures safely" doc.

### Risks & mitigations
- *Over-scrubbing breaks downstream analysis* → default keeps headers + structure; payload
  scrub level is a knob; validated by "re-analyze after sanitize" test.
- *Weak anonymization gives false confidence* → prefix-preserving crypto transform + explicit
  documentation of what is and isn't protected; time-shift option for timing correlation;
  no reversible-mapping export.
- *pcapng edge cases (multi-interface, options blocks)* → reuse the hardened existing
  pcapng reader; fall back to per-packet copy of unknown blocks.

## 4. Backlog (documented for future consideration)

- **#4 Retrospective "Time Machine" re-scan** — persist lightweight per-capture flow/IOC
  indices; re-evaluate against updated reputation/MISP/Sigma feeds; alert when a
  previously-clean indicator later turns dirty. High differentiation (no local tool offers
  it), natural **Pro-tier** hook, medium build. Strong candidate for the *next* cycle.
- **#3 Keyless encrypted-traffic analysis (QUIC/HTTP3, TLS 1.3/ECH)** — first-class QUIC/HTTP3
  decode + packet-length/inter-arrival behavioral scoring without keys. Highest strategic
  payoff, largest build; sequence after Time Machine.
- **#9 IoT/OT/ICS triage** — targeted vertical (Modbus/DNP3/S7comm/BACnet dissect + scoring)
  if an OT go-to-market is pursued.

## 5. Recommendation if not approved

If the team prefers a different bet: **Time Machine (#4)** is the higher-differentiation,
higher-ceiling play and the better monetization hook, at roughly 2–3× the build cost and with
some SaaS-backend/feed-scheduling surface. **Safe Share (#5)** is recommended first because it
ships fast, de-risks with crisp criteria, and strengthens brand positioning that the other
features build on (sanitize-then-share underpins collaboration #6). If research had shown no
viable gap the recommendation would be to hold — but the landscape shows several concrete,
cited, addressable gaps, so proceeding is warranted.

---

## Appendix — research evidence (cited)

- **Scale / OOM:** Wireshark `KnownBugs/OutOfMemory`
  (https://wiki.wireshark.org/KnownBugs/OutOfMemory); packet-foo "notorious out-of-memory"
  (https://blog.packet-foo.com/2013/05/the-notorious-wireshark-out-of-memory-problem/);
  Netresec "Analyzing 85 GB of PCAP in 2 hours"
  (https://www.netresec.com/?page=Blog&month=2013-01&post=Analyzing-85-GB-of-PCAP-in-2-hours).
- **No automated verdict / triage load:** LabEx Wireshark threat detection
  (https://labex.io/tutorials/wireshark-how-to-detect-network-security-threats-using-wireshark-in-cybersecurity-415263);
  Expel SOC ops (https://expel.com/cyberspeak/optimizing-soc-operations/); Corelight agentic
  triage (https://corelight.com/blog/agentic-triage-soc-transformation).
- **Encrypted / QUIC / JA4:** parsing decrypted QUIC
  (https://blog.elmo.sg/posts/parsing-decrypted-quic-traffic-in-wireshark/); QUIC-Exfil
  (https://arxiv.org/html/2505.05292v1); JA3 limits
  (https://fingerprint.com/blog/limitations-ja3-fingerprinting-accurate-device-identification/);
  Cloudflare JA4 signals (https://blog.cloudflare.com/ja4-signals/); Omdia NDR 2026
  (https://omdia.tech.informa.com/blogs/2026/may/network-detection-and-response-ndr-market-2026-navigating-xdr-disruption-platform-consolidation-and-ai-driven-renaissance).
- **Retrospective re-scan:** OpenText Smart PCAP
  (https://blogs.opentext.com/smart-pcap-a-time-machine-for-the-soc/); Fortinet Retrospective
  IoC (https://docs.fortinet.com/document/fortianalyzer/6.2.0/new-features/894000/retrospective-ioc-history-scan-threat-hunting);
  ExtraHop retrospective detection
  (https://www.extrahop.com/resources/papers/automated-retrospective-detection).
- **PCAP anonymization / compliance:** PacketSafari "How to anonymize a PCAP"
  (https://packetsafari.com/blog/2025/how-to-anonymize-a-pcap); TraceWrangler
  (https://www.tracewrangler.com/); SafePcap / NIST IR 8053 (https://omnipacket.com/safepcap);
  OPSWAT PCAP anonymization
  (https://www.opswat.com/blog/protecting-sensitive-data-with-ai-enhancement-and-pcap-anonymization).
- **Collaboration:** CloudShark (https://www.qacafe.com/analysis-tools/cloudshark); qacafe IR
  with pcaps (https://www.qacafe.com/resources/how-to-improve-incident-response-with-pcaps);
  DFIR-IRIS (https://www.dfir-iris.org/).
- **Local-LLM pcap competitors:** AI-PCAP-Analyzer
  (https://github.com/privatefound/AI-PCAP-Analyzer); mcpcap (https://github.com/mcpcap/mcpcap);
  Amaze-with-AI/PCAP-Analyzer (https://github.com/Amaze-with-AI/PCAP-Analyzer); TracePcap
  (https://github.com/NotYuSheng/TracePcap).
- **Behavioral detection:** Hunt.io C2 beaconing (https://hunt.io/glossary/c2-beaconing);
  ActiveCM threat-hunting labs (https://activecm.github.io/threat-hunting-labs/beacons/); DNS
  tunneling survey (https://arxiv.org/pdf/2507.10267).
- **OT/ICS:** ITI ICS-Security-Tools PCAP repo
  (https://github.com/ITI/ICS-Security-Tools/blob/master/pcaps/README.md); Shieldworkz NDR 2026
  (https://shieldworkz.com/comprehensive-guide-to-network-detection-and-response-ndr-in-2026).
- **Brim/Zui silent-failure:** zui#790 (https://github.com/brimdata/zui/issues/790); zui#633
  (https://github.com/brimdata/zui/issues/633); zui#1104
  (https://github.com/brimdata/zui/issues/1104); zui#2304
  (https://github.com/brimdata/zui/issues/2304).
</content>
</invoke>
