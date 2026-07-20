# Market research & feature planning — 2026-07-11

*Author: automated market-research routine · Status: **findings + recommendation, awaiting a maintainer decision***

---

## TL;DR — the bottleneck is approval, not ideas

This routine ran again today. Before proposing anything new, it checked the state of prior runs.
**Two fully-researched feature proposals are already open and unactioned**, each correctly stopped
at its approval gate:

| Issue | Feature | Opened | Plan / branch | State |
|---|---|---|---|---|
| **#125** | **Batch / Case Triage** — a folder of pcaps → one ranked index + cross-capture indicator correlation | 2026-07-10 | `docs/market-research/2026-07-10-batch-case-triage.md` · `claude/cool-dijkstra-u1rlzy` | OPEN, unapproved |
| **#117** | **Safe Share** — one-click pcap sanitization / anonymization | 2026-07-08 | `docs/market-research/2026-07-08-competitive-gap-analysis-and-safe-share.md` · `claude/cool-dijkstra-tr3b86` | OPEN, unapproved |

Meanwhile the previous run's pick (**Artifact Extraction / carve-to-disk**) *was* approved and
shipped — merged as **#116**. So the lifecycle works end-to-end; it is simply **waiting on a human
"go" for the next feature.** Generating a third proposal would add noise to a backlog that already
has two strong, unbuilt options. **The most useful output of this run is a decision, not another plan.**

---

## 1. This run's market research (2025–2026)

Fresh competitive scan of the pcap-analysis / network-forensics / NDR landscape (Wireshark/tshark,
NetworkMiner, Arkime/Malcolm, Brim/Zui, Sniffnet, Suricata/Zeek, CloudShark, Hatching Triage,
Corelight, and the new AI entrants — PcapAI, PacketSafari, TracePcap, A-Packets, Cisco/Meraki AI
PCAP Analyzer).

**Key market signal:** a wave of **AI-assisted, increasingly local-first** entrants is converging
on *exactly* PacketPilot's thesis (one-click triage, "packets never leave the device"). This both
**validates** the direction and means **the window is closing** — several competitors now market the
same positioning. Moving on a differentiated, unserved capability soon matters.

### What analysts still ask for / struggle with (documented, sourced)

1. **Working across *many* captures.** DFIR reviews routinely span numerous pcaps that must be
   reconstructed/correlated; IDS/sensor deployments (Suricata alert-pcap, multi-threaded output)
   and malware sandboxes emit *directories* of small captures; MSSPs are volume-constrained and
   value anything that "removes boring triage work." Today's answer is expert-only `mergecap`/
   `editcap`/tshark bash loops that produce **no ranked output**, and **no competitor ships a
   combined ranked index across a directory.** → This is issue **#125 (Batch Triage)**.
2. **Evidence admissibility / reproducibility.** Network evidence needs integrity (crypto hash),
   documented **chain of custody**, and **reproducibility** (ISO/IEC 27037; SWGDE best practices).
   Current pcap tools optimize for speed, not admissibility — **clear white space, net-new** (not
   covered by #117 or #125). *See §3 — new candidate.*
3. **Sanitize-before-share** (compliance-driven, GDPR/NIST) — served today only by clunky
   standalone tools (TraceWrangler, SafePcap). → This is issue **#117 (Safe Share)**.
4. **Deeper file/credential carving** beyond HTTP/FTP (SMB/SMB2, SMTP/IMAP/POP3, TFTP, NTLM/Kerberos)
   — a repeatedly-cited limitation even of NetworkMiner. Extends the carving that just shipped (#116).

### Sources (selected)
DFIR multi-pcap pain: link.springer.com/chapter/10.1007/978-3-031-98036-7_26 · insanecyber.com/mastering-pcap-review ·
Suricata alert-pcap: docs.suricata.io · docs.securityonion.net · sandboxes: cybersecuritynews.com/best-malware-sandbox-tools ·
stamus-networks.com malware-pcap-analysis · MSSP volume: cybermindr.com · any.run mssp-growth-guide ·
current tooling: blog.packet-foo.com pcap-split-and-merge · wireshark.org mergecap · github.com/NotYuSheng/TracePcap ·
AI entrants: pcapai.com · app.packetsafari.com · apackets.com/on-premise-interest · Meraki AI PCAP Analyzer ·
admissibility: forensicfocus.com network-forensics guide · truescreen.io digital-evidence · swgde.org 18-F-002 ·
timeline/correlation: giac.org GCFA timeline · dfirmadness.com super-timeline ·
carving gaps: securityboulevard.com 2025/05 compare-tools-extract-files · netresec.com NetworkMiner ·
skills shortage (positioning): qacafe.com why-packet-analysis-still-matters

---

## 2. Feasibility & value — the two options already on the table

**#125 Batch / Case Triage — RECOMMENDED next build.**
- **Value:** highest-validated, genuinely unserved (no competitor ships a ranked cross-pcap index);
  serves IR/DFIR/consultant/sandbox workflows directly. Best framed as *"a bag of saved captures →
  ranked index,"* **not** mass-SOC monitoring (that lane is owned by streaming sensors — Arkime,
  Corelight, Malcolm).
- **Feasibility: HIGH.** Largely orchestration + aggregation over already-tested single-capture
  code; the DuckDB case schema already unions `{CASE_DIR}/parquet/flow/*.parquet`, so the layout is
  half-built. Sequential fan-out keeps peak heap at one-capture budget.
- **Risk:** low — no new decode/detect code in v1.

**#117 Safe Share — strong, but a positioning play more than a workflow gap.**
- **Value:** turns the "local-first" promise into an active, marketable feature; unlocks
  sanitize→share→escalate. Compliance-driven demand is real but served (clunkily) by existing tools.
- **Feasibility: HIGH**, self-contained in the engine (reader + `gen/container.rs` writer exist).
- **Risk:** anonymization-strength correctness (false confidence) — mitigated in its plan.

**Recommendation:** approve **#125 (Batch Triage)** as the next feature. It closes the last big
*workflow* gap, is the strongest-validated and lowest-risk, and reuses the most existing code.
#117 (Safe Share) is the natural feature after it.

---

## 3. New candidate surfaced this run (net-new, not yet an issue)

**Forensic reproducibility & evidence integrity ("Chain of Custody" mode).**
- **Gap:** admissibility needs input/artifact **crypto-hashing**, a **signed audit manifest**
  (tool version + exact settings + timestamps at each stage), and a **reproducible/re-runnable
  report**. Competitors optimize for speed, not court-readiness — white space.
- **Fit / feasibility: HIGH** — PacketPilot already hashes inputs, carves + hashes artifacts, and
  emits HTML/JSON/PDF reports. This is mostly a **manifest + signing + reproducibility layer** on top
  of the existing report path, not new analysis code.
- **Buyer:** IR/legal/law-enforcement/regulated — higher willingness-to-pay; reinforces the Pro tier.
- **Status:** documented here for consideration. **Deliberately not opened as a third issue** —
  the pipeline already has two unapproved proposals; adding a third before either is picked would
  deepen the backlog rather than help. Promote to an issue once #125/#117 are decided.

---

## 4. Recommendation & the approval gate

1. **Decide the next feature.** Recommended order: **#125 Batch Triage → #117 Safe Share →**
   (new) Chain-of-Custody. Approving one issue unblocks the rest of the lifecycle.
2. **This run intentionally stops here.** Steps 6–8 of the routine — implement, open PR, **merge to
   main, deploy to production, and announce in Slack/release notes** — are hard-to-reverse,
   outward-facing actions gated on *"Once approved."* No human approval has been given, so this
   autonomous run does **not** implement, merge, deploy, or post anywhere. On a maintainer "go"
   (a comment on the chosen issue), the next run implements it in a branch with tests and opens a PR.
