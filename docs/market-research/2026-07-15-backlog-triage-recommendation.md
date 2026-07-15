# Market research & recommendation — pause new proposals, triage the backlog

*Date: 2026-07-15 · Author: automated market-research routine · Status: **findings + recommendation, no new proposal***

---

## TL;DR

This run's honest conclusion is **not** a new feature proposal. The core PCAP-triage feature
space PacketPilot targets is **saturated**, and the routine has already produced a **backlog of
four open, unapproved proposals** — one of which (#128) explicitly recommended pausing new
proposals until the queue is triaged. Stacking a fifth would add noise, not value.

**Recommended action for the maintainer:** triage the existing backlog (approve/decline #117 and
#128, and de-duplicate #125/#127) rather than commission more research. The bottleneck is a human
decision, not a shortage of ideas.

---

## 1. What this run did

1. Re-read the product (`README.md`, `docs/PROJECT-SPEC.md`), the shipped roadmap, and the prior
   market-research output (`docs/market-research/2026-07-08-artifact-extraction.md`, shipped as
   #116).
2. Enumerated the open GitHub issue backlog for `f1cti0nal/packetpilot`.
3. Ran a fresh 2025–2026 market scan (Wireshark/NetworkMiner alternative roundups, packet-analyzer
   comparisons) to check for any *new* gap not already in the pipeline.

## 2. Market scan — no new gap

The 2026 tool-comparison literature keeps surfacing the same short list of differentiators and
pain points, all of which PacketPilot has already shipped or already has a pending proposal for:

| Recurring 2025–2026 theme | Status in PacketPilot |
|---|---|
| **Artifact / file extraction** from captures (NetworkMiner's flagship) | ✅ **Shipped** — carve-to-disk (#116) |
| **Batch / high-volume triage** of many captures | 📋 Proposed — **#125** (Case Triage) & **#127** (Fleet Triage) — *duplicates* |
| **Encrypted-traffic (TLS 1.3 / QUIC) content inspection** with operator-held keys | 📋 Proposed — **#128** (headless `--keylog` decryption) |
| **Safe sharing / anonymization** (share pcaps without leaking data) | 📋 Proposed — **#117** (Safe Share) |
| Cross-capture **correlation** (same IOC across N captures) | 📋 Folded into #125 |
| SIEM / detection-rule interop (STIX/MISP/CEF/Sigma) | ✅ Shipped (`export/mod.rs`) |
| Steep learning curve / manual filtering | ✅ Addressed (summary-first triage + explainable severity) |

Nothing in the scan pointed to a distinct, well-validated gap outside this set. The one adjacent
idea worth *noting* (not proposing) is **passive/active enrichment beyond the wire** — e.g.
optional active probing of hosts seen in a capture, which NetworkMiner deliberately does **not**
do. It conflicts with PacketPilot's local-first, "captures never leave the device" ethos and is
**not recommended**.

Sources: cybersecuritynews.com (network packet analyzer tools, 2026); thectoclub.com (Wireshark
alternatives, 2026); netcontroler.com (NetworkMiner forensic overview); goworkwize.com &
codeitbro.com (alternatives roundups); github.com/caesar0301/awesome-pcaptools. Plus the sourcing
already captured in the four open proposals.

## 3. The real finding — an approval backlog, not a feature gap

| Issue | Proposal | Opened | State |
|---|---|---|---|
| **#117** | Safe Share (sanitize / anonymize) | 2026-07-08 | Open, unapproved |
| **#125** | Batch / **Case** Triage (correlate, don't merge) | 2026-07-10 | Open, unapproved |
| **#127** | Batch / **Fleet** Triage (ranked incident index) | 2026-07-12 | Open, unapproved — **substantially duplicates #125** |
| **#128** | Headless keylog decryption (`analyze --keylog`) | 2026-07-13 | Open, unapproved |

Every one of these is research-and-plan-complete with an implementation branch, and every one is
**correctly parked at an approval gate** (implementation/PR/merge/release intentionally not
started). The routine is doing its guardrails right — but it is now producing proposals faster
than they are being triaged, and it has started to **duplicate itself** (#127 ≈ #125). Issue #128
already called this out and recommended pausing.

## 4. Recommendation

1. **Do not commission more feature research** until the queue clears. (This run deliberately does
   not open a fifth issue.)
2. **De-duplicate the batch-triage pair:** keep **#125** (the richer superset — adds cross-capture
   correlation + case report) and close **#127** as a duplicate, or explicitly merge #127's
   CSV-index framing into #125's scope.
3. **Make one pick to actually build.** On value-to-effort, the strongest single candidate is
   **#125 Batch / Case Triage** — it is largely orchestration/aggregation over already-tested
   single-capture code (bounded-memory preserved, no new decode logic) and answers the
   best-validated remaining workflow pain (volume). **#117 Safe Share** is the best *brand-fit*
   pick (activates the local-first promise) and is self-contained/low-risk. **#128 keylog** has the
   highest analytical ceiling but carries a real bounded-memory design decision that needs sign-off
   first.
4. **Then let the routine implement the approved one** — branch, tests, PR, CI — per the normal
   flow. That is where the next unit of real value is, not in a new proposal.

## 5. Why no issue was created this run

The task template's final clause covers exactly this case: *"If research reveals no clear gaps or
the feature is not feasible, document findings and recommendations for future consideration."* The
research revealed **no new clear gap** and an existing **approval bottleneck**, so the right output
is this document plus a heads-up to the maintainer — not another entry in a queue that is already
waiting on a human.
