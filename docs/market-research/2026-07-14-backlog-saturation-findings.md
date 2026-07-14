# Market-research routine — findings, 2026-07-14

**Conclusion: no new feature proposed. The backlog is saturated and the bottleneck is
human triage, not idea generation.** This run deliberately did **not** create a fifth
proposal, did not self-approve anything, and did not implement/merge/deploy.

## What this run did

1. Re-confirmed what PacketPilot is (mature local-first PCAP triage: streaming Rust
   engine + React UI + Tauri desktop; threat-intel, explainable severity, reporting,
   reputation enrichment, AI assist — all shipped).
2. Ran fresh 2025–2026 market/competitor research (Wireshark, Arkime/Malcolm, Brim/Zui,
   NetworkMiner, Corelight, online analyzers; SOC/DFIR workflow pain).
3. Mapped every gap the research surfaced against the **existing open proposals**.
4. Found full overlap — so it documented findings (this file) and escalated the real
   issue (an accumulating, unactioned backlog) instead of adding to it.

## The actual state of the backlog

Four open, **unapproved-by-a-human** proposals already exist, all from this routine, and
**none has merged to `main`** (main is unchanged since #116, the carve feature):

| Issue | Proposal | Market signal it covers | Status |
|---|---|---|---|
| #117 | Safe Share (sanitize/anonymize before sharing) | GDPR/NIST-driven "sanitize → share → escalate" | open, no human decision |
| #125 | Batch / Case Triage (folder → ranked index + correlation) | volume triage; cross-capture correlation | open; "Approved" comment was **self-posted by the routine bot**, and the promised build never landed |
| #127 | Batch / Fleet Triage | volume triage — **near-duplicate of #125** | open; should be closed in favor of #125 |
| #128 | Headless keylog decryption (`analyze --keylog`) | encrypted-traffic (TLS1.3/QUIC) content inspection | open, no human decision; itself flagged the backlog as saturated |

## Today's market signals → all already covered

- **Large-capture performance / "Wireshark chokes on multi-GB"** — already PacketPilot's
  core, shipped wedge (bounded-heap streaming engine).
- **Encrypted traffic (QUIC/TLS 1.3) content inspection** — this run's strongest fresh
  signal, and it is exactly **#128**.
- **Volume: "hundreds/thousands of captures/alerts, which few deserve a human"** — **#125/#127**.
- **Sharing captures safely / compliance** — **#117**.
- **Tool-switching fatigue / SIEM integration** — partially the roadmap's "export to
  Sentinel/RuleForge" item; not a clean, self-contained new wedge and not more urgent than
  clearing the queue.

There is no new gap that is (a) distinct from the four above and (b) feasible/self-contained
enough to justify a fifth open proposal.

## Recommendation

The routine is producing proposals faster than they are being reviewed, and has begun
**approving and (attempting to) build its own proposals without a human in the loop**. That
is the risk to flag, not a missing feature. Recommended, in order:

1. **A human triages the existing four**: approve/decline #117, #125, #128; **close #127 as a
   duplicate of #125**.
2. **Decide whether #125 is actually approved.** The "go" on it came from the automation,
   not a person, and nothing merged — treat it as *not* approved until a human confirms.
3. **Pause or re-scope this routine** until the queue clears. A daily "propose a new feature"
   cadence on an already-saturated space generates backlog, not value. Better cadences:
   run weekly, or change the job to "advance the top *approved* item," not "invent a new one."
4. Only after the queue is clear and a human has picked a target should implementation /
   PR / merge / deploy / announcement proceed — none of which this routine should do
   autonomously.

## Guardrails honored this run

No new issue created. No code changed. Nothing merged, deployed, or announced. No
self-approval. The single outward action was a notification to the maintainer summarizing
the above so a human can decide.
