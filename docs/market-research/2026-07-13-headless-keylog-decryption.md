# Market research & feature plan — Headless keylog decryption (whole-capture)

*Date: 2026-07-13 · Author: automated market-research routine · Status: **proposal, awaiting approval***

---

## 0. Read this first — state of the backlog

This routine has run repeatedly and the core PCAP-triage feature space is now **saturated**. Before
proposing anything, this pass audited what is built and what is already proposed:

- **Shipped** (engine + UI): streaming ingest, flow reconstruction, payload-aware classification,
  the full detection suite (beacons, exfil, DGA, port/SYN scan, ARP spoof, ICMP/DNS tunnel,
  cryptomining, cleartext creds, PII, weak/deprecated TLS, cert health, evasive-beacon escalation),
  JA3/JA4/HASSH fingerprinting, IOC + MITRE enrichment + online reputation, explainable severity,
  HTML/JSON report + CSV/STIX/MISP/CEF/Sigma export, **artifact carve-to-disk (#116)**, AI analyst
  assist, SaaS/billing/admin, and — critically for this proposal — **a real 4,500-line TLS 1.2/1.3
  + QUIC decryption engine** (`tls/decrypt.rs`, `tls/http2.rs`, `quic/crypto.rs`, `tls/keylog.rs`).
- **Already proposed, still awaiting maintainer approval** (three open issues):
  - **#117 Safe Share** — sanitize/anonymize a capture for sharing.
  - **#125 Batch / Case Triage** — folder of pcaps → ranked index + cross-capture correlation.
  - **#127 Batch / Fleet Triage** — folder of pcaps → ranked incident index. **This substantially
    duplicates #125.** Recommend the maintainer close one (keep #125, the richer superset) to stop
    the backlog from accumulating near-duplicates.

**Recommendation to the maintainer:** the highest-leverage next action is to *triage the existing
backlog* (approve/decline #117, and dedup #125/#127), not to keep adding proposals. This document
adds exactly one new candidate — and only because it is genuinely distinct from all three above,
is validated by the strongest recurring market signal, and *unlocks* the value of the batch/CLI
proposals rather than competing with them. If the maintainer would rather pause new proposals until
the backlog clears, that is the right call and this can wait.

## 1. Market research — the one gap not yet built or proposed

Fresh 2025–2026 research into what makes PCAP analysts reach for a different tool consistently
surfaces **encrypted traffic** as the single hardest, most-cited problem:

- "Due to QUIC's encrypted nature, inspecting and debugging traffic is challenging; while Wireshark
  gives rich graphical interpretations of TCP flows, the same is *not* true for QUIC."
- Payload inspection of modern TLS 1.3 / QUIC "requires the traffic secrets in the NSS
  **`SSLKEYLOGFILE`** format"; CloudShark 3.10 and Wireshark decrypt when those keys are supplied.
- Analyst tool comparisons list "difficulty analyzing encrypted traffic" among the top standing
  limitations of PCAP tooling in 2026.

Sources: qacafe.com (CloudShark 3.10 QUIC/DoH decryption, 2025); wireshark.org QUIC/TLS keylog docs;
netwitness.com & corelight.com PCAP/NDR glossaries (2026); fidelissecurity.com PCAP best-practices
(2026); arxiv.org 2410.03728 (VisQUIC — SSLKEYLOGFILE-controlled decryption dataset).

PacketPilot already answers "detect on encrypted metadata" (SNI, JA3/JA4, cert health, behavioral
beacons). What the fresh research points at — and what PacketPilot *cannot* do headless today — is
**analyze the decrypted contents of a whole capture when the analyst legitimately holds the keys.**

## 2. The specific gap — decryption exists, but only UI-side and one flow at a time

PacketPilot is, again, ~90% of the way there and doesn't expose it:

- The decryptor is real and shipped: `ppcap_core::decrypt_tls_flow(source, &CarveQuery, keylog_text)`
  reassembles a single flow, applies the TLS/QUIC key schedule from an `SSLKEYLOGFILE`, AEAD-decrypts
  records, and returns cleartext HTTP/1.1 + HTTP/2 transactions (`HttpTxn`, `TlsDecryptResult`).
- **But it is only reachable from the wasm/UI path**, invoked *per flow, on demand* when an analyst
  clicks a TLS flow and pastes a keylog (`ppcap-wasm` `decrypt_tls_flow` → one `QueryDto`).
- **The headless analysis pipeline never consumes a keylog.** `analyze::PipelineConfig` has no keylog
  field, and `ppcap analyze` has no `--keylog` flag (confirmed: the CLI exposes `--threat-feed`,
  `--carve-dir`, `--stix`, `--rules`, … but nothing for key material). So every headless run —
  including the batch pipelines proposed in #125/#127 — classifies, carves, and runs credential/PII
  and HTTP-metadata detection on the **encrypted** view of TLS/QUIC flows, even when the operator has
  the session keys sitting right there.

That is the gap: **whole-capture, keylog-driven decryption in the headless pipeline**, so that
carving, classification, and content-aware detection see cleartext when (and only when) keys are
supplied. It is distinct from #117 (sanitize), #125/#127 (multi-capture orchestration), and #116
(carve). It also directly *amplifies* the batch proposals — a batch triage that can decrypt is far
more valuable than one that reads only ciphertext.

## 3. Feasibility & value assessment — with an honest caveat

| | Assessment |
|---|---|
| **Value** | High — closes the #1 cited PCAP-tooling gap (encrypted-content visibility), reuses a large already-tested asset, and preserves the local-first promise (keylog never leaves the device). |
| **Feasibility** | **Medium — not a one-seam change.** The per-flow `decrypt_tls_flow` re-reads/reassembles a whole flow on demand. The main pipeline is deliberately *single-pass, streaming, bounded-memory*. Feeding decrypted bytes into the streaming carver/classifier/detectors requires either (a) a bounded second decrypt-and-reingest pass over flows flagged decryptable, or (b) buffering only keyed TLS/QUIC flows. Neither is trivial; both must protect the bounded-heap guarantee. |
| **Fit with ethos** | Strong — decryption is strictly opt-in and requires operator-supplied keys; "captures never leave the device" is untouched (keylog is read locally). |
| **Key tension (needs sign-off)** | Bounded-memory design vs. flow reassembly for decryption. This is the crux and the reason this is *medium* effort. The maintainer should confirm the acceptable approach (bounded second pass vs. selective buffering) and the peak-heap budget before implementation. |

## 4. Proposed feature — v1 scope

**Headless keylog decryption: `ppcap analyze --keylog <FILE>` decrypts keyed TLS/QUIC flows so the
whole-capture analysis runs on cleartext.**

**In scope (v1):**
- CLI: `--keylog <FILE>` on `analyze` (NSS `SSLKEYLOGFILE` text). Absent → today's behavior and
  memory profile, byte-for-byte unchanged.
- Pipeline: thread the parsed `KeyLog` into `PipelineConfig`; for TLS/QUIC flows whose
  `client_random` has a matching secret, decrypt via the existing engine and route the resulting
  cleartext HTTP transactions through the **existing** carve + HTTP-metadata + cleartext-cred/PII
  detectors (which already run on cleartext HTTP today).
- Reporting: mark decrypted flows in the summary/report (`decrypted: true`) and count
  `keylog_sessions` used, so the analyst sees what was and wasn't decryptable.
- Bounded: only flows with a matching key are buffered/re-read; over-cap flows are skipped, not
  truncated; peak heap stays within an agreed budget of the current profile.

**Out of scope (v1) — documented follow-ups:**
- UI/desktop "load keylog for the whole capture" (today's per-flow UI decryption stays as is).
- Decrypting protocols beyond the HTTP-over-TLS/QUIC the engine already reconstructs.
- Wiring `--keylog` into the (still-unapproved) batch pipelines — trivial once both land, but gated
  on #125/#127 being approved first.

## 5. Implementation approach (grounded in the code)

1. **`tls/keylog.rs`** — already parses `SSLKEYLOGFILE` (`KeyLog::parse`, `secret()`); reuse as-is.
2. **`analyze/mod.rs`** — add `keylog: Option<KeyLog>` to `PipelineConfig`; at flow finalize, for TLS
   /QUIC flows with a matching `client_random`, invoke the existing decrypt path and feed cleartext
   transactions into the current carve/detect seams. This is the one architecturally significant
   change — see the §3 bounded-memory tension.
3. **`ppcap-cli/src/cli.rs`** — add `--keylog <PathBuf>`; read the file, `KeyLog::parse`, place in
   `PipelineConfig`.
4. **`model/summary.rs`** — add `#[serde(default)] decrypted: bool` per flow + a capture-level
   `keylog_sessions_used` count (serde-default keeps old JSON readable).
5. **`report/mod.rs`** — badge decrypted flows; show the session-used count.
6. **Docs** — README quickstart `--keylog` example; PROJECT-SPEC note.

## 6. Success criteria

- **Correctness:** on a synthetic capture generated with a known `SSLKEYLOGFILE`, a `--keylog` run
  surfaces the cleartext HTTP host/URI and any seeded credential/PII that a no-keylog run cannot; the
  decrypted-flow SHA-256 of a carved object equals the object's true plaintext hash.
- **Isolation:** without `--keylog`, output bytes and peak heap match the current benchmark within
  noise (≥250k pkt/s, bounded heap) — the feature is inert when off.
- **Bounded memory when on:** peak heap for a keyed capture stays within the agreed budget of the
  current profile; over-cap keyed flows are skipped, not truncated.
- **Honesty of reporting:** flows without a matching key are reported un-decrypted (not silently
  dropped); `keylog_sessions_used` reflects reality.
- **Tests green:** `cargo test -p ppcap-core` (new keyed-capture round-trip + no-keylog-parity +
  bounded-heap tests) + clippy + rustfmt; UI unaffected (no UI change in v1).

## 7. Recommendation

1. **First, triage the backlog** — approve or decline #117, and dedup #125/#127 (keep #125). The
   routine should not keep stacking proposals on an un-triaged queue.
2. **Then, if a new build is wanted**, this — *headless keylog decryption* — is the strongest new
   candidate: it targets the #1 documented market gap, reuses a large tested asset, keeps the
   local-first promise, and multiplies the value of the batch proposals. It is **medium effort**, not
   the "single-seam" kind of change (§3), and **requires maintainer sign-off on the bounded-memory
   approach before implementation.**

Per the routine's guardrails, no implementation, tests, PR, merge, or release were done
autonomously — this is research + a code-grounded plan awaiting approval.
