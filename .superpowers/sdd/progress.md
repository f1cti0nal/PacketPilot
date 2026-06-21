# Online reputation connectors — SDD progress

Plan: docs/superpowers/plans/2026-06-21-reputation-connectors.md
Spec: docs/superpowers/specs/2026-06-21-reputation-connectors-design.md
Branch: feat/reputation-connectors
Merge-base (final-review BASE): b19a066
Pre-impl HEAD (Task A1 BASE): 487af2e   (spec + plan docs committed)

Scope note: IP reputation end-to-end (all 3 surfaces). SNI-domain reputation DEFERRED (user-approved).

## Tasks
- [x] A1: RepStatus + extended ReputationVerdict (enrich/reputation.rs)
- [x] A2: IpThreat.reputation field
- [x] A3: apply_reputation raise path
- [x] A4: apply_reputation suppress path
- [x] A5: neutral statuses + re-sort tests
- [x] A6: public exports + wasm-safety build
- [x] B1: online feature + ureq + HttpGet skeleton
- [x] B2: AbuseIPDB adapter
- [x] B3: GreyNoise adapter
- [x] B4: VirusTotal adapter (IP + domain)
- [x] B5: on-disk cache (TTL + atomic)
- [x] B6: per-provider budget
- [x] B7: lookup_reputation orchestrator + UreqClient
- [x] C1: CLI --reputation flag
- [x] D1: WASM apply_reputation export
- [x] D2: Tauri reputation_lookup + keychain commands
- [x] E1: TS reputation types
- [x] E2: proxy HttpGet + 3 TS adapters
- [ ] E3: reputation IndexedDB cache
- [x] E4+E5: TS budget + orchestrator
- [x] E6: applyReputationWasm wrapper
- [x] F1: ReputationChip on threat cards
- [x] F2: Settings dialog + consent
- [x] F3: App wiring (consent-gated)
- [x] G1: cross-surface parity test
- [x] G2: CI online-feature coverage
- [x] G3: docs

## Log
- Task A1: complete (487af2e..184c0b5, review clean; 270/270). Minor (carry to A3): impl kept `Severity` import alive via a `const _: fn()` keepalive trick + `#[allow(unused_imports)]` on HashSet — A3 actually uses both, so DROP the trick/allow in A3.
- Task A2: complete (184c0b5..741290c, review clean; 271 pass). Added `Eq` to ReputationVerdict (IpThreat derives Eq) — sound. Minor: tests mod placed mid-file (style). Construction sites fixed: stats/mod.rs + tests/report_html.rs.
- Task A3: complete (741290c..c0021c6, review clean; 274 pass). A1 keepalive trick removed. downgrade_one_band #[allow(dead_code)] until A4. Minor (final-review triage): (1) reputation.rs:93 `25*mal_count` mult-before-cap = latent u16 overflow only at >2621 providers (impossible, ≤3 here) — could simplify to `if mal_count>=1 {CAP} else {0}`; (2) :98 evidence shows total `+points` per provider line (cosmetic); (3) :101 High-floor evidence omitted when ≥2-malicious already lands in High band (intentional — Critical floor is the operative one; end state correct).
- Task A4: complete (c0021c6..9430333, review clean; 8/8 rep + 277 total, warning-free). dead_code allow removed. Guard tests exercise A3 guard end-to-end. Minor: loose `contains`/`<=` assertions (could tighten).
- Task A5+A6: complete (9430333..38d4434, 2 commits, review clean; 326 pass, wasm release build CLEAN — apply_reputation is wasm32-safe). Exports added to existing enrich re-export block. Minor: re-sort test omits a score assertion (cosmetic).
### PHASE A COMPLETE — reputation scoring keystone done, all reviews clean.
- Task B1: complete (38d4434..ed09ff2, review clean + 1 fix; ureq 2.12.1 rustls, NO C deps verified via cargo tree; default/online/wasm builds all green, 282 pass). is_lookupable #[allow(dead_code)] until B7 removes it. B5/B6 NOTE: budget.rs/cache.rs are placeholder `pub struct Budget;`/`pub struct ReputationCache;` — replace whole file. ureq pinned "2" (3.x API differs) — only non-`=`-pinned workspace dep, intentional.
- Task B2: complete (ed09ff2..4014cfb, review clean). NOTE: haiku's `git add -A` swept pre-existing untracked ui/coverage + ui/.claude into the commit — CONTROLLER FIXED: gitignored both (ui/.gitignore) + recommitted clean (only abuseipdb.rs + Cargo.lock + gitignore). Cargo.lock (ureq tree, left dirty by B1) now committed. Minor: no test for score=0&reports>0→Unknown boundary (code correct); isWhitelisted not plumbed (not required).
- Task B3: complete (4014cfb..1cf5d66, review clean; commit clean — gitignore fix worked, only greynoise.rs). classification-gated (noise never elevates). Minor: NotFound score Some(0) (defensible); else-branch covers unknown classifications safely.
- Task B4: complete (1cf5d66..66231ca, review clean; clean commit). Implementer fixed a BRIEF TYPO: score formula floored `(100*m)/total` but brief test+prose want ROUND → now `(100*m + total/2)/total` (8/90→9). NOTE: TS E2 adapter uses Math.round → Rust+TS now consistent. No `reputation` field used; shared parse for ip+domain.
- Task B5: complete (66231ca..fccb6da, review clean; controller re-ran full online suite = 296 passed 0 failed, ⚠️-count resolved, no regression). Adjudicated-benign: `save` propagates create_dir_all/write errors via `?` (matches brief code; only caller B7 does `let _ = cache.save()` → discards Result). NOTE: cargo is OFF-PATH for the controller Bash — use `/c/Users/ravid/.cargo/bin/cargo.exe`.
- Task B6: complete (fccb6da..c3d79e7, review clean; 297 passed). Quotas exact (gn9/vt480/abuse950). Minor: cosmetic (doc comment, loose test loop, undocumented margins).
- Task B7: complete (c3d79e7..3bbe203, 2 commits incl. fix; 300 passed, warning-free, wasm clean). Important#1 FIXED: is_lookupable reverted to is_external() (Public-only) to match apply_reputation; test now asserts 203.0.113.7(doc) NOT lookupable, orchestrator tests use 8.8.8.8. Important#2 (reviewer said lookup_reputation not feature-gated) = FALSE POSITIVE: whole `online` mod is gated `#[cfg(feature="online")]` at the `pub mod online` decl in enrich/mod.rs (outside the diff). UreqClient ureq 2.x error handling correct (Status(code,resp) carries 404 body). Minor: lookup_reputation_native hardcodes default budget/ttls (per brief).
### PHASE B COMPLETE — native online layer done (types+scoring+3 adapters+cache+budget+orchestrator+UreqClient), all reviews clean.
- Task C1: complete (3bbe203..92a3e0f, review clean; 3 pass, warning-free). FIXED a B1 gap: ppcap-cli did NOT actually enable ppcap-core/online — added features=["online"]. Flag off-by-default, double-gated, public-IP-only, dirs cache dir. Minor: cosmetic (fn-ptr unwrap_or_else, dirs unpinned).
### PHASE C COMPLETE — CLI `ppcap analyze --reputation` works.
- Task D1: complete (92a3e0f..65c3a99, review clean — zero issues). WASM apply_reputation export (serde_json, no unwrap); wasm rebuilt, binding in .js/.d.ts; only lib.rs committed (bundle gitignored). Behavioral parity deferred to G1.
- Task D2: complete (65c3a99..7b498f0, review clean; Tauri build 26s clean, keyring 2.3.3). 3 commands registered. Minor: fn-ptr unwrap_or_else (cosmetic); cache-dir creation already handled by B5 save()'s create_dir_all.
### PHASE D COMPLETE — WASM export + Tauri reputation/keychain commands done.

>>> ARCHITECTURE FINDING (flag at final review / user decision): the `online` feature's TLS stack ureq→rustls→**ring** compiles C/asm and REQUIRES A C COMPILER (MinGW gcc) to build — tension with the project's "pure-Rust, no C deps" thesis. Latent since B1 (cargo tree check only looked for *-sys, ring isn't one). SCOPED: default offline build stays C-free; only opt-in `online` feature pulls ring. Options if user objects: rustls w/ a pure-Rust crypto provider, or accept ring (ecosystem standard). FLAGGED TO USER after Phase D.
- Task E1: complete (7b498f0..b083005, review clean). TS RepStatus + ReputationVerdict mirror Rust wire shape exactly (notfound one word, score/link nullable, fetched_at snake_case); IpThreat.reputation? optional. Minor: test only happy path.
- Task E2: complete (b083005..e8dd75f, review clean; 5 tests + tsc). 3 TS adapters mirror Rust B2-B4 exactly (parity holds); proxyHttp never throws. Minor: per-provider header casing (Key vs key — both correct); shallow test coverage (5 happy-path+404 per brief).
- Task E3: complete (e8dd75f..32c9002, review clean; full suite 172 pass, recent/flows 6/6 — DB v1→v2 bump safe, flows preserved). Added fake-indexeddb dev-dep. getReputation/putReputation TTL(<=) + best-effort. Removed brief's unused beforeEach (tsc TS6133).
- Task E4+E5: complete (32c9002..aa7eef7, review clean; 1 test + tsc). Cache-first (no trySpend on hit), quota-tagged unavailable, budget gn9/vt480/abuse950, isPublicIp matches engine is_external. Benign: IPs w/ 0 providers omitted (correct). Minor: `(keys as any)[source]` cast; coverage gap (quota path untested per brief); coarse IPv6 fc/fd prefix.
- Task E6: complete (aa7eef7..c67f1d8, review clean; tsc). applyReputationWasm mirrors analyzeViaWasm, reuses ensureWasm(), import extended not duplicated. Behavior deferred to G1 parity.
### PHASE E COMPLETE — browser TS path done (types+adapters+cache+budget+orchestrator+wasm-apply).
- Task F1: complete (c67f1d8..905a75c, review clean; chip 2/2 + existing ThreatRail 3/3 + tsc). Additive chip (worst-verdict by RANK, null on empty), guarded render. Minor: label separator, test-name copy (both cosmetic).
- Task F2: complete (905a75c..072118e, 2 commits incl. fix; settings 3/3 + full 178 + tsc). Important FIXED: isTauri dedup → new lib/tauri-detect.ts (zero-dep), re-exported by platform.ts + settings.ts, no call-site changes. Minor (final-review): SettingsDialog.save() swallows invoke() errors (no UX feedback); isTauri() called per-render; browserKeys() exported for F3 use.
- Task F3: complete (072118e..b607907, review clean; tsc + 178 pass incl App 6/6). runReputation re-applies via setSummary IN-PLACE (never applyCapture — avoids recent double-record + activeSource reset); lastRepSourceRef identity dedup (sha256??path); gate in all 4 load paths; desktop Tauri / browser proxy; consent gate; CommandBar gear → SettingsDialog. Minor (final-review): desktop consent dialog hardcodes all 3 providers (should use reputation_key_status); exhaustive-deps lint noise.
### PHASE F COMPLETE — UI surfacing done (chip + settings + consent + App wiring).
- Task G1: complete (b607907..fb194cd, review clean; Rust parity 1 + TS parity 1, suite 179). Anti-drift VERIFIED: both tests read same fixture.expected; 8.8.8.8 consensus→Critical(90)@idx0, 1.1.1.1 benign→Low(34), 10.0.0.5 internal untouched; scoring math traced correct; real WASM binary exercised (initSync + raw export, jsdom-safe). Minor: fixture severity_counts stale post-apply (not asserted); raw export vs E6 wrapper (documented, parity-equivalent).
- Task G2: complete (fb194cd..df93d32, 2 commits, review clean). Added `cargo test -p ppcap-core --features online` to engine job; build:wasm already before test:coverage. RESOLVED the C-free-gate conflict (USER DECISION: scope to offline core): gate now `cargo tree -p ppcap-core -e no-dev` — offline ppcap-core stays C-free (enforced), opt-in online feature's ring/cc is an accepted exception. Verified gate PASSES.
>>> RING/CC ARCHITECTURE FINDING RESOLVED: user chose to scope the C-free gate to ppcap-core (offline core). No longer open.
- Task G3: complete (df93d32..<docfix>, review clean + 1 doc fix; all 6 numeric anchors + proxy contract + ToS verified accurate). README roadmap→shipped; docs/reputation.md operator guide; engine/README online-feature note. Fixed: shell comment "skips silently" → "prints a notice" (matched prose + C1 impl).
### PHASE G COMPLETE — parity test + CI online coverage + docs done.
### ALL 28 PLAN TASKS COMPLETE. Ready for final whole-branch review.

## CI-gate fixes

- **clippy "this impl can be derived"** (`enrich/reputation.rs`): removed manual `impl Default for RepStatus`, added `Default` to `#[derive(...)]`, marked `Unknown` variant with `#[default]`. `status_default_is_unknown` test still passes.
- **clippy "items after a test module"** (`model/summary.rs`): the `#[cfg(test)] mod tests` block was mid-file with `impl Summary` after it. Moved the test module to the end of the file (after `impl Summary`). `ipthreat_reputation_defaults_empty_on_old_json` test still passes.
- **rustfmt** (`ppcap-cli/src/cli.rs` + 4 online adapter files): `cargo fmt --all` reformatted long lines in the reputation block of cli.rs and minor style in the online adapters (abuseipdb, cache, greynoise, mod, virustotal). No logic changes.
- **Verification**: `cargo clippy --workspace --all-targets -- -D warnings` → ZERO warnings. `cargo fmt --all --check` → clean (exit 0). `cargo test --workspace` → 300 ppcap-core + 12 integration tests, all pass.
