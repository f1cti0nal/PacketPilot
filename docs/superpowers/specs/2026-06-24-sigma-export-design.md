# Sigma rule export — design

Status: design · 2026-06-24 · Feature: export the behavioral findings as **Sigma detection rules**
(YAML), a new format alongside the existing CSV / STIX / MISP / CEF exports.

## Problem

PROJECT-SPEC §F calls for "export findings to **RuleForge AI** (auto-generate Sigma/SIEM rules from
observed threats)". PacketPilot already exports findings as STIX (IOC interchange), MISP (event),
CEF (SIEM logging), and CSV — but not as **deployable detection rules**. Sigma is the open,
vendor-neutral detection-rule format; turning findings into Sigma lets an analyst take what
PacketPilot observed and deploy a matching detection in their SIEM.

## Approach

Add `export::sigma_rules(out) -> String` — a **multi-document YAML stream, one Sigma rule per
finding** — and plumb it through the existing export seam (the exact chain CEF/MISP use):
`engine → ppcap-wasm (export_sigma) → Tauri (save_sigma / export_sigma) → platform.ts
(exportSigma / copySigma) → ExportMenu dropdown + ⌘K palette`.

Each rule:
- `title`, deterministic `id` (a UUID from [`det_uuid`] over the finding — no randomness, so the
  same analysis yields the same rules), `status: experimental`, `description` (the evidence),
  `author`, `references` (ATT&CK technique URLs).
- `logsource.category` mapped from the finding kind (`dns` for DNS tunneling, `proxy` for
  cleartext-cred / PII, else `firewall`).
- `detection.selection`: `dst_ip` (+ `dst_port`) when the finding has a destination, else `src_ip`
  for fan-out findings (e.g. a host sweep). `condition: selection`.
- `level` from the finding severity (`informational`/`low`/`medium`/`high`/`critical`).
- `tags`: `attack.<technique>` (lowercased) per ATT&CK id.

## Scope

In: one Sigma rule per finding, deterministic, pure over `AnalysisOutput`, no new deps (hand-built
YAML with a small double-quoting/escaping helper). Save (desktop dialog / browser download) + copy.

Out: per-IOC consolidation (one rule per IP across findings), backend-specific field schemas, Sigma
correlation rules, round-tripping. These are deliberately left to the analyst to adapt.

## Invariants

No new dependencies; C-free (string building only). Deterministic output. YAML scalars that can
contain special characters (title, description, references, IPs) are emitted as escaped
double-quoted scalars; control characters are flattened to spaces.
