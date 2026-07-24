# Evidence integrity & chain of custody

Network evidence is only as good as its custody story: who produced these files, with what
tool and settings, from which capture — and have they changed since? **Evidence mode** answers
all four offline. `ppcap analyze --evidence <path>` writes a **sealed chain-of-custody
manifest** next to the run's artifacts, and `ppcap verify` re-checks the whole bundle in
seconds — integrity (SHA-256 of the input and of every artifact), provenance (tool version,
exact settings, timestamps, the capture's own time window), and reproducibility (the engine is
deterministic: same input + same settings ⇒ byte-identical outputs, and the manifest records
the recipe that makes that claim checkable).

## Usage

```sh
# Analyze with evidence mode: every artifact is hashed into a sealed manifest.
ppcap analyze case042.pcap \
  --json out.json --parquet flows.parquet --html report.html \
  --threat-feed feeds/iocs.json \
  --evidence case042.evidence.json
# stderr: evidence: sealed manifest (3 artifacts, input a1b2c3d4e5f6…) -> case042.evidence.json

# Later — before presenting, after transfer, on intake at another team:
ppcap verify case042.evidence.json
#   seal: OK (schema v1, ppcap 0.1.0, created @1753261442)
#   source: OK          case042.pcap (14096929 bytes, sha256 a1b2c3d4e5f6…)
#   flows_parquet: OK   flows.parquet
#   html_report: MODIFIED (hash mismatch)  report.html
#   summary_json: OK    out.json
# exit 1 — something changed since sealing

# Machine-readable report for an evidence pipeline:
ppcap verify case042.evidence.json --json verify-report.json
```

| Flag / command | Effect |
|---|---|
| `analyze --evidence <path>` | Hash the input + every file artifact the run wrote; record tool version, effective settings, capture window; seal; write the manifest |
| `verify <manifest>` | Recompute the seal, re-hash source + artifacts; per-file `OK / MISSING / MODIFIED`; exit 0 all-intact, 1 any failure |
| `verify --json <path\|->` | Also emit the full verification report as JSON |

## The manifest, field by field

```json
{
  "schema_version": 1,
  "tool": "ppcap",
  "engine_version": "0.1.0",
  "created_unix_secs": 1753261442,
  "settings": ["--hash", "--threat-feed feeds/iocs.json"],
  "source_path": "case042.pcap",
  "source_sha256": "a1b2c3…",
  "source_bytes": 14096929,
  "first_ts_ns": 1700000000000000000,
  "last_ts_ns": 1700003600000000000,
  "artifacts": [
    { "role": "flows_parquet", "path": "flows.parquet", "sha256": "…", "bytes": 2021205 },
    { "role": "html_report",   "path": "report.html",   "sha256": "…", "bytes": 412330 },
    { "role": "summary_json",  "path": "out.json",      "sha256": "…", "bytes": 129549 }
  ],
  "seal_sha256": "9f8e7d…"
}
```

- **`settings`** — the reproducibility recipe: every flag that shapes the artifacts' bytes, in
  stable order. Re-running the same engine version with these settings on the hashed input
  reproduces the artifacts byte-for-byte. (`--reputation` is recorded honestly but its online
  verdicts are not reproducible offline.)
- **`artifacts`** — every file the run wrote, sorted by role. Paths are recorded as written;
  relative paths resolve against the manifest's own directory at verify time, so a bundle
  moved *whole* (capture + artifacts + manifest in one folder) stays verifiable anywhere.
- **`seal_sha256`** — SHA-256 over the manifest's canonical serialization with this field
  empty. Editing *any* field — a hash, a setting, the timestamp — breaks the seal, and
  `verify` says so first.

## What the seal is — and is not

The seal proves **integrity**: the record and the files it describes are exactly what the
analysis produced. It does **not** prove **authenticity** (who ran the analysis) — a
self-contained tool cannot vouch for its operator. For authenticity, sign the manifest file
itself with your existing key infrastructure and archive the signature beside it:

```sh
gpg --detach-sign case042.evidence.json          # or:
ssh-keygen -Y sign -f ~/.ssh/id_ed25519 -n file case042.evidence.json
```

Verifying then has two steps: your signature check (authenticity of the record), then
`ppcap verify` (integrity of the bundle the record describes).

## Guarantees, verified by tests

- Sealing is deterministic and idempotent; editing any manifest field breaks the seal.
- `verify` distinguishes `OK` / `MISSING` / `MODIFIED (size)` / `MODIFIED (hash)` per file,
  never panics on unreadable paths, and exits nonzero on any failure.
- Hashing streams with a fixed 64 KiB buffer — bounded memory at any capture size, using the
  same vendored FIPS 180-4 SHA-256 as `--hash` (no new dependencies).
- Manifests written by a **newer** engine are rejected with a clear error; the current schema
  round-trips byte-stable.
- A relative-path bundle moved whole verifies from its new location.

## Not in v1 (follow-ups)

Built-in signature verification (`verify --require-signature`), `verify --reproduce` (re-run
the recorded recipe and byte-compare), per-case evidence bundles for `analyze --batch`, an
"Export evidence bundle" desktop action, and opt-in RFC 3161 timestamping.
