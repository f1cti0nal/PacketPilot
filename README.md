# PacketPilot

**Your PCAP autopilot — from capture to conclusion in one click.**

PacketPilot analyzes an *entire* packet capture (pcap/pcapng) and lands the analyst on a
**triage dashboard**: an executive summary, a real **explainable severity** ranking, categorized
traffic with payload-detected protocols + TLS SNI, per-IP threat report cards (IOC + MITRE
ATT&CK + evidence), a virtualized flow table, and a one-click **HTML/JSON report** — on a
streaming, bounded-memory Rust engine, delivered as a **web UI and a native desktop app**, with
captures never leaving the device.

> Status: **core build complete & verified.** Engine, UI, desktop app, threat-intel + severity,
> reporting/export, online reputation enrichment, and AI analyst assist are all built and tested.
> Working name (alternates: PacketLens, NetSift).

---

## What it does

```
capture.pcap ──▶ streaming Rust engine ──▶ triage dashboard ──▶ shareable report
                 (one pass, bounded RAM)    (web + desktop)      (HTML / JSON / PDF)
```

- **Ingest** classic pcap (LE/BE, µs/ns) and pcapng (multi-interface), streaming with a fixed
  64 KiB buffer — peak heap stays bounded (~38 MiB) regardless of capture size.
- **Decode** Ethernet/VLAN/SLL · IPv4/IPv6 · TCP/UDP/SCTP/ICMP, plus payload **L7 sniffing**
  (HTTP / DNS / TLS) and **TLS SNI** extraction — never panics on malformed input.
- **Reconstruct** bidirectional 5-tuple flows; **classify** traffic (payload-aware, not just
  ports); **enrich** with IP classification + a local **IOC threat feed** + **MITRE ATT&CK**.
- **Score** every flow with a transparent weighted **severity** (Critical/High/Medium/Low/Info)
  where *every point is explained* — no black-box numbers.
- **Persist** flows as Snappy Parquet (queryable by a DuckDB view) + a summary JSON with per-IP
  **threat report cards**.
- **Present** a summary-first dashboard + a virtualized flows table (millions of rows at 60 fps)
  + drill-down, and **export** a self-contained HTML report (print-to-PDF) or JSON.
- **Share safely** — one-click **Safe Share** exports a sanitized/anonymized copy of a capture
  (prefix-preserving IP/MAC pseudonyms, payload scrub or L7-field redaction, recomputed checksums,
  chain-of-custody manifest) so a capture can go to a vendor/CERT without leaking sensitive data.
  See [docs/sharing-captures-safely.md](docs/sharing-captures-safely.md).

## The gap it fills

| Existing tool | Strength | The gap PacketPilot fills |
|---|---|---|
| Wireshark / tshark | Deepest dissection | Loads whole file into RAM → chokes on multi-GB; manual; no triage/severity/threat-intel |
| Arkime / Malcolm | Scale | Heavy infra & ops; "know what to look for" dashboards; not laptop-light or one-click |
| Brim / Zui | Big pcaps on desktop | Requires query skills; thin automated severity & enrichment |
| NDR vendors | Real-time ML | Expensive appliance/cloud; not for ad-hoc saved pcaps |
| Online analyzers | Zero install | **Sensitive captures leave the premises** |

**The wedge:** the scale of the big tools **+** the simplicity of one click **+** the privacy of
local-first. Plus *explainable* severity — every verdict shows its evidence and ATT&CK mapping.

## Architecture

```
PacketPilot/
├── engine/                     # Rust workspace — the analysis core (pure-Rust, no C deps)
│   ├── crates/ppcap-core       #   reader · decode · flow · classify · stats · enrich · score
│   │                           #   · columnar (Parquet) · report (HTML) · gen · metrics
│   └── crates/ppcap-cli        #   `ppcap`: analyze / gen / init-db
├── ui/                         # React 18 + Vite 5 + TS + Tailwind — the shared frontend
│   └── src-tauri/              #   Tauri 2 desktop shell (ppcap-core as native backend)
└── docs/PROJECT-SPEC.md        # full specification
```

The **same React frontend** powers both the browser build and the Tauri desktop app
(`isTauri()`-gated): the desktop runs the engine natively via Tauri commands + native file
dialogs; the browser build reads bundled sample output.

## Quickstart

### Prerequisites
- **Rust** (stable, MSRV 1.85). On Windows this repo targets `x86_64-pc-windows-gnu` with a
  MinGW-w64 toolchain (gcc/dlltool/ld) for linking — MSVC also works. Pure-Rust deps, so **no C
  compiler is needed for the engine itself**.
- **Node** 20+ and npm (the UI). **Tauri** prerequisites for the desktop app (WebView2 runtime,
  present on Windows 10/11).

### Engine (CLI) — `cd engine`
```sh
# Generate a deterministic synthetic capture (for trying it out)
cargo run -p ppcap-cli --release -- gen sample.pcap --scenario mixed --packets 100000 --edge-cases

# Analyze: summary JSON + flows Parquet + threat enrichment + an HTML report
cargo run -p ppcap-cli --release -- analyze sample.pcap \
  --json out.json --parquet flows.parquet \
  --threat-feed crates/ppcap-core/data/sample_iocs.json \
  --html report.html --hash

# Emit the DuckDB schema (for the external sidecar / DuckDB-Wasm)
cargo run -p ppcap-cli --release -- init-db --out schema.sql

# Safe Share: write a sanitized copy + chain-of-custody manifest (scrubs payloads,
# pseudonymizes IP/MAC, redacts DNS/HTTP/SNI/credentials, recomputes checksums)
cargo run -p ppcap-cli --release -- sanitize sample.pcap --out sample.sanitized.pcap
```
The HTML report is self-contained — open it in any browser and **print to PDF**.

### Desktop app — `cd ui`
```sh
npm install
npx tauri dev      # live native app (PacketPilot window)
npx tauri build    # packaged release (installer / exe)
```
Open a capture via the native dialog → one-click triage → **Export report** saves the HTML.

### Web UI (dev) — `cd ui`
```sh
npm install
npm run dev        # http://localhost:5180 (loads the bundled sample)
```

### Tests & benchmark — `cd engine`
```sh
cargo test                 # full suite (200+ tests)
cargo bench                # criterion ingest benchmark (10k / 100k / 1M packets)
```

## Performance budget (verified)

| Metric | Budget | Measured (1M-packet synthetic, 1 core) |
|---|---|---|
| Peak heap | ≤ 64 MiB | **38 MiB** (bounded, plateaus) |
| Throughput | ≥ 250k pkt/s | **~1.17M pkt/s** |
| Wall (100k pkts) | < 2 s | ~0.09 s |

See [engine/BENCHMARK.md](engine/BENCHMARK.md) for methodology and the full table.

## Features
- Streaming, bounded-memory ingest (pcap + pcapng); chain-of-custody SHA-256.
- L2–L4 decode + L7 (HTTP/DNS/TLS) + **TLS SNI**; payload-aware classification.
- Bidirectional flow reconstruction; traffic taxonomy (web/dns/email/file/remote/voip/iot/tunnel/scan/c2/anomalous).
- **Threat intel**: IP classification, local IOC feed (IP/CIDR/domain/JA3), MITRE ATT&CK.
- **Explainable severity** per flow + per-IP **report cards** (score, evidence, ATT&CK).
- Columnar Parquet output + DuckDB view; summary JSON.
- Triage dashboard (severity strip, threat panel, charts) + virtualized flows + drill-down.
- One-click **HTML / JSON report** export (print-to-PDF); in-app Export button.
- Native **Tauri desktop app** + browser build from one codebase.
- **Online reputation enrichment** — opt-in, bring-your-own-key corroboration of public IPs via
  AbuseIPDB / GreyNoise / VirusTotal; aggressively cached (local only), privacy-preserving (only
  bare public IP strings leave the device, never packets or internal IPs). See [docs/reputation.md](docs/reputation.md).
- **AI Analyst Assist** — opt-in NL executive brief + interactive chat over the *derived* summary
  (not raw packets). BYO endpoint — Anthropic/OpenAI/OpenRouter/Ollama/Custom. Privacy-preserving:
  only the engine's computed summary ever leaves; localhost endpoints stay fully on-device. Desktop
  stores the API key in the OS keychain; browser routes through a user-supplied streaming relay.
  See [docs/ai-assist.md](docs/ai-assist.md).

## Roadmap (optional)
- gzip-capture ingest; `packet_index` Parquet for packet-level drill-down.
- AI: SNI-domain context in chat; multi-session conversation memory.
- Self-hosted team server (shared cases, RBAC) — the "hybrid" other half.
- Integrations: export findings to RuleForge AI (detection rules) and Sentinel (SOC incidents).

## Docs
- [docs/PROJECT-SPEC.md](docs/PROJECT-SPEC.md) — full specification & gap analysis.
- [docs/reputation.md](docs/reputation.md) — online reputation enrichment operator guide.
- [docs/ai-assist.md](docs/ai-assist.md) — AI analyst assist operator guide.
- [engine/README.md](engine/README.md) — engine internals, build, schema.
- [engine/BENCHMARK.md](engine/BENCHMARK.md) — performance methodology & results.
