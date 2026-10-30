# PacketPilot

<img width="1908" height="907" alt="PacketPilo" src="https://github.com/user-attachments/assets/08e55323-bd45-45dd-b295-196aa9605c52" />


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
  (HTTP / DNS / TLS / **QUIC + HTTP-3**) and **TLS/QUIC SNI** extraction — keyless, never
  panics on malformed input.
- **Reconstruct** bidirectional 5-tuple flows; **classify** traffic (payload-aware, not just
  ports); **enrich** with IP classification + a local **IOC threat feed** + **MITRE ATT&CK**.
- **Score** every flow with a transparent weighted **severity** (Critical/High/Medium/Low/Info)
  where *every point is explained* — no black-box numbers.
- **Persist** flows as Snappy Parquet (queryable by a DuckDB view) + a summary JSON with per-IP
  **threat report cards**.
- **Present** a summary-first dashboard + a virtualized flows table (millions of rows at 60 fps)
  + drill-down, and **export** a self-contained HTML report (print-to-PDF) or JSON.
- **Triage a whole folder** with `analyze --batch <dir>`: one ranked case index (`case.json` /
  `case.html`) + cross-capture indicator correlation (IP / SNI / JA3 seen across captures),
  bounded-memory and local-first.
- **Share safely** — one-click **Safe Share** exports a sanitized/anonymized copy of a capture
  (prefix-preserving IP/MAC pseudonyms, payload scrub or L7-field redaction, recomputed checksums,
  chain-of-custody manifest) so a capture can go to a vendor/CERT without leaking sensitive data.

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
└── ui/                         # React 18 + Vite 5 + TS + Tailwind — the shared frontend
    └── src-tauri/              #   Tauri 2 desktop shell (ppcap-core as native backend)
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

# Time Machine: emit a capture-indicator index, then re-scan it later vs an updated feed
cargo run -p ppcap-cli --release -- analyze sample.pcap --json out.json --hash --index sample.index.json
cargo run -p ppcap-cli --release -- rescan sample.index.json --threat-feed updated-feed.json

# Safe Share: write a sanitized copy + chain-of-custody manifest (scrubs payloads,
# pseudonymizes IP/MAC, redacts DNS/HTTP/SNI/credentials, recomputes checksums)
cargo run -p ppcap-cli --release -- sanitize sample.pcap --out sample.sanitized.pcap

# Evidence mode: seal a chain-of-custody manifest over the run's artifacts, verify any time
cargo run -p ppcap-cli --release -- analyze sample.pcap --json out.json --html report.html \
  --evidence case.evidence.json
cargo run -p ppcap-cli --release -- verify case.evidence.json

# Teach it once: mark an alert benign (rules expire in 90 days), then apply the rule file
# (repeatable: a team file in git plus a personal one) to later captures
cargo run -p ppcap-cli --release -- suppress add out.json --alert alert:0123abcd4567ef89 \
  --scope destination --reason "DHCP discovery on port 67" --author john --file suppressions.json
cargo run -p ppcap-cli --release -- analyze next.pcap --json next.json --suppress suppressions.json
cargo run -p ppcap-cli --release -- suppress test next.json --suppress suppressions.json

# AI agents: serve captures (or analyze --json outputs) to any MCP host over stdio
cargo run -p ppcap-cli --release -- mcp sample.pcap out.json --threat-feed feed.json

# Push integrations: send the alert queue to Slack / Teams / Jira / TheHive / Splunk HEC /
# Elastic (ECS) / OCSF / a webhook. Start from the example file, enable what you use, export
# the secrets it names, preview, then send (a ledger stops duplicate tickets on re-runs)
cargo run -p ppcap-cli --release -- push --example > destinations.json
cargo run -p ppcap-cli --release -- push out.json -d destinations.json --dry-run
cargo run -p ppcap-cli --release -- push out.json -d destinations.json --min-band investigate
# Offline hand-off: write the ECS / OCSF / HEC bodies to files instead of sending
cargo run -p ppcap-cli --release -- push out.json -d destinations.json --to elastic --out-dir push-out

# Zeek logs out: conn / dns / http / ssl / ssh / files / notice logs sharing one connection uid
# (tab-separated like Zeek, or --json for Zeek JSON), on their own or alongside an analysis
cargo run -p ppcap-cli --release -- zeek sample.pcap -o zeek-logs
cargo run -p ppcap-cli --release -- analyze sample.pcap --json out.json --zeek zeek-logs --zeek-json

# Suricata EVE in: sensor alerts become findings that rank and correlate with PacketPilot's own,
# at analysis time or folded into a saved analysis (importing the same file twice adds nothing)
cargo run -p ppcap-cli --release -- analyze sample.pcap --json out.json --eve /var/log/suricata/eve.json
cargo run -p ppcap-cli --release -- eve out.json eve.json --json out.json

# File extraction + YARA: files carried by HTTP, FTP, SMTP/POP3 and SMB2 are hashed in-stream;
# your YARA rules run over every one (each match is a finding), and --carve-dir saves them
cargo run -p ppcap-cli --release -- analyze sample.pcap --json out.json \
  --yara team-rules.yar --yara my-rules.yar --carve-dir carved

# What is new to this network: each run learns into the baseline file what the network's hosts
# resolve, which client fingerprints and user agents they use, which certificates they are served
# and where they connect; later runs list what no earlier capture saw. Share the file to share history
cargo run -p ppcap-cli --release -- analyze monday.pcap --json out.json \
  --baseline network.json --update-baseline network.json
cargo run -p ppcap-cli --release -- baseline merge alice.json bob.json --out network.json
```

A destination in `destinations.json` never holds a secret: it names the environment variable
that does (`url_env` for Slack / Teams webhook URLs, `token_env`, and `user_env` for Jira Cloud or
Elastic basic auth), and unknown keys are rejected, so the file is safe to commit for a team.
Only variables starting with `PPCAP_` can be named, so a shared file can never read an unrelated
credential from your shell. Review a destinations file you did not write before running it: its
URLs decide where your `PPCAP_` tokens are sent.

```json
{
  "destinations": [
    { "name": "soc-slack", "kind": "slack", "url_env": "PPCAP_SLACK_WEBHOOK_URL", "min_band": "investigate" },
    { "name": "jira", "kind": "jira", "url": "https://acme.atlassian.net", "project": "SEC",
      "user_env": "PPCAP_JIRA_USER", "token_env": "PPCAP_JIRA_TOKEN", "min_band": "investigate" },
    { "name": "splunk", "kind": "splunk_hec", "url": "https://splunk.acme.org:8088",
      "token_env": "PPCAP_SPLUNK_HEC_TOKEN", "index": "network" }
  ]
}
```

Slack and Teams get one digest per 10 alerts; Jira gets one issue and TheHive one alert per
PacketPilot alert (with the narrative, next step and incident timeline, each row carrying its
capture filter); Splunk HEC, Elastic `_bulk` and OCSF get batched events. Deliveries are recorded
in `push-ledger.json` beside the destinations file (with the Jira key or TheHive id), keyed by
alert and capture, after every request. A re-run of the same analysis sends only what has not gone
yet; the same host flagged again in a new capture is a new delivery; an alert whose band rose
since is sent again, and for Jira and TheHive that updates the existing ticket (a comment, a
severity bump) instead of opening a second one. `--resend` overrides the ledger.

The Zeek logs use Zeek's field names, types and header (a subset of Zeek's fields per log), so a
pipeline that already parses Zeek logs can read them.
Every row about one connection carries the same `uid`, and `notice.log` holds PacketPilot's findings
(`note` is `PacketPilot::<kind>`, with severity, score and ATT&CK ids). Fields are filled from one
pass without TCP reassembly beyond a segment: `conn_state` comes from each side's TCP flags,
`history` is left unset, HTTP body lengths are the declared `Content-Length`, and `files.log`
lists every file the analysis carved, with its protocol as `source`, its `filename` and any
`yara` matches. An export first removes the Zeek logs an earlier export left in the same
directory, so the folder only ever holds one capture's logs; `--evidence` records every log written
and every `--eve` input.

File carving follows TCP strictly in order: a lost segment drops that file rather than hash wrong
bytes. Besides HTTP downloads it carves FTP transfers (passive and active, `RETR` and `STOR`;
directory listings are skipped), email attachments from SMTP and POP3 (nested MIME, base64 and
quoted-printable; a part is carved when it has a filename, is an attachment, or is not text),
and SMB2 files read or written from offset 0 to their end (named `\\server\share\path`; `IPC$`
pipes, shares connected before the capture began, and encrypted SMB3 are skipped). An FTP `APPE`
is not carved, since it carries only the end of a file. Each file gets its SHA-256, content signatures and YARA
verdicts with nothing buffered; `--carve-dir` writes it to `<sha256>.<ext>`, with `.quarantine`
added when anything flagged it. Traffic after `STARTTLS`, `STLS` or `AUTH TLS` is encrypted and
not carved.

`--yara` takes the common YARA subset, implemented in pure Rust so it builds without a C compiler
(the web UI does not take rule files yet): text strings (`nocase`, `wide`, `ascii`), hex strings with wildcards and
bounded jumps, `and`/`or`/`not`, `any`/`all`/`N of`, `#a` counts, `$a at`/`in`, `filesize`,
`uint8`/`16`/`32` reads within the first 16 KiB, tags, `meta`, `private` rules and references to
earlier rules. A rule that uses regular expressions, modules (`pe.`, `math.`), `for` loops,
`fullword`, `xor` or `base64` is listed on stderr and skipped; the rest of the file still loads.
A match becomes a `rule_match` finding titled `YARA <rule>` on the client, with severity from the
rule's `severity` meta (`critical`/`high`/`medium`/`low`, or 1–10; High when absent) and ATT&CK
ids from `mitre_attack`. `--evidence` records each rule file's hash.

The baseline file also keeps a network-wide history: registered domains (from DNS queries, TLS
SNI and HTTP `Host`), JA4 and JA3 client fingerprints, HTTP user agents, server certificates
(SHA-256 of the leaf, with its CN; visible on TLS 1.2 and older) and external destinations, each
with how many captures saw it, first and last seen, and the most internal hosts that produced it
at once. Only sightings by internal hosts count. Each analysis gets a "new to this network" list
(nothing no earlier capture saw), shown once the baseline holds at least 3 captures of history so a
young file does not call everything new, and an "only one host" list of domains, fingerprints,
user agents and certificates a single host produced, shown when the capture has at least 5 internal
hosts. An alert whose peer, peer domain or client software is new to the network says so in its
context and gains a small priority bump; when one host shows both new client software and a new
domain, certificate or destination, that becomes a Medium `baseline_deviation` finding. The
history keeps the 50,000 most-seen values; anything dropped would show as new again, never hidden.
`baseline merge` combines teammates' files; `baseline diff` lists what is new for a saved analysis.

Suricata EVE import reads `alert` events and skips other event types. Each signature between the
same two hosts becomes one `rule_match` finding with a hit count and first/last seen; Suricata
severity 1/2/3 maps to High/Medium/Low and `mitre_technique_id` metadata to ATT&CK ids. The flow
start of each alert opens the incident timeline.

To connect an agent, add PacketPilot to its MCP config (Claude Desktop's
`claude_desktop_config.json` shown; Claude Code: `claude mcp add packetpilot -- ppcap mcp <capture>`):

```json
{
  "mcpServers": {
    "packetpilot": {
      "command": "/path/to/ppcap",
      "args": ["mcp", "/cases/incident-42/capture.pcap", "--suppress", "/cases/team/suppressions.json"]
    }
  }
}
```

The server exposes `list_captures`, `capture_overview`, `list_alerts`, `get_alert` (narrative,
findings, incident timeline), `host_profile`, `query_flows` (filter / group / sort over the flows
Parquet), `get_packets` (a flow's packets with payload preview, so the agent checks its claims
against the bytes) and `lookup_indicator`, plus a `triage` prompt that walks the investigation.
Every tool is read-only and offline. `--allow-write <DIR>` adds `carve_pcap` (writes only into
that directory, never overwrites); `--online` lets `lookup_indicator` use the reputation API keys.

OT/ICS captures (Modbus / DNP3 / S7comm / BACnet / EtherNet-IP) are identified from packet
structure — even on non-standard ports — and land in the **IoT/OT** category and the
`ip.<l4>.ot` protocol-hierarchy node.
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
- **Keyless QUIC / HTTP-3**: structural QUIC identification (v1 + v2, any long-header type, port-agnostic) with keyless Initial **SNI/JA4** extraction and **HTTP/3** detection via ALPN — encrypted-transport visibility without keys.
- Bidirectional flow reconstruction; traffic taxonomy (web/dns/email/file/remote/voip/iot/tunnel/scan/c2/anomalous).
- **OT/ICS protocol triage** — payload-based, length-validated identification of Modbus/TCP, DNP3,
  S7comm, BACnet/IP, and EtherNet/IP-CIP (recognized on non-standard ports, not just by port), so
  industrial traffic surfaces in the IoT/OT category and protocol hierarchy. Modbus **write/control
  commands to a PLC** raise an explainable *ICS control command* finding (ATT&CK for ICS T0855/T0831).
- **Encrypted Traffic Analysis** — analyst-grade verdicts on traffic that is never decrypted:
  **JA4S** server fingerprints (TCP *and* keyless QUIC, whose server Initial is opened with the
  RFC-published salt — no keys), a per-server **TLS posture** rollup, and three explainable
  findings — an unnamed **high-entropy channel** (custom-crypto C2 / hand-rolled tunnels, and the
  first producer of the `anomalous` category), **TLS without SNI** (ECH-aware),
  **port/protocol mismatch** (TLS on an odd port; non-TLS on 443), and **weak SSH posture**
  (SSH-1 support, deprecated host keys, CBC/`none` ciphers — all read from the cleartext
  identification line and KEXINIT, which precede key exchange). Server fingerprints are
  feed-matchable (`bad_ja4s`, `bad_hassh`, `bad_hassh_server`) and re-scannable by Time Machine.
- **Windows identity attacks** — the cleartext envelopes of Kerberos, DCE-RPC, LDAP, SMB2/3 and
  NTLM are parsed (bounded reassembly; tickets, hashes, NTLM responses and RPC/file payloads are
  never kept) to raise explainable **Kerberoasting** (RC4-only or bulk service-ticket requests,
  T1558.003), **AS-REP roasting** (an AS-REP issued without pre-authentication, T1558.004),
  **DCSync** (`DRSGetNCChanges` from a host that is not a domain controller — visible even when
  the call is sealed, T1003.006), **remote service execution** (a service created and started, or
  a task registered, over a named pipe — the PsExec / schtasks pattern, T1021.002 / T1569.002 /
  T1053.005), **password spraying** (SMB logons failing across many accounts from one host,
  T1110.003), **AD reconnaissance** (SPN / no-pre-auth / adminCount / delegation / LAPS LDAP
  queries, SAMR enumeration, Kerberos username enumeration) and **legacy auth** (DES/RC4 Kerberos
  tickets, NTLMv1 responses, or the SMB1 dialect) findings. DCE-RPC carried on SMB named pipes is
  analysed the same as raw-port RPC, so DCSync and service execution are seen on 445 too. Domain
  controllers are inferred from the capture; add more with `--dc 10.0.0.10,10.0.0.11`, or turn the
  stage off with `--no-identity`. Sealed LDAP (the Windows default), LDAPS and encrypted SMB3 stay
  unread.
- **Threat intel**: IP classification, local IOC feed (IP/CIDR/domain/JA3/JA4/JA4S/HASSH), MITRE ATT&CK.
- **Time Machine (retrospective re-scan)** — `analyze --index` distils a capture into a compact
  indicator index; later `ppcap rescan` re-evaluates it against an updated threat feed and flags
  indicators that were clean at capture time but are dirty now — no pcap re-read, fully offline.
- **Teach it once (analyst suppression rules)** — mark an alert benign once (in the Alerts tab or
  with `ppcap suppress add`) and the verdict becomes a rule (finding kind + source/destination IP or
  CIDR + port, with reason, author and a 90-day expiry) applied to every later capture. Hidden
  findings stay listed under *Suppressed* with the rule that hid them, and confirmed malware, ARP
  spoofing, OT writes and threat-intel or reputation hits are never hidden. Rules are a plain
  `suppressions.json`, so one analyst keeps them offline and a team shares them in git — no server.
- **Incident timeline** — every alert retold as one chronological story across all the hosts it
  touches: first contact with the peer, the DNS answer that resolved it, downloads with their
  SHA-256, each detection as it starts, and the lateral hops between hosts. Every row is one click
  from its packets (the app carves a `.pcap` of just that host pair and time window; the report
  and exports carry the matching capture filter). It is in the app's Timeline tab, the HTML
  report, and `ppcap timeline <summary.json> --format markdown|csv|json` for tickets and hand-offs.
- **Local MCP server for AI agents** — `ppcap mcp` lets Claude, Cursor or an Ollama-backed agent
  triage a capture through the Model Context Protocol: the ranked alert queue, alert timelines,
  host profiles, flow queries, the packets themselves and indicator lookups. It runs on the
  analyst's machine over stdio with no listener, every tool is read-only, and nothing leaves the
  machine unless the analyst opts in (`--online`) or points the agent at a remote model.
- **Push integrations** — `ppcap push` sends the ranked, suppression-filtered alert queue to
  Slack, Microsoft Teams, Jira, TheHive, Splunk HEC, Elastic (ECS) or any OCSF consumer, or a
  plain webhook. Destinations are a shareable JSON file that names secrets by environment
  variable; a sent ledger prevents duplicate tickets; `--dry-run` and `--out-dir` work offline.
- **Zeek logs out, Suricata EVE in** — `ppcap zeek` (or `analyze --zeek`) writes Zeek-format
  conn / dns / http / ssl / ssh / files logs plus a notice log of findings, linked by one `uid`,
  for any SIEM pipeline that reads Zeek; `analyze --eve` and `ppcap eve` fold a Suricata sensor's
  alerts into the alert queue so they rank and correlate with PacketPilot's detections.
- **Explainable severity** per flow + per-IP **report cards** (score, evidence, ATT&CK).
- Columnar Parquet output + DuckDB view; summary JSON.
- Triage dashboard (severity strip, threat panel, charts) + virtualized flows + drill-down.
- One-click **HTML / JSON report** export (print-to-PDF); in-app Export button.
- Native **Tauri desktop app** + browser build from one codebase.
- **Online reputation enrichment** — opt-in, bring-your-own-key corroboration of public IPs via
  AbuseIPDB / GreyNoise / VirusTotal; aggressively cached (local only), privacy-preserving (only
  bare public IP strings leave the device, never packets or internal IPs).
- **Evidence Integrity & Chain of Custody** — `analyze --evidence` seals a tamper-evident
  manifest over the run (input + every artifact SHA-256, tool version, exact settings, capture
  window); `ppcap verify` re-checks the whole bundle offline with per-file intact/missing/
  modified verdicts — court-ready custody for the analysis itself, generalizing Safe Share's
  manifest.
- **Natural Language Querying** — a **Query** tab running read-only DuckDB SQL over the flow
  table *entirely in-browser* (lazy DuckDB-Wasm; nothing leaves the device), with bundled +
  saved queries, CSV export, and a flow_id cross-filter into the Flows view. With AI enabled,
  ask in plain English and the model writes the SQL (only the question text is sent — the SQL
  always runs locally).
- **AI Analyst Assist** — opt-in NL executive brief + interactive chat over the *derived* summary
  (not raw packets). BYO endpoint — Anthropic/OpenAI/OpenRouter/Ollama/Custom. Privacy-preserving:
  only the engine's computed summary ever leaves; localhost endpoints stay fully on-device. Desktop
  stores the API key in the OS keychain; browser routes through a user-supplied streaming relay.

