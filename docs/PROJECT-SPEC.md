# PacketPilot — Project Specification

*One-click packet-capture triage for cybersecurity professionals.*
Status: design/spec · 2026-06-18 · Deployment: hybrid (Tauri desktop + optional team server) · Placement: fresh standalone.

---

## 1. Problem & vision

An analyst opens a `.pcap` in Wireshark and faces millions of undifferentiated rows. Triage
demands display-filter fluency, protocol knowledge, and time. Worse, Wireshark loads the whole
file into memory and becomes unusable past a few hundred MB — multi-GB captures are often
impossible to open. The tools that *do* scale (Arkime, Malcolm) demand heavy infrastructure and
still assume the analyst knows what to look for. Online analyzers are easy but exfiltrate
sensitive packet payloads to third-party clouds.

**Vision:** open any capture, click once, and in seconds get *the answer* — what's in this
traffic, what's dangerous, why, and what to do — visualized, drillable, exportable, and
entirely on-device by default.

**Primary users:** SOC analysts, incident responders / DFIR, threat hunters, network/security
engineers, pentesters, and students. **Job-to-be-done:** "I have a capture. Tell me fast and
clearly whether it's bad, where, and let me prove it."

---

## 2. Market gap analysis

| Tool | What it's great at | Where it falls short (our opening) |
|---|---|---|
| **Wireshark / tshark** | Deepest dissection, ~3000 dissectors, ground truth | Single-threaded dissection; loads file into RAM (sluggish >100 MB, often can't open multi-GB); manual, expert-only; no triage, severity, threat-intel, reporting, or IP reputation; table-only |
| **Arkime** (ex-Moloch) | Full-packet capture, indexing, scale to many Gbps | Heavy OpenSearch/Elastic cluster + ops burden; built for continuous capture, not ad-hoc file triage; query expertise required; no built-in severity/enrichment |
| **Zeek** | Rich L7 metadata logs, scriptable | A log generator/framework, not a UI; Zeek-scripting learning curve; needs ELK on top; no scoring/viz alone |
| **Suricata** | Signature IDS/IPS alerts (EVE JSON) | Alerts only; FP-heavy untuned; no holistic view or workspace |
| **Brim / Zui** | Large pcaps on the desktop (Zeek+Suricata) | Requires Zed/ZQL query familiarity; thin automated severity & threat-intel; viz is query-driven, not summary-first; no management report/IP reputation |
| **NetworkMiner** | Artifact/credential extraction, host-centric | Windows-centric; key features behind paid tier; no severity/threat-intel; dated UI; no big-data scale |
| **Malcolm** (CISA/INL) | Free full suite (Arkime+Zeek+Suricata+OpenSearch), offline | Heavy Docker stack & resources; steep; "know what to look for" dashboards; not laptop-light or one-click |
| **NetWitness / Corelight / ExtraHop / Vectra / Darktrace** | Enterprise NDR, real-time, ML, polished | Expensive; sensors/appliances/cloud; long procurement; not for "analyze this saved pcap"; data often leaves to vendor cloud |
| **CloudShark / PacketTotal / A-Packets** | Zero-install, shareable web analysis | Upload sensitive captures to 3rd-party cloud (compliance killer); size limits; shallow automated severity/enrichment |

**The empty middle PacketPilot occupies:** a **one-click, local-first, lightweight** experience
that (a) ingests an *entire* capture of any size without choking, (b) auto-produces a
plain-English summary + categorized breakdown, (c) scores every IP/indicator's severity with
*explainable* threat-intel, (d) correlates findings into ranked incidents, and (e) exports a
report — all while keeping packets on-device and running on a normal laptop.

> **One-line positioning:** *The scale of Arkime, the simplicity of one click, the privacy of local-first.*

---

## 3. The one-click experience

`Open .pcap → progress streams → Triage Dashboard`

The dashboard is **summary-first** — the answer appears *before* any filtering:

1. **Summary card** — file stats, capture time range, # hosts/flows, headline risks, incidents-by-severity.
2. **Severity-ranked incidents** — correlated stories ("Host A beaconing to known-C2 1.2.3.4"), top of the list.
3. **Traffic categories** — web / DNS / email / file transfer / remote access / VoIP / IoT-OT / tunneling-VPN / scanning / malware-C2 / anomalous.
4. **IP severity map** — every external IP scored Critical→Info with reputation evidence.
5. **Timeline + top talkers + protocol breakdown** — visual, interactive.

Everything drills down: dashboard → category → conversation → flow → packet bytes/hex. Then **Export report** (analyst + management versions). No filter expertise required to reach insight.

---

## 4. Complete feature list

### A. Ingestion & engine
- One-click open of pcap / pcapng (+ gzip, multi-file merge); drag-drop, file picker, CLI, and "watch folder."
- **Streaming, memory-mapped parsing** with bounded RAM — handles multi-GB to tens-of-GB captures.
- **Multi-core parallel dissection**, reusing tshark / Zeek / Suricata as sidecar processes.
- Flow reconstruction (5-tuple), TCP stream reassembly, bidirectional flows.
- L7 extraction: DNS, HTTP, TLS (SNI / JA3 / JA4 / certs), SMB, FTP, SMTP, QUIC, ICMP, DHCP, Kerberos, LDAP, RDP, SSH, etc.
- File/artifact carving (extracted files, images, executables) with hashing.
- Columnar persistence + indexes; resumable, idempotent; SHA-256 chain-of-custody on every capture.

### B. Automated analysis & summary
- Auto-generated **plain-English executive summary** (optional, LLM-assisted, privacy-gated).
- Traffic **categorization** by taxonomy (above).
- Top talkers, conversations, protocol hierarchy, port usage, bandwidth-over-time, packet-size & TTL distributions.
- **Behavioral detection:** C2 beaconing (periodicity/jitter), DNS tunneling / DGA, port & host scanning, brute force, data exfiltration, lateral movement, cleartext credential exposure, self-signed/expired certs, suspicious JA3/JA4, plaintext PII.

### C. Threat intelligence & IP severity
- Per-IP / per-indicator **severity score** (Critical / High / Medium / Low / Info) — fully explainable.
- Reputation enrichment: AbuseIPDB, GreyNoise (noise filtering), VirusTotal, AlienVault OTX, Spamhaus/DNSBLs, ASN/Geo (MaxMind), Tor/VPN/cloud tagging.
- **Offline / air-gapped mode:** local MISP + downloaded feeds; no observable leaves the device unless opted in.
- IOC extraction & export (STIX 2.1 / CSV); MITRE ATT&CK technique mapping; per-IP **report cards** (verdict, sources, geo/ASN, flows, ATT&CK, recommended action).
- **Incident correlation:** collapse atomic alerts into ranked incidents per host/flow.

### D. Visualization & interaction
- **Triage dashboard** (summary-first, zero-config).
- **Virtualized tables** — millions of rows at 60fps, sort / filter / group / column pick.
- Visuals: severity heatmap, interactive timeline, conversation/flow graph, geo map, protocol treemap/sunburst, bandwidth charts.
- Drill-down to packet bytes/hex (lazy-loaded), follow-stream, export selection.
- Wireshark **display-filter compatibility** (familiar syntax) + optional natural-language query.
- Saved views, tagging, bookmarks, annotations, dark mode, full keyboard-driven triage.

### E. Reporting & collaboration
- **One-click report export** — PDF / HTML / JSON / CSV, analyst + management versions.
- Case management; capture comparison/diff & baselining.
- (Team server) shared cases, comments, assignment, audit trail.

### F. Hybrid platform & integrations
- **Desktop (Tauri):** local, offline, low-resource — the default.
- **Optional team server:** shared case store, RBAC, large/continuous captures, central feeds, audit.
- Sync: push a local case to the server; pull team threat feeds.
- **Integration APIs:** export findings to **RuleForge AI** (auto-generate Sigma/SIEM rules from observed threats) and **Sentinel** (SOC incidents); SIEM/SOAR via webhook / syslog / STIX-TAXII.

### G. Security & compliance
- Captures stay local by default; enrichment is opt-in and sends only derived observables, never payloads.
- Encrypted-at-rest case store; audit log; signed auto-updates; **no telemetry by default**.
- Redaction for sharing; chain-of-custody hashing for forensic integrity.

---

## 5. Tech stack

### Engine / data plane — **Rust** (the hot path)
- Parsing: native Rust fast-path (`pcap-parser`, `etherparse`, `pnet`) for flows/metadata + **tshark** sidecar for dissection breadth; optional **Zeek** & **Suricata** sidecars (ingest their logs/EVE).
- Concurrency: `tokio` + `rayon` (work-stealing); `memmap2` for memory-mapped IO; bounded channels for back-pressure.
- Columnar: **Apache Arrow** + **DuckDB** (embedded, runs in-process on *both* desktop and server) + **Parquet** for persisted cases.

### Desktop shell — **Tauri 2**
- Rust backend + web frontend; tens-of-MB install, low RAM (vs Electron). The Rust engine is the Tauri core/sidecar.

### Frontend — **React + TypeScript + Vite**
- **TanStack Virtual + TanStack Table** for virtualized grids; **TanStack Query** + Zustand for state.
- **DuckDB-Wasm** for in-browser analytical queries (desktop) or **Arrow Flight** to server.
- Viz: **Apache ECharts** / **visx** (charts), **deck.gl**/WebGL (large scatter/geo/flow), **Cytoscape.js**/sigma.js (conversation graphs), **MapLibre** (geo).
- **Tailwind + shadcn/ui** (consistent with your nexus/RuleForge stacks).

### Server (optional team mode)
- API: **Rust (Axum)** sharing the engine crate (or Go; Python/FastAPI only to reuse Sentinel).
- Storage: **MinIO/S3** (captures) · **ClickHouse** (columnar flow/packet metadata at scale) · **OpenSearch** (optional full-text/IOC search) · **Postgres** (cases/users/RBAC) · **Redis** (cache/queues).
- Ingestion: horizontally-scalable Rust workers on a queue (NATS / Redis Streams / Kafka — Kafka if aligning with Sentinel).

### Detection & threat intel
- **Suricata** (signatures), **Zeek** (L7 logs), **YARA** (carved files).
- Enrichment connectors: AbuseIPDB, GreyNoise, VirusTotal, OTX, Spamhaus, MaxMind GeoLite2; **MISP** for offline.

### AI/LLM (optional, privacy-gated)
- **Claude (Opus 4.8 / Sonnet 4.6)** for plain-English summaries, report narration, and NL→filter translation.
- **Off by default in air-gapped mode**; never sends raw payloads — only derived metadata, with explicit consent.

### Build & CI
- Cargo + pnpm + Vite + Tauri bundler; cross-platform (Windows/macOS/Linux). Docker Compose + Helm for the server. GitHub Actions (lint · typecheck · test · build), matching your other repos.

> **Licensing note:** Wireshark/tshark, Zeek, and Suricata are GPL/GPL-compatible. Invoke them as **separate sidecar processes** (don't statically link) so PacketPilot's own (non-GPL) code stays unencumbered.

---

## 6. Infrastructure & performance architecture

The "runs smooth, no latency/lag, light resources" requirement, made concrete:

| Principle | Mechanism |
|---|---|
| **Never full-load** | Streaming + memory-mapped reads; bounded channels → constant memory regardless of file size |
| **Parse once, query forever** | First pass writes Arrow/Parquet + indexes; UI only queries DuckDB/ClickHouse, never re-parses. Re-open = instant (cached by file hash) |
| **Two-tier dissection** | Fast native flow/metadata pass over the whole file; deep per-packet dissect only on demand |
| **Parallelism** | Split capture by byte-range/time-window across cores (rayon); merge flow tables → near-linear scaling |
| **Render a window, not the dataset** | Virtualized tables + Wasm/server pagination; tiny DOM; 60fps over millions of rows |
| **Off-thread everything** | Web workers + Rust sidecar; UI thread never blocks; <100ms interactions |
| **Tiered caching** | RAM (hot flows) → local Parquet/DuckDB (case) → server ClickHouse (team); reputation lookups cached & deduped |
| **Progressive results** | Dashboard streams in as analysis completes (summary first) — time-to-first-insight in seconds |
| **Scale path** | Desktop = laptop scale; server adds horizontal ingestion workers + ClickHouse for 10s–100s GB & continuous feeds |

### Performance budgets (SLOs to design against)
- **Time-to-first-insight:** < 5 s for a 1 GB pcap on a laptop (summary + top incidents streaming).
- **Full analysis:** ~minutes for 10 GB, with bounded RAM.
- **Scroll / filter / sort:** < 100 ms perceived; 60 fps.
- **Idle desktop footprint:** < 150 MB RAM; install tens of MB (Tauri).
- **Re-open cached case:** < 1 s.

### One-click data flow
`Open → hash & validate → mmap + chunk → parallel dissect (native + tshark/Zeek/Suricata) → flows/L7/artifacts → Arrow columnar + indexes → enrich (cached, offline-capable) → detect + categorize + score → correlate incidents → stream to dashboard → drill-down / report`

---

## 7. Data model (sketch)

- **capture**(id, path, sha256, bytes, first_ts, last_ts, pkt_count, status)
- **flow**(flow_id, capture_id, src_ip, dst_ip, src_port, dst_port, proto, app_proto, bytes_c2s, bytes_s2c, pkts, start_ts, end_ts, ja3, ja4, sni)
- **packet_index**(capture_id, flow_id, ts, offset, len) — for lazy deep-dissect
- **indicator**(value, type, capture_id, first_seen, last_seen)
- **enrichment**(indicator, source, verdict, score, asn, geo, tags, fetched_at) — cached
- **finding**(id, capture_id, category, rule, severity, confidence, attack_technique, evidence, flow_ids)
- **incident**(id, capture_id, host, severity, finding_ids, narrative)
- **artifact**(id, capture_id, flow_id, filename, sha256, mime, path)

Columnar tables (flow, packet_index) in DuckDB/Parquet (desktop) or ClickHouse (server); relational tables (capture, finding, incident, case) in SQLite (desktop) / Postgres (server).

---

## 8. Severity model (explainable)

`score = w1·reputation + w2·behavior + w3·asset_context + w4·confidence` → mapped to bands
(Critical / High / Medium / Low / Info). Every score **must** show its evidence: which sources,
which matched rules, which behavior. No black-box numbers — a SOC lead or auditor can trace any verdict.

---

## 9. Roadmap (phased)

- **Phase 0 — Engine MVP:** Rust streaming parser → Arrow/DuckDB; flows + protocol hierarchy; CLI emitting summary JSON. *Prove the perf budget on a 5–10 GB pcap.*
- **Phase 1 — Desktop triage:** Tauri app; one-click open; triage dashboard; virtualized tables; categories; drill-down to packet.
- **Phase 2 — Threat intel & severity:** enrichment connectors + offline MISP; explainable severity; IP report cards; ATT&CK; Suricata/Zeek integration; incident correlation.
- **Phase 3 — Reporting & detection depth:** report export; behavior detections (beaconing, tunneling, exfil); saved cases; capture diff.
- **Phase 4 — Team server:** server mode, RBAC, ClickHouse scale, shared cases, feeds; integration APIs to RuleForge AI & Sentinel; SIEM/SOAR export.
- **Phase 5 — AI assist:** plain-English summaries, NL query, guided investigation (Claude), all privacy-gated.

---

## 10. Key risks & mitigations

- **GPL entanglement** from tshark/Zeek/Suricata → run as separate sidecar processes; bundle binaries, don't link.
- **Reputation API limits/cost** → cache + dedupe + offline feeds.
- **Detection false positives** → layered signatures+behavior, correlation, and explainability.
- **Sidecar packaging on desktop** → bundle pinned tshark/Zeek/Suricata builds per-OS; verify on install.
- **Sensitive data handling** → local-first default, opt-in enrichment, encryption at rest, redaction, audit.

---

## 11. Specialist agents & skills (installed)

Build with: `pcap-engine-engineer` (engine), `threat-intel-analyst` (enrichment/severity),
`detection-engineer` (detection/categorization), `netforensics-frontend` (UI/viz),
`perf-infra-architect` (perf/deploy), and the `analyze-pcap` skill (the pipeline contract).
Use superpowers `brainstorming` → `writing-plans` → `executing-plans` to drive each phase.
