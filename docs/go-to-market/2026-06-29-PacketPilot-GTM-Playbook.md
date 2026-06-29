# PacketPilot — Go-To-Market & Sales Playbook

**Prepared:** 2026-06-29 · **Owner:** Founder · **Status:** pre-launch
**Optimized for:** solo founder · ~$0 marketing budget · individual security practitioners (first buyers) · **maximize MRR in 90 days**
**Product:** https://packet-pilot.vercel.app — in-browser PCAP threat-triage SaaS

---

## Strategy at a glance

PacketPilot is built and deployed. The job now is to convert a privacy-first, in-browser PCAP triage tool into recurring revenue. Optimized for your three constraints — **solo / $0 budget**, **individual practitioners first**, **maximize 90-day MRR** — the plan takes one specific shape:

- **One wedge, repeated everywhere:** *"Drop a pcap, get a verdict — nothing leaves your machine."* Privacy + automated triage is the uncontested white-space between **Wireshark** (manual, shows packets) and **cloud uploaders** (A-Packets / CloudShark, which ship your evidence offsite and even make free results public).
- **Free does the marketing; Pro captures the value.** Keep the in-browser analyzer free and ungated — it's your virality + SEO engine and costs ~$0 since analysis runs client-side. Gate the *workflow accelerators*: AI summary, reputation enrichment, the five exports (STIX/MISP/CEF/Sigma/HTML), PCAP carve, multi-capture compare, saved rules.
- **Organic-only growth.** High-intent SEO ("analyze pcap online", "wireshark alternative", "pcap to csv"), value-first presence in infosec communities, and stacked launches (Show HN → Product Hunt → Reddit). No paid acquisition until the funnel converts.
- **Pull MRR forward.** Annual-first pricing + a capped "founder" early-bird deal, fired into your first traffic spike. (See §3 and §8 for the model.)
- **The one gate before any of this:** flip **Stripe from test → live**, publish **Terms / Privacy / a "your data never leaves your browser" trust page**, wire **analytics + error monitoring**, and **rotate the temp admin password**. You cannot collect a dollar until Stripe is live — make it the first checklist item (§8).

**How to use this doc:** §1–§2 are positioning you'll reuse in every asset. §3 is the money model. §4 is what to *do*, week by week. §5–§7 are the demand engine + copy you can paste. §8 is the dashboard + the go-live checklist. Start at §8's checklist, then execute §4.

---

## Table of contents

1. [Positioning, Category & Value Proposition](#1)
2. [Ideal Customer Profile & Buyer Personas](#2)
3. [Pricing & Packaging (90-day MRR plan)](#3)
4. [The 90-Day Go-To-Market Plan](#4)
5. [Demand Generation: SEO, Content & Community](#5)
6. [Self-Serve Funnel, Activation & Retention](#6)
7. [Sales & Launch Collateral Kit (copy-ready)](#7)
8. [Metrics, Financial Model & Launch-Readiness Checklist](#8)

---

<a id="1"></a>

## 1. Positioning, Category & Value Proposition

### One-line positioning statement

> **For security practitioners who need to know what's in a packet capture *right now* — without uploading evidence to someone else's server — PacketPilot is the in-browser network threat-triage tool that turns a raw .pcap into ranked, MITRE-mapped findings and an analyst-grade report in seconds, while the capture never leaves your machine. Unlike cloud uploaders (A-Packets, CloudShark) and manual analyzers (Wireshark), it gives you the verdict, not just the packets — privately, by default.**

Tightened to the canonical template:

| Slot | Fill |
|---|---|
| **For [audience]** | SOC analysts, DFIR responders, and pentesters |
| **who [pain]** | get handed a pcap and need a fast malicious/not verdict — but can't (or won't) upload evidence to a third-party server |
| **PacketPilot is the [category]** | in-browser network threat-triage tool |
| **that [benefit]** | turns a capture into ranked, MITRE-mapped findings + an exportable report in seconds, with zero install and nothing leaving the device |
| **unlike [alternative]** | cloud uploaders (A-Packets, CloudShark) that ship your packets offsite, and Wireshark, which shows you packets but never tells you what's wrong |

### Category framing

**Primary category (own this): "in-browser network threat triage."**

Pick the category by what's defensible and uncontested, not what's highest-volume:

| Candidate category | Verdict | Why |
|---|---|---|
| **"In-browser network threat triage"** | ✅ **Lead with this** | Fuses your two unforgeable wedges — *private/client-side* + *automated verdict (triage)*. No incumbent occupies it; it's the white-space the research confirms is open. |
| **"PCAP triage" / "automated PCAP analysis"** | ✅ Use as SEO/discovery label | Matches search intent ("analyze pcap online," "pcap triage"). Use in page titles and meta, not as the brand promise. |
| **"Wireshark alternative"** | ⚠️ Use *only* as a comparison/SEO hook | High-intent search term, but framing yourself as Wireshark's *alternative* invites a feature-depth fight you lose (3000+ protocols). Position as "triage *before* Wireshark," not "instead of." |
| **"Network detection & response (NDR)"** | ❌ Avoid | That's Corelight/Darktrace/Vectra's enterprise-sensor category — wrong buyer, wrong budget, implies live-sensor infra you don't have. |
| **"PCAP viewer"** | ❌ Avoid | Commoditized and undersells you — viewers (PCAP Viewer Online) stop at the packet list; your value is everything above it. |

**The category sentence to repeat everywhere:** *"PacketPilot is in-browser network threat triage — drop a pcap, get a verdict, nothing leaves your machine."*

### Core value propositions (each tied to a real, shipped feature)

| # | Value prop (headline) | The promise | Backed by these REAL features |
|---|---|---|---|
| **1** | **Your packets never leave your machine** *(lead wedge)* | Full analysis runs locally in the browser via a Rust→WASM engine. The capture is never uploaded. Compliance/air-gap-friendly by default — no on-prem deployment, no per-analysis server cost. | Client-side WASM engine; works offline/anonymous, no signup to analyze; only an *optional* derived summary + public IPs transit the backend for AI/reputation, gated behind opt-in + login. |
| **2** | **A verdict, not a packet list** | Drop a capture and get ranked threat findings with incident severity scoring — the "what's wrong and how bad" that Wireshark makes you derive by hand. | ~20 behavioral detectors (brute-force, lateral movement, port scan, ARP spoof, SYN flood, cryptomining, DGA, DNS tunneling, data-exfil, malware download + SHA256 file carving, weak/deprecated TLS, cleartext creds, PII exposure, etc.); incident scoring; score waterfall; findings triage table; incident hero. |
| **3** | **Framework-grade output the expensive tools reserve for enterprise** | Every finding maps to MITRE ATT&CK with a kill-chain coverage matrix and per-technique links — analysis you normally only get from Darktrace/Vectra/sandboxes. | MITRE ATT&CK matrix (T1110, T1552, T1040, T1046, T1557.002, T1499.001, T1496, T1568.002, T1133, T1595, T1036, T1105…); per-finding technique chips linking to attack.mitre.org; threat-intel severity scoring. |
| **4** | **Zero install, instant, no signup** | No desktop install, no account, no upload wait. Open the URL, drop a file, get answers — the convenience of a web tool with the privacy of a local one. | Live web app (Vercel); anonymous first-run; supports .pcap/.pcapng/.cap/.gz; also a local-first Tauri desktop path. |
| **5** | **Exports that drop straight into your SOC/IR workflow** | Hand off the result in the format your stack already speaks — report, intel, or detection rules — plus carve the exact traffic you need. | Polished HTML report, STIX 2.1, CSV, MISP event, CEF, Sigma rules; PCAP flow/host carving; Suricata rule import → RuleMatch findings; multi-capture diff; per-host triage annotations. |

*Optional 6th (use selectively, not in the lead): privacy-preserving AI assist — one-click executive summary + NL chat that runs only over the derived summary, never raw packets.*

### Differentiation table vs. top competitors

| Capability | **PacketPilot** | **A-Packets** (closest direct) | **Wireshark** (the substrate) | **PCAP Viewer Online** (in-browser peer) |
|---|---|---|---|---|
| **Hosting / privacy** | ✅ **100% in-browser, nothing uploaded** | ❌ Upload required; **free results are public** | ✅ Local desktop | ✅ In-browser (no upload) |
| **Install required** | ✅ None (web) | ✅ None (web) | ❌ Desktop install | ✅ None (web) |
| **Automated threat triage / verdict** | ✅ ~20 behavioral detectors + scoring | ⚠️ Pattern hints, not a scored verdict | ❌ Manual only | ❌ Viewer only |
| **Incident severity scoring** | ✅ Yes (score waterfall, incident hero) | ❌ No | ❌ No | ❌ No |
| **MITRE ATT&CK mapping** | ✅ Full matrix + per-technique links | ❌ No | ❌ No | ❌ No |
| **Artifact / file carving** | ✅ File carving (SHA256) + PCAP carve | ✅ Strong (files, creds, handshakes) | ⚠️ Manual export objects | ❌ No |
| **Analyst exports (STIX/MISP/CEF/Sigma)** | ✅ All five + HTML report | ⚠️ Limited | ⚠️ Manual / plugins | ❌ No |
| **Fingerprinting (JA3/JA4/JA4-Q/JA3S/HASSH)** | ✅ Full suite | ⚠️ Partial | ⚠️ Via plugins | ❌ No |
| **Reputation / threat-intel enrichment** | ✅ AbuseIPDB / GreyNoise / VirusTotal (opt-in) | ⚠️ Some | ❌ No | ❌ No |
| **Deep per-protocol dissection (3000+ protos)** | ⚠️ Focused (triage, not full dissection) | ⚠️ Moderate | ✅ **Gold standard** | ⚠️ Wireshark-engine view |
| **Price (individual)** | **Free tier + Pro $19/mo** | Free (public) / paid packs | Free (OSS) | Free (OSS) |

**One-line takeaways to deploy per competitor:**
- **vs A-Packets:** *"They upload your packets (and make free results public). We never upload anything — and we hand you a MITRE-mapped verdict, not pattern hints."*
- **vs Wireshark:** *"Wireshark shows you every packet. PacketPilot tells you which ones are the problem — then you can still open it in Wireshark."*
- **vs PCAP Viewer Online:** *"They show you packets in the browser. We tell you what's wrong in the browser — triage, scoring, and MITRE, not just a viewer."*

### Elevator pitch

**One sentence:**
> PacketPilot is an in-browser PCAP triage tool that turns a raw packet capture into ranked, MITRE-mapped threat findings and an analyst-grade report in seconds — without the capture ever leaving your machine.

**One paragraph:**
> When a SOC analyst or incident responder gets handed a packet capture, they face a bad choice: dig through it manually in Wireshark for an hour, or upload the evidence to a cloud analyzer that ships sensitive traffic offsite (and, on free tiers, sometimes makes the results public). PacketPilot removes the tradeoff. Its analysis engine is compiled to WebAssembly and runs entirely in your browser, so you drop a .pcap and get instant automated triage — ~20 behavioral detectors (C2 beaconing, port scans, DGA, cleartext creds, malware downloads with SHA256 file carving, and more), incident severity scoring, full MITRE ATT&CK mapping, and one-click exports to STIX, MISP, CEF, Sigma, or a polished HTML report — while the capture itself never touches a server. Zero install, no signup to start, works offline. It's the privacy of a local tool with the speed of a web app, and the automated verdict that Wireshark, A-Packets, and the in-browser viewers don't give you.

### Proof points / reasons-to-believe

1. **Architecturally private, not policy-private.** The capture *can't* leak because there's no upload path for it — analysis is a Rust→WASM engine executing in the browser tab. You can verify it: it runs offline, with no account, and the network tab shows no packet upload. (Only an *optional*, opt-in derived summary + public IPs ever transit the backend, and only for AI/reputation enrichment behind login.) This is the air-gap/compliance story that A-Packets, PacketSafari, and Joe Sandbox charge "on-prem" pricing to match.
2. **Breadth that's normally split across three tool tiers.** ~20 MITRE-mapped behavioral detectors + JA3/JA4/JA4-Q/JA3S/HASSH fingerprinting + SHA256 file carving + five interchange exports (STIX/MISP/CEF/Sigma/CSV) in one free-to-start web app — capabilities you'd otherwise assemble from a desktop forensics tool (NetworkMiner), an enterprise NDR (for the MITRE rollup), and a cloud analyzer.
3. **It fills a real vacuum.** PacketTotal — the canonical "drop a pcap, get IOCs online" tool — shut down (~2023–24), pushing analysts to upload-and-public alternatives or nothing. PacketPilot is "PacketTotal, but private and nothing leaves your browser," and it's already built, deployed, and live at packet-pilot.vercel.app.

**RTB one-liners for landing/launch copy:**
- *"Check the Network tab. We'll wait. Your pcap never uploads."*
- *"~20 MITRE-mapped detectors. Five analyst exports. Zero packets uploaded."*
- *"The convenience of an online analyzer, the privacy of an air-gapped one."*

---

<a id="2"></a>

## 2. Ideal Customer Profile & Buyer Personas

> **TL;DR for the founder:** Sell to **individual security practitioners** first, with **SOC / blue-team triage analysts as the beachhead** and **pentesters/bug-bounty hunters as the early monetization wedge** (highest proven personal willingness-to-pay). The "aha" is one drop of a pcap → a ranked verdict + copy-paste ticket text in under 10 seconds, **with nothing leaving the browser.** Everything below is built to make that conversion happen inside the first session.

---

### 1. Beachhead segment

**Primary beachhead: SOC / blue-team triage analysts (T1–T2), bleeding into threat hunters.**
**Early monetization wedge (run in parallel): pentesters / red-teamers / bug-bounty hunters.**

| Dimension | Beachhead (SOC/blue-team) | Why it wins first |
|---|---|---|
| Pain frequency | Every shift, thousands of alerts/day, ~2/3 false positives, documented burnout | Frequency → habit → retention |
| JTBD ↔ product fit | Their verb is literally *triage* — maps 1:1 to "verdict + evidence + ticket text" | Tightest fit of any segment |
| Buy path | Can't buy, but textbook *champion*: free on shift → forward to lead → seats | Cleanest bottom-up→expense motion |
| Population | Large, replenishing (~70% of juniors churn in 3 yrs → carry tools to next SOC) | Built-in evangelism + distribution |
| Adjacency | Win triage → threat hunters, DFIR, and students fall out for free | Expansion shares one engine |

**Why not lead with pentesters?** They have the *highest proven personal WTP* (Burp Pro is per-user, ~$449/yr, bought out of pocket because "one bounty pays for the year") and pay **pre-employer** — perfect for early cash. But their pcap need is *secondary* to web/recon, so retention is weaker and the market is narrower. **Strategy: land SOC for volume + retention; milk pentester WTP opportunistically for early MRR.**

---

### 2. Detailed personas

#### Persona A — "Maya," SOC Analyst (T1/T2) · **BEACHHEAD**

| | |
|---|---|
| **JTBD** | "An alert handed me a pcap/flow — tell me in 60 seconds if it's malicious, what talked to what, and what to put in the ticket." |
| **Trigger / pain moment** | 15 minutes deep in Wireshark on one alert, flipping between tools, queue stacking up behind her. Search intent: *"quickly analyze pcap for malicious traffic," "Wireshark too slow large capture," "pcap triage automation."* |
| **Where she is** | r/blueteamsec, r/AskNetsec, r/cybersecurity; CyberDefenders + Discord; TryHackMe community; SANS blue-team content; DFIR Discord `#network-forensics`. |
| **What makes her try** | No signup, runs in-browser, **capture never leaves her machine** (so she can run it on *tonight's real alert* without a policy violation). |
| **What makes her pay (or champion)** | Saves visible triage minutes → forwards link to lead → team seats at $10–30/seat. Personal spend ~$0 (employer cost). |
| **Top objections** | "Is my evidence really staying local?" · "Can I trust an automated verdict?" · "Does it handle a real multi-GB capture?" · "I already have Wireshark/Arkime." |
| **Objection-killers** | Client-side WASM badge + "no upload" proof · transparent per-finding evidence + MITRE link (not a black box) · show it on a big real capture · "we triage *for* Wireshark, then hand off." |

#### Persona B — "Devon," DFIR / Incident Responder

| | |
|---|---|
| **JTBD** | "Reconstruct an incident from a capture — extract files/creds/hosts/sessions, build a timeline, produce a defensible report." |
| **Trigger / pain moment** | Handed a multi-GB capture mid-incident under time pressure; Wireshark chokes, manual carving is slow, a report is due. |
| **Where he is** | SANS DFIR (FOR572), Malware-Traffic-Analysis.net, DFIRMadness, This Week in 4n6 newsletter, NetworkMiner/Arkime/Zeek communities, #DFIR on X/Mastodon. |
| **What makes him try** | File carving + SHA256, IOC extraction, STIX/MISP/CEF export, and **chain-of-custody-friendly "evidence stays local"** (huge for DFIR). |
| **What makes him pay** | Freelance/consultant = **personal card** (~$20–60/mo, bills client back); in-house = expenses it. Tools are revenue-generating. |
| **Top objections** | "Defensible/repeatable enough for a report?" · "Will it scale to my capture size?" · "Does the export fit my SIEM/case tool?" |
| **Objection-killers** | Polished HTML report + deterministic detectors (not just LLM) · large-file handling story · the 5 export formats already shipped. |

#### Persona C — "Sam," Pentester / Red-Teamer / Bug-Bounty · **MONETIZATION WEDGE**

| | |
|---|---|
| **JTBD** | "What did I just capture off this device/network? Prove exfil/C2 in an engagement; produce evidence for the report." (Secondary for pure-web hunters; real for network/IoT/thick-client work.) |
| **Trigger / pain moment** | Sitting on a capture from a thick-client/IoT/red-team op, needs IOCs + a clean evidence artifact fast. |
| **Where they are** | X/Twitter infosec, bug-bounty Discords/Telegram, PortSwigger community, NahamSec/YouTube, InfoSec Write-Ups, GitHub "awesome-bugbounty." Discovery = methodology write-ups. |
| **What makes them try** | Fingerprinting (JA3/JA4/JA4-Q/JA3S/HASSH), cleartext-cred + file extraction, fast evidence export. **Discovery via a write-up, not an ad.** |
| **What makes them pay** | **Already pays out of pocket** (Burp Pro precedent). ROI framing: "one bounty/engagement pays for the year." ~$20–60/mo personal, pre-employer. |
| **Top objections** | "Is pcap even core to my workflow?" · "Does it beat my existing scripts/Wireshark filters?" |
| **Objection-killers** | Lean into fingerprinting + carve as one-click vs. hand-rolled · annual "one bounty = a year" pricing. |

#### Persona D — "Priya," Network / Security Engineer

| | |
|---|---|
| **JTBD** | "App is slow/flaky — find the retransmissions, resets, bad handshakes, the *one* bad conversation in millions of packets." |
| **Trigger / pain moment** | Outage bridge call, capture in hand, execs waiting. Intent leans **troubleshooting, not threat** (adjacent, not core). |
| **Where she is** | r/networking, Cisco Learning Network, NANOG, Wireshark Q&A/SharkFest, LinkedIn. Wireshark is a *daily* tool here. |
| **What makes her try** | "Paste a pcap → top talkers / retransmits / TLS versions in-browser, nothing uploaded." Frame for **performance, not security.** |
| **What makes her pay** | Low personally (Wireshark is free + sufficient). ~$0 personal; $15–25/seat employer tool if it shaves outage MTTR. |
| **Top objections** | "Wireshark already does this for free." · "My JTBD is troubleshooting, you're a security tool." |
| **Objection-killers** | "Minutes vs. hours" auto-flagging of the interesting packets · don't oversell — position as a fast *first pass* before Wireshark. **Treat D as expansion, not a launch target.** |

> **Feeder segment — Students / CTF players (not a persona to monetize, a pipeline):** live on TryHackMe/HTB Discords, CyberDefenders, Malware-Traffic-Analysis.net, r/securityCTF. Already pay ~$8–14/mo for THM out of pocket, so they'll spend *small* but expect a free tier. **Strategic value = word-of-mouth + they graduate into Personas A/B/C carrying the tool with them.** Keep them on Free forever; they are your distribution flywheel.

---

### 3. Top use cases / "I need to…" scenarios

The concrete, high-intent jobs to feature on landing pages, in demos, and as SEO targets (each maps to a shipped capability):

| # | "I need to…" | Maps to | Primary persona |
|---|---|---|---|
| 1 | …**triage this alert's pcap fast** and know if it's malicious + why | Findings + severity scoring + MITRE matrix | Maya (A) |
| 2 | …**find C2 / beaconing / lateral movement** in a capture | Behavioral detectors (lateral, exposed remote access) | Maya / Devon |
| 3 | …**extract files (and their SHA256) from a pcap** | File carving + malware-download detection (T1105) | Devon / Sam |
| 4 | …**pull cleartext creds / spot PII exposure** in traffic | Cleartext-cred (T1552) + PII (T1040) detectors | Devon / Sam |
| 5 | …**detect a port scan / ARP spoof / SYN flood / DGA / cryptomining** | Dedicated MITRE-mapped detectors | Maya / hunters |
| 6 | …**get JA3/JA4/JA3S/HASSH fingerprints** out of a capture | Fingerprinting suite | Sam (C) |
| 7 | …**produce an analyst report / export IOCs to my SIEM** (STIX/MISP/CEF/CSV/Sigma) | Export surface + HTML report | Devon / Maya |
| 8 | …**carve one flow or one host's traffic** to a new pcap for deeper dig | PCAP carve (flow/host) | Devon / Sam |
| 9 | …**convert / read a pcap online without uploading it** (incl. pcap→CSV) | In-browser viewer + CSV export | All + SEO catch-all |
| 10 | …**apply Suricata rules** to a capture and see matches | Rule import → RuleMatch findings | Maya / Devon |

*(Lead with #1–4 and #9 — highest intent + clearest "Wireshark makes you work for this, we do it in one click.")*

---

### 4. Activation ("aha") moment + first-session success

**The single aha:**
> **Drop a pcap → in under 10 seconds, get a ranked verdict + a one-paragraph "what happened" + copy-paste-ready ticket text — without the capture ever leaving the browser.**

Why this is the hook: it kills the measured "15 minutes per alert / minutes-vs-hours" pain; the **copy-paste ticket output is the shareable artifact** (a colleague asks "how'd you do that so fast?" → organic loop); and **no-upload** is what converts "looks cool" into "I can run this on tonight's *real* alert."

**First-session success checklist — the product must deliver ALL of these before the user closes the tab:**

- [ ] **Zero-friction entry** — analyze a pcap with **no signup, no install, anonymous**, first run.
- [ ] **Sub-10-second verdict** — ranked findings + severity visible almost immediately on a real file.
- [ ] **Plain-English "what happened"** — one paragraph a tier-1 analyst can paste into a ticket.
- [ ] **Visible privacy proof** — an explicit "nothing uploaded / runs in your browser" signal they actually notice.
- [ ] **Transparent evidence** — each finding shows *why* (evidence + MITRE link), so the verdict is trustable, not black-box.
- [ ] **A shareable artifact created** — they copy ticket text **or** export/screenshot an HTML report (this is the viral loop).

**The activation metric to instrument (the real leading indicator of a future paid seat):**

> **first pcap analyzed → verdict viewed → output copied/exported — all in one session, within the first few minutes.**

Instrument that *triad*, not "signup" and not "feature explored." If a user completes it, they are your hottest upgrade lead — fire the contextual paywall (export / 6th capture / >50 MB / AI / carve) on their very next high-intent action.

---

### 5. Anti-personas — who NOT to chase yet

| Anti-persona | Why to skip (for now) |
|---|---|
| **Enterprise NDR buyers / SOC managers via procurement** | Wrong motion entirely — that's top-down sales with security review and POCs. You're PLG, solo, $0 budget. Let analysts champion *up* instead; don't chase the buyer directly. |
| **Network engineers as a *launch* target** | Their JTBD is troubleshooting, not security; Wireshark is free and sufficient; low personal WTP. Great *expansion* later, terrible beachhead. |
| **Compliance / GRC / auditors** | Don't live in pcaps, no triage JTBD, long non-self-serve sales cycles. |
| **Pure-web bug-bounty hunters (no network/IoT work)** | pcap is irrelevant to their day — Burp-and-browser only. Chase the *network/thick-client* slice of Persona C, not all hunters. |
| **Malware reverse-engineers wanting deep sandbox detonation** | That's ANY.RUN/Joe Sandbox territory; you're pcap triage, not a detonation sandbox. Adjacent IOC value only. |
| **Free-tier-forever students as a *revenue* target** | Keep them — they're the distribution flywheel — but **do not** build monetization for them. Value is word-of-mouth + graduating into A/B/C. |
| **Anyone requiring on-prem/self-hosted enterprise deployment** | Your in-browser model already *is* the privacy answer; don't get pulled into building/selling on-prem infra pre-PMF. |

**One-line takeaway:** Win **Maya (SOC triage)** for volume and retention, monetize **Sam (pentester)** for early cash, treat **Devon (DFIR)** as the high-WTP power user, and keep **Priya (network eng)** + **students** warm as expansion and flywheel — all hung off a single, instrumented aha: *drop a pcap, get a verdict, nothing leaves the browser.*

---

I'll write the Pricing & Packaging section now. This is a synthesis task drawing on the briefs provided — no codebase exploration needed.

## Pricing & Packaging (90-day MRR plan)

**Thesis:** Keep the in-browser analyzer free and frictionless (it's the SEO/word-of-mouth engine and PacketTotal's vacant lane), gate the *professional workflow* features behind Pro at **$19/mo**, default checkout to **annual**, and front-load cash with a **capped Founder annual ($149)** — not a margin-destroying lifetime deal. The gating seam already exists in code (commit `dbde536`: AI / reputation / PCAP-carve / capture-compare are flag-gated), so this is mostly configuration, not a build.

---

### 1. Recommended tier table

| Tier | Monthly | Annual | Who | Included / Gated |
|---|---|---|---|---|
| **Free** | $0 | $0 | Students, CTF players, evaluators, the viral top-of-funnel; anonymous first-run, no signup to try | **Included:** Full client-side analysis — all ~20 behavioral detectors, severity scoring, MITRE matrix, flows/findings tables, all dashboards & viz, packet drill-down, **browser HTML report export**, JA3/JA4/HASSH fingerprints, **5 captures/mo**, **50 MB/file**, 1 saved filter + 1 saved rule set. **Gated:** AI Analyst, reputation enrichment, structured exports (STIX/CSV/MISP/CEF/Sigma), PCAP carve, file carving, multi-capture diff, Suricata rule import, unlimited captures/size. |
| **Pro** | **$19** | **$190** (2 mo free, ~17% off) | Working analysts, DFIR, pentesters/bug-bounty, indie security consultants — anyone using pcaps for billable/job work | **Everything in Free, plus:** unlimited captures, **1 GB/file**, **AI Analyst** (exec summary + NL chat), IP/domain **reputation enrichment** (AbuseIPDB/GreyNoise/VirusTotal), **all structured exports**, **PCAP flow + host carve**, **file carving (SHA256)**, **multi-capture diff**, **Suricata rule import** + unlimited saved rule sets/filters, priority email support. |
| **Pro Annual — Founder** *(launch-only, capped)* | — | **$149/yr** (first 12 mo, then renews at $190) | The first 200 believers who'll pay up front | Full Pro at a locked-in founder rate. **Hard cap: first 200 subscribers**, public counter. Pulls a full year of cash forward per buyer. |
| **Team** *(add ~day 60)* | **$39** (2 seats) | **$390** (2 seats) | 2-person consultancies, an analyst + their lead | Pro for all seats + shared rule sets / saved filters / annotations + seat management. **+$15/seat** beyond 2. Raises ARPU with **no new feature build** — just seat plumbing. |

**Why not a $9 tier now:** it cannibalizes $19 and anchors the market low. Hold it in reserve. *If* 90-day data shows price-sensitive drop-off at the paywall, introduce a **$9 "Solo"** down-sell (unlimited captures + structured exports, but **no** AI/reputation/carve) — never as the default toggle.

---

### 2. Free vs Pro — what to gate, what to protect

**Keep FREE (these are acquisition, not revenue — gating them kills the funnel):**

- [ ] The entire **core analysis loop** — upload → all ~20 detections → severity score → MITRE matrix. This is the "aha," the thing people screenshot, the SEO landing-page payload, and PacketTotal's vacant lane. Never gate it.
- [ ] **Anonymous, no-signup first run.** Signup is triggered only when a user *hits a gate*, never to try. Friction-free first run is the acquisition moat and aligns with the privacy invariant (nothing leaves the browser).
- [ ] **Browser HTML report export.** Every shared report is a free ad with your name on it. Keep it free; gate only the *machine-readable* exports (STIX/CSV/MISP/CEF/Sigma) that signal a real SOC/IR workflow.
- [ ] **Fingerprints in the UI** (JA3/JA4/HASSH/per-flow TLS) — they're differentiators that drive "how'd you do that?" word-of-mouth. Free to *see*; Pro to *export in bulk*.

**Gate to PRO (the next action a *satisfied* user wants — monetize that exact moment):**

| Pro feature | Why it's the right gate |
|---|---|
| **AI Analyst assist** | Highest perceived value + real operator cost (hosted proxy). Classic premium gate. |
| **Reputation enrichment** | Operator-funded API cost (AbuseIPDB/GreyNoise/VT) — can't be free at scale. |
| **Structured exports** (STIX/CSV/MISP/CEF/Sigma) | "Hand this off to my SIEM/team" = a working professional, not a tire-kicker. |
| **PCAP carve + file carving** | "I'm doing real IR now" — strongest signal of someone who'll expense $19. |
| **Multi-capture diff** | Only matters to repeat users — self-selects retained, high-intent accounts. |
| **Suricata rule import** | Detection-engineering workflow = a serious practitioner. |
| **Volume: captures/mo + file size** | Meters the *core loop* without gating it — a fair "you've outgrown free" moment for your most engaged users. |

**Rule:** *Never block the aha; block the next thing a happy user reaches for.* The user who just saw a `critical` finding is your hottest lead — the upgrade prompt belongs at *that* click.

---

### 3. Free → paid conversion triggers (wire these contextual paywalls)

Fire the upgrade modal at these exact in-product moments. Show the real UI **behind a soft blur** (see the value > be told about it), not a hard wall.

| # | Trigger moment | Real feature | Modal copy (template) |
|---|---|---|---|
| 1 | Click any **structured export** (STIX/CSV/MISP/CEF/Sigma) | Exports | *"Export to STIX/MISP is a Pro feature. Start your 14-day Pro trial — no card."* + blurred preview of the formatted output |
| 2 | **6th capture** in a calendar month | Capture limit | *"You've analyzed 5 captures this month. Unlimited is Pro — $19/mo, or $190/yr."* |
| 3 | Upload a **file > 50 MB** | Size limit | *"This capture is 180 MB. Free handles up to 50 MB — Pro goes to 1 GB."* (high intent: real file, not a sample) |
| 4 | Click **"Ask AI Analyst"** / **"Run reputation"** | AI / enrichment | Show the first sentence of the AI summary, blur the rest: *"Unlock the full executive summary with Pro."* |
| 5 | Click **"Carve PCAP"** / **"Carve files"** / **"Apply rules"** | Carve / rules | *"Carving and rule import are Pro — the IR toolkit. Start free trial."* |
| 6 | Click **"Compare captures"** | Multi-capture diff | *"Diff this against a previous capture with Pro."* |

**Conversion mechanic to wrap it all — the reverse trial (do this; it's the single biggest lever):**
- Every signup starts a **14-day full-Pro trial, no card**, then **auto-downgrades to Free** (never locked out, data preserved).
- This keeps the viral free tier *and* makes every new user taste the paywall features once — so the 6 prompts above land on **warm** users. Reverse trials report ~2× the paid conversion of plain freemium.
- **On expiry, use loss-aversion, not a feature list:** *"During your trial you exported 4 reports and ran AI analysis 11 times. Keep them for $19/mo."* Show what they actually used.
- Tie trial to account (one per email) to limit re-trial abuse.

**Non-paywall nudges:**
- [ ] Persistent low-key countdown banner: *"9 days of Pro left."*
- [ ] Pricing toggle **defaulted to annual** with a "2 months free" badge.
- [ ] On a high-severity free finding: *"Pro users export this straight to their SIEM."*

---

### 4. Launch monetization tactics (ranked by 90-day MRR impact)

**A. Founder annual — the highest-impact move** ⭐ *(launch day; run 30–45 days or until full)*
- **Offer:** Pro Annual **$149** (vs $190 standard, vs $228 monthly) for the **first 200 subscribers**, rate locked as long as they stay subscribed. Public counter: *"137/200 founder seats left."*
- **Math:** 200 × $149 = **$29,800 cash in 90 days** = **~$2,483 MRR-equivalent** ($29,800 ÷ 12). Even a partial 60 founders = **~$8.9K cash / ~$745 MRR-equiv**.
- **Pros:** Massive cash-forward for runway; genuine scarcity rewards your earliest evangelists; annual locks 12-month retention so churn can't touch it for a year.
- **Cons:** Front-loads revenue you "spend" against future months (watch the renewal cliff 12 mo out); the locked rate is permanent forgone margin on loyal users; over-discounting trains anchor expectations.
- **Recommendation: DO IT.** It's what makes the 90-day number hit *now* instead of in month 9. The hard cap + locked rate contain the downsides.

**B. Annual-default on every conversion** ⭐ *(week 1)*
- **Offer:** Standard annual **$190 (2 months free)**, pricing toggle defaults to annual.
- **Pros:** Industry-standard 17% discount; each sale = cash up front + 12 months locked retention; smooths bootstrapped cash flow. Annual share is the #1 predictor of survivable bootstrapped MRR.
- **Cons:** Lower nominal MRR per dollar collected (you gave up 2 months); deferred-revenue bookkeeping. Net strongly positive.
- **Recommendation: DO IT.**

**C. Reverse trial as the default funnel** ⭐ *(week 1 — the conversion engine)*
- **Pros:** ~2× plain-freemium conversion while *keeping* the viral free tier; no-card = zero acquisition friction; primes users for the §3 prompts.
- **Cons:** No card up front = lower trial→paid *rate* (offset by far more trial *starts*); re-trial abuse (mitigate: one per account).
- **Recommendation: DO IT — ship first.**

**D. Public price-increase commitment** *(announce day 60)*
- **Offer:** *"Pro goes to $24/mo on [date]. Lock in $19 now."* Real, announced, honored.
- **Pros:** Manufactures a deadline to convert fence-sitters; sets up a legitimate future ARPU bump; zero discounting.
- **Cons:** Only credible if you actually raise it (don't cry wolf); modest effect vs A/B/C.
- **Recommendation: DO IT — cheap urgency, no discount.**

**E. Lifetime / capped founder deal** ⚠️ *(default: SKIP)*
- **Offer (if runway forces it):** strictly capped LTD — **≤100 seats at $299 one-time**, on **your own channels only** (avoid AppSumo-style marketplaces — security buyers there skew bargain-hunter). 100 × $299 = **$29,900 immediate cash**.
- **Pros:** Big one-time runway injection; instant base of motivated power-users → testimonials, bug reports, word-of-mouth.
- **Cons (real):** LTD buyers are **$0 MRR forever**, run heaviest on support/infra, anchor the product "cheap," pollute LTV/retention metrics, and resent later price hikes. **An LTD is structurally an anti-MRR tactic.**
- **Recommendation: SKIP for a 90-day *MRR* goal.** The Founder **annual** (A) gives you the same cash-forward *and* keeps the relationship recurring. Only run the LTD if pure cash-now > MRR-later for your runway math — and if so, cap it ≤100 @ $299.

---

### 5. The 90-day stack (do in this order)

- [ ] **Week 1 —** Ship the **reverse trial** (C) as the default funnel.
- [ ] **Week 1 —** Default the pricing toggle to **annual $190** (B); flip Stripe **TEST → LIVE** (launch gate).
- [ ] **Weeks 1–3 —** Wire the **6 contextual paywall triggers** (§3) with soft-blur previews + loss-aversion trial-expiry copy.
- [ ] **Launch day —** Open the **Founder annual: 200 seats @ $149** (A) with a public counter; run 30–45 days or until full.
- [ ] **Day 60 —** Announce **$19 → $24** for new signups after day 90 (D) to convert stragglers.
- [ ] **Day 60 —** Add the **Team 2-seat tier @ $39** (B) once you have Pros to upsell.
- [ ] **Skip the broad LTD** (E). Only run ≤100 @ $299 on your own channel if runway demands a cash spike.

**Conservative 90-day illustration:** reverse trial converting ~3–4% of signups + 200 founder annuals (~$2.5K MRR-equiv) + steady monthly Pros → roughly **$3–4K MRR** exiting day 90. The **Founder annual is the lever that makes that land now** rather than in month 9.

> **One line:** Keep Free viral, hold Pro at **$19**, add a **reverse trial**, **default to annual**, and front-load cash with a **capped $149 Founder annual** — not a lifetime deal.

---

<a id="4"></a>

## 4. The 90-Day Go-To-Market Plan

**Goal:** maximize exit-day-90 MRR with $0 budget, solo, organic-only. **Beachhead:** SOC/blue-team triage analysts; **early monetization wedge:** freelance pentesters/DFIR who pay personal cards. **The one rule:** in every security channel the tool *is* the value — free, no signup, nothing leaves the browser — never tease, always disclose you built it.

**The MRR math you're driving toward:** ~120 paying Pros (mix monthly $19 + annual $190) + a capped Founder-annual cohort ($149 × up to 200) lands you in the **$3K–4K MRR** range exiting day 90. The Founder annual is what pulls that number into *now* instead of month 9. Every action below is ranked by its line to that number.

---

### Phase 0 — Pre-launch (Weeks -2, -1, 0)

**MRR-moving priority:** go-live gates + a warm list to harvest on launch day. Nothing else matters if Stripe is in test mode or you launch into a void.

#### Week -2 — Go-live gates (the non-negotiables)

These are blockers. A launch with broken billing or a missing paywall wastes the single hottest traffic window you will ever get.

- [ ] **Flip Stripe TEST → LIVE.** Real products/prices: Pro **$19/mo** + **$190/yr** (annual default). Run one real card end-to-end and confirm the webhook flips the account to Pro. *(Billing lives under `D:\Project\PacketPilot\ui\src\`; Phase 6 Payments admin already exists.)*
- [ ] **Stand up the Founder annual SKU:** Pro Annual **$149/yr**, locked rate, **hard cap 200 seats**. Wire a public counter ("137/200 founder seats left").
- [ ] **Wire the reverse-trial funnel:** every signup → 14-day full-Pro, **no card**, auto-downgrade to Free (don't lock out, don't delete data). Trial tied to account/email (one per email).
- [ ] **Wire the 6 contextual paywall triggers** (these are your conversion engine — feature gates already exist per commit `dbde536`):
  1. Click any structured export (STIX/CSV/MISP/CEF/Sigma) → blurred preview + "start free Pro trial"
  2. 6th capture in a calendar month
  3. File > 50 MB upload
  4. "Ask AI Analyst" / "Run reputation enrichment"
  5. "Carve PCAP" / "Carve files" / "Apply rules"
  6. Multi-capture diff
- [ ] **Set the operator secrets in /admin** so Pro features actually work: `AI_API_KEY`, `ABUSEIPDB/GREYNOISE/VIRUSTOTAL_KEY`; enable `ai_config` + `rep_config`. (Per memory: AI/rep need login + these secrets or they silently no-op.)
- [ ] **Set Vercel env vars** `VITE_SUPABASE_URL` / `VITE_SUPABASE_ANON_KEY` (deployed /admin + accounts break without them). **Rotate the temp admin password.**
- [ ] **Instrument the funnel.** Privacy-safe analytics (Plausible/Umami free tier) on the activation triad: **first pcap analyzed → verdict viewed → output copied**. UTM every outbound link. This is how you'll know what to double down on in Phase 3.
- [ ] **Re-run `npm run build:wasm` + commit** so the deployed engine isn't lagging (committed `ui/src/wasm/` is what Vercel builds).

#### Week -1 — Assets + build-in-public starts

Build the artifacts once; reuse them across every Phase-1 channel.

| Asset | Spec | Reused in |
|---|---|---|
| **60-sec demo GIF/video** | Drop malware pcap → threats light up → carve dropped EXE → export report. All offline. No narration needed. | PH, Show HN comment, X/Mastodon, newsletters |
| **Show HN first comment** | Why client-side WASM, the ~20-detector list, one honest limitation | HN |
| **PH tagline** | "Wireshark-grade PCAP triage in your browser. Nothing leaves your machine." | PH, landing `<title>` |
| **README-as-landing** | Screenshots, the privacy invariant, the detector table | HN crowd reads the repo |
| **"I built this" disclosure line** | One sentence, paste into every community post | Reddit, Discord |
| **6 SEO landing routes** | Pre-rendered, real `<title>`/meta/H1 + SoftwareApplication JSON-LD | SEO (Phase 2 compounding) |

- [ ] Ship pre-rendered Tier-1 landing routes: `/analyze-pcap-online`, `/pcap-viewer`, `/pcapng-analyzer`, `/pcap-to-csv`, `/wireshark-alternative`, `/extract-files-from-pcap`. Submit sitemap.
- [ ] **Start build-in-public** on X + Indie Hackers. Post the demo GIF: "Building a pcap analyzer that runs 100% in your browser — your packets never leave your machine. Launching in 2 weeks." Commit to 2–3 posts/week through day 90.
- [ ] **Warm a Reddit account NOW** (it needs ~2–4 weeks): get to 40–50 karma by genuinely answering in **r/AskNetsec**, `ask.wireshark.org`, Network Engineering StackExchange. First few days just comment, don't link.
- [ ] **Open the waitlist** on the landing page ("get notified about Pro + lock the founder rate"). The free tool itself is the magnet.

#### Week 0 — Soft launch + relationship-building

- [ ] **PR into awesome-lists** (evergreen backlinks + discovery): `caesar0301/awesome-pcaptools` (under Traffic Analysis), `paulveillard/cybersecurity-pcap-tools`, `meirwah/awesome-incident-response`. Add to **AlternativeTo** as a Wireshark/CloudShark alternative.
- [ ] **Soft-post the tool** in the most permissive, highest-fit channels: **r/blueteamsec** + **r/dfir** + one DFIR Discord `#tools` channel. Frame: "client-side pcap triage with 20 behavioral detectors (C2, port scan, DGA, file carving) — no upload, no signup, I built it."
- [ ] **Line up newsletter slots:** email **tl;dr sec** (Clint Gibler) and **This Week in 4n6** (Phill Moore) a 2-sentence "new free tool" note + direct link. Both explicitly feature tool releases.
- [ ] **Pre-warm PH:** cultivate a handful of active Product Hunt users (6+ mo old accounts carry vote weight) — relationships, not a launch-day cold blast.
- [ ] Confirm the **30-day post-launch conversion plan is live on day one** (trial, founder offer, upgrade prompts) — not "added later."

---

### Phase 1 — Launch week (Week 1), sequenced by day

**MRR-moving priority:** harvest the spike into the founder-annual cohort + warm emails. Optimize for **signups and paid conversions, not upvotes**. Stack channels so no single event is load-bearing. Be in every thread answering within ~15 minutes — comment velocity drives ranking on both HN and PH.

| Day | Channel | Action | Why / timing |
|---|---|---|---|
| **Mon** | Waitlist + build-in-public | Email the list + X thread: "We're live. Founder annual: $149/yr locked, first 200 only." | Warms early traffic & reviews before the big swings |
| **Tue** | **Show HN** (your #1 channel) | `Show HN: PacketPilot – Analyze pcaps in your browser, nothing leaves your machine`. Post **Tue 9am–12pm ET**. Maker's first comment immediately (why client-side, detector list, one honest limitation). | HN over-indexes on privacy-first + no-signup — your exact edge. Best $0 PR + durable SEO backlink spike |
| **Wed** | **Product Hunt** | Launch **12:01am PT**. Lead asset = the 60-sec demo video. Self-hunt + maker comment, monitor all 24h. | PH = backlinks/credibility/SEO, not core ICP. First 2h momentum sets rank |
| **Thu** | Reddit + Indie Hackers | Value posts: **r/AskNetsec** (answer-style, link only where it's the literal answer) + **r/netsec** *only if* you have a meaty technical writeup ("How we decrypt QUIC Initial client-side to extract SNI" — method, not product). IH "launch week" post. | r/netsec punishes product posts; lead with method. Never same-day cross-post identical copy |
| **Fri** | X/Mastodon + recap | Post a **finding GIF** (not "check out my tool"): "loaded a malware pcap → flagged the C2 beacon + carved the dropped EXE in one click, fully offline." Post to **both** X and infosec.exchange/ioc.exchange. Build-in-public recap thread with real numbers. | Mastodon is where serious DFIR/netsec migrated. Recap drives a second traffic wave |

**Launch-week hard rules:**
- [ ] Never ask for upvotes or share voting links (auto-flagged on HN + PH).
- [ ] No marketing-speak to a technical crowd — direct, specific, honest.
- [ ] **Founder-annual counter visible everywhere** during the spike — this is the MRR-pulling-forward mechanism. Run it 30–45 days or until full.
- [ ] Capture emails on every non-converter (free-tool report-save, "notify me about Pro"). The 95%+ who don't buy day-one are your Phase-2 nurture pipeline.
- [ ] Load-test the WASM path before Tuesday (a front-page Show HN = 5K–30K uniques/24h).

---

### Phase 2 — Weeks 2–6 (the conversion + content engine)

**MRR-moving priority:** convert the launch traffic that's still warm (reverse-trial expiries are firing now), then build the compounding long-tail SEO + community presence that produces *durable* signups after the spike dies. Going silent here resets you to zero.

#### Content / SEO engine (the compounding moat — one per week)

The unfair advantage: you ship ~20 detectors, each a near-zero-competition "how do I find X in a pcap" query. One explainer post/week, each ending "...or do it in one click in PacketPilot," each internally linked to its tool page.

| Week | Detector explainer post | Internal-links to |
|---|---|---|
| 2 | How to detect C2 beaconing in a pcap | `/analyze-pcap-online` |
| 3 | Extract files from a pcap (file carving + SHA256) | `/extract-files-from-pcap` |
| 4 | Detect a port scan in a pcap (T1046) | `/pcap-viewer` |
| 5 | Get JA3/JA4 fingerprints from a pcap | `/wireshark-alternative` |
| 6 | Find cleartext credentials in a pcap (T1552) | `/pcap-viewer` |

- [ ] Each post: H1 = the exact query, depth that out-classes the thin tutorials currently ranking, end-CTA to the matching tool page.
- [ ] When a post is genuinely technical, cross-post as a **method writeup** (not product) to r/netsec.
- [ ] Maintain the internal-link mesh: every detector post → tool page; every tool page → 2–3 sibling tool pages.

#### Community presence (ongoing, the trust layer)

- [ ] **r/AskNetsec, ask.wireshark.org, Network Engineering SE:** answer real "how do I analyze this pcap / convert to csv / find X" questions weekly. These answers rank in Google for years = compounding referral traffic. Lowest-risk, highest-trust channel.
- [ ] Share once (right channel, with disclosure) in **DFIR Discord `#tools`**, TCM Security / InfoSec Prep `#resources`. Don't spam.
- [ ] Respect the 90/10 rule everywhere (≤10% self-promo). Never cross-post identical copy same-day.

#### Conversion optimization (where MRR is actually made)

- [ ] **Reverse-trial expiry sequence with loss-aversion framing** (converts far better than feature lists): on downgrade, show exactly what they used — *"You exported 4 reports and ran AI analysis 11 times during your trial. Keep them for $19/mo."*
- [ ] **Soft paywalls, never hard walls:** render gated panels behind a blur with one inline "Unlock with Pro." Seeing value > being told about it. Never gate the core analysis loop (your viral hook).
- [ ] **Default the pricing toggle to annual** ($190, "2 months free" badge).
- [ ] **Nurture captured emails:** PQLs (already ran an analysis) get a warmer, separate sequence — they convert ~3× better than cold signups.
- [ ] Instrument it: watch the activation triad + which channel drove *paid* conversions, not just signups.

#### First outbound (founder-led selling, the monetization wedge)

- [ ] Target the **personal-card payers**: freelance DFIR/IR consultants + pentesters (the Burp-Pro pattern — they buy tools that make them money, "one engagement pays for the year").
- [ ] DM/reply into threads where people complain about Wireshark friction or ask "how do I quickly triage a pcap" — offer the tool as the literal answer, not a pitch.
- [ ] Personally onboard your first 10–20 trial users (DM: "saw you tried it — what were you triaging? anything missing?"). Their answers are your roadmap + testimonials.

---

### Phase 3 — Weeks 7–12 (double down, annual push, partnerships, referrals)

**MRR-moving priority:** ruthlessly amplify whatever channel produced *paid* conversions in Phase 2, pull more cash forward with annual, and add ARPU/distribution levers (Team tier, referrals, partnerships) that don't need new feature builds.

#### Double down on what converts (data-driven, weeks 7–8)

- [ ] **Read the attribution.** Rank channels by **paid conversions per hour of effort**, not traffic. Kill the losers. If detector posts drove signups → publish 2/week. If r/AskNetsec answers converted → 3× the cadence. If Mastodon finding-GIFs landed → daily.
- [ ] **Re-launch loop:** treat each new detector/feature as a fresh mini-launch (changelog post, a Show HN of an OSS component if any, directory re-submit). Launching is a recurring habit, not one event.

#### Annual + pricing push (the biggest MRR lever, weeks 8–10)

- [ ] **Announce the $19 → $24 price increase** for new signups after a set date. Real, honored. "Lock in $19 now." Manufactures a deadline for fence-sitters with zero discounting + sets up a future ARPU bump.
- [ ] **Final founder-annual push** before the 200 cap closes — the counter scarcity is real now. 200 × $149 = **$29,800 cash / ~$2,483 MRR-equiv**.
- [ ] **Add the Team 2-seat tier** ($39/mo, $390/yr, +$15/seat) — upsell existing Pros (2-person consultancies, an analyst + their lead). Raises ARPU with **no new feature build** (seat management + shared rule sets/filters).

#### Partnerships (distribution without budget, weeks 9–11)

- [ ] **Suricata/Sigma rule-author communities:** you already import Suricata rules + export Sigma — offer "test your rule against a pcap in-browser, free." Natural co-marketing with rule authors and detection-engineering blogs (Detection.fyi).
- [ ] **CTF / training orgs (the student feeder):** offer PacketPilot as a free network-forensics aid to TryHackMe/HackTheBox/CyberDefenders community Discords and Malware-Traffic-Analysis.net writeup authors. Students graduate into SOC/DFIR roles and carry the tool with them — pipeline, not immediate revenue.
- [ ] **Newsletter relationships → recurring:** having shipped weekly content, re-pitch tl;dr sec / This Week in 4n6 with each substantial new detector or writeup.

#### Referrals (turn happy free users into distribution, weeks 10–12)

- [ ] **Shareable-report loop:** every free HTML report is an ad — ensure it carries a subtle "Generated with PacketPilot — analyze your own pcap, nothing leaves your browser" footer + link. The copy-pasteable ticket output is the artifact that self-propagates ("how'd you triage that so fast?").
- [ ] **Founder referral perk:** give Pro users a referral link → 1 free month per converted referral (or a discount for both sides). Cheap, MRR-accretive, leverages your most-loyal cohort.
- [ ] **Testimonial harvest:** ask your earliest founder-annual buyers + onboarded trial users for a one-line quote. Put them on the landing page + pricing page (social proof lifts conversion on every channel above).

---

### 90-Day Scorecard (track weekly)

| Metric | Why it matters | Target by day 90 |
|---|---|---|
| **MRR (incl. annual ÷ 12)** | The goal | **$3K–4K** |
| **Founder-annual seats sold** | Cash pulled forward | 60–200 of 200 cap |
| **Paying Pros (monthly + annual)** | Recurring base | ~120 |
| **Trial → paid %** | Conversion engine health | 25%+ (reverse-trial blended) |
| **Activation triad completion** | Leading indicator of future paid | rising weekly |
| **Paid conversions by channel** | What to double down on | 1–2 clear winners |
| **Annual share of paid** | #1 predictor of survivable bootstrapped MRR | majority |

**Watch-outs (the things that actually kill this):** launching with Stripe in test mode; going silent after the spike (resets to zero); a Reddit launch-day blast → sitewide shadow-ban (warm the account for weeks); salesy HN title to a technical crowd; gating the core analysis loop (kills the viral hook); a broad lifetime deal (zero-MRR support load — **skip it**, the founder *annual* gives cash-forward *and* keeps the relationship recurring).

---

<a id="5"></a>

## 5. Demand Generation: SEO, Content & Community

PacketPilot's organic moat is one phrase repeated everywhere: **your packets never leave your browser.** Almost every tool ranking for these keywords uploads the capture (A-Packets even makes free results public). Every page, post, and comment below leads with client-side privacy plus auto-triage + MITRE mapping — the gap no incumbent fills. All channels are $0 and founder-led.

> **Privacy note:** Memory and the brief flag a real claim-vs-code gap (FindingKind count = 20, not "50+"). Use **"~20 behavioral detectors"** in all copy. Don't inflate. The privacy invariant and detector list are your unforgeable claims — keep them exact.

---

### 1. SEO Plan

#### 1a. Prioritized keyword/topic table

Difficulty is for a **new/low-authority domain** (Low = winnable in 1–3 mo, Med = 3–6 mo, High = needs authority+backlinks). Page type maps to what you build.

| Keyword cluster | Intent | Difficulty | Page type |
|---|---|---|---|
| `analyze pcap online`, `pcap analyzer online` | Very high (task-in-hand) | Med | Tool landing `/analyze-pcap-online` |
| `online pcap viewer`, `pcap viewer online`, `read pcap online` | High | Low–Med | Tool landing `/pcap-viewer` |
| `pcapng analyzer`, `open pcapng online` | High | Low | Tool landing `/pcapng-analyzer` |
| **`pcap analyzer no upload`, `private pcap analyzer`, `analyze pcap without uploading`** | High | **Very Low (uncontested — your exact wedge)** | Tool landing `/private-pcap-analyzer` |
| `wireshark online`, `wireshark in browser`, `wireshark alternative` | High | Med | Tool landing + comparison `/wireshark-alternative` |
| `pcap to csv`, `convert pcap to csv online`, `pcapng to csv` | Very high (converter intent) | Low–Med | Converter tool `/pcap-to-csv` |
| `pcap to json`, `extract pcap to spreadsheet` | High | Low | Converter tool `/pcap-to-json` |
| `extract files from pcap (online)` | Very high (file carving = real volume) | Low | Detector/tool `/extract-files-from-pcap` |
| `cloudshark alternative`, `a-packets alternative`, `packettotal alternative` | High (active migration) | Low | Comparison pages (one each) |
| `free pcap analyzer`, `best online pcap analyzer` | High | Med | Comparison/roundup `/best-pcap-analyzer` |
| `detect C2 / beaconing in pcap`, `find C2 in pcap` | High (specialist) | Very Low | Detector explainer + tool deep-link |
| `detect port scan in pcap`, `find port scan in capture` | High | Very Low | Detector explainer |
| `find DNS tunneling in pcap`, `detect DGA in pcap` | High | Very Low | Detector explainer |
| `extract credentials from pcap`, `cleartext passwords pcap` | High | Very Low | Detector explainer |
| `get JA3 / JA4 from pcap`, `JA3 fingerprint from pcap` | High | Very Low | Detector explainer |
| `detect ARP spoofing / SYN flood in pcap` | Medium–High | Very Low | Detector explainer |
| `extract SNI from pcap`, `find TLS server name in capture` | Medium | Very Low | Detector explainer |
| `find malware download in pcap`, `IOC extraction from pcap` | High | Low | Detector explainer |
| `HASSH SSH fingerprint from pcap`, `suspicious user-agent pcap` | Medium | Very Low | Detector explainer |
| `pcap to STIX / MISP / Sigma / CEF`, `pcap IOC export` | Medium (SOC workflow) | Very Low | Export-feature page |

**Build order:** (1) the **`/private-pcap-analyzer`** + Tier-1 task pages first — highest intent, your wedge sits in the lowest-competition lane; (2) the **converters** (`/pcap-to-csv`, `/pcap-to-json`) — weak SERP held by low-authority converter farms you beat on the "no upload" trust angle; (3) **comparison** pages (active migration demand from CloudShark/PacketTotal); (4) the **detector explainer** long-tail engine (near-zero competition, compounds weekly via the content calendar).

#### 1b. Programmatic / templated page ideas

Two repeatable templates turn ~20 detectors + 6 export formats + competitor set into ~35 indexable pages with near-zero per-page effort:

| Template | Pattern (one page per item) | Count | Targets |
|---|---|---|---|
| **Detector pages** — `/detect/{slug}` | "How to detect **{X}** in a pcap (online, no upload)" — what it is → the Wireshark manual-filter way → one-click in PacketPilot → MITRE id → sample capture link | ~20 (C2, port scan, DGA, DNS tunnel, cleartext creds, JA3/JA4, ARP spoof, SYN flood, cryptomining, exposed RDP, ICMP tunnel, suspicious UA, disguised download, malware download, weak TLS, cert health, encrypted DNS, exfil, PII, lateral movement) | "detect {X} in pcap" long-tail |
| **Comparison pages** — `/vs/{competitor}` | "PacketPilot vs **{competitor}** — private, in-browser alternative" — honest feature table, the privacy column they fail, who each is for | ~6 (Wireshark, A-Packets, CloudShark, PacketTotal, PacketSafari, NetworkMiner) | "{competitor} alternative" |
| **Converter pages** — `/{fmt}` | "Convert pcap to **{fmt}** online (client-side)" | ~4 (CSV, JSON, STIX, MISP) | "pcap to {fmt}" |

Each page: H1 = exact query, working tool/CTA above the fold, 200–400 words below, `SoftwareApplication` JSON-LD (price: 0), internal links to 2–3 siblings + matching detector post.

#### 1c. Technical SEO checklist (Vite SPA on Vercel)

- [ ] **Pre-render marketing/tool routes** — app is a Vite SPA (`main.tsx` pathname branch); Googlebot ranks server-delivered HTML faster. Each SEO route needs real `<title>`/meta/H1 in the initial response, not client-injected. Use Vercel static generation for the marketing routes only; leave `/app` as-is.
- [ ] Unique `<title>` + meta description + `<link rel=canonical>` per route.
- [ ] `SoftwareApplication` JSON-LD (offers: price 0) on every tool page → rich-result eligibility.
- [ ] `sitemap.xml` listing all landing/detector/comparison/converter routes; submit to Google + Bing Search Console.
- [ ] Internal-link mesh: every detector post → its tool page; every tool page → 2–3 siblings + 1 comparison page.
- [ ] OpenGraph image per page (a finding screenshot) — drives social CTR when shared.
- [ ] Keep `/app` crawlable but it doesn't need ranking; the landing routes carry SEO.

---

### 2. 12-Week Content Calendar

One publish/week. Each piece is **SEO + social fuel**: it targets a keyword, internally links a tool page, *and* becomes a Mastodon/X/Reddit post (screenshot/GIF of the finding). Pillar weeks (Show HN / launch) cluster the strongest assets. Effort tuned for a solo founder — detector explainers reuse one template.

| Wk | Title (working) | Type | Primary keyword | Tool page it links | Social cut |
|---|---|---|---|---|---|
| 1 | **How to analyze a pcap file online (without uploading it)** | Tutorial / pillar | analyze pcap online | `/analyze-pcap-online` | "Drop a pcap, get a verdict in 10s — nothing leaves your browser" GIF |
| 2 | **How to read a pcap without Wireshark** | Tutorial | wireshark alternative / online | `/wireshark-alternative` | Before/after: 15-min Wireshark dig vs 1 click |
| 3 | **Convert pcap to CSV online (client-side, no upload)** | Tutorial + tool | pcap to csv | `/pcap-to-csv` | "pcap → CSV in your browser, data stays local" |
| 4 | **How to detect C2 beaconing in a pcap** | Detector explainer / **pillar (Show HN week)** | detect C2 in pcap | `/detect/c2-beaconing` | Malware-traffic.net pcap → beacon + carved EXE flagged, offline GIF |
| 5 | **How to extract files from a pcap (and hash them)** | Detector explainer | extract files from pcap | `/extract-files-from-pcap` | "Carved the dropped payload + SHA256, fully in-browser" |
| 6 | **PacketPilot vs A-Packets: a private, in-browser alternative** | Comparison | a-packets alternative | `/vs/a-packets` | "Their free results are *public*. Mine never leave my machine." |
| 7 | **How to detect a port scan in a pcap** | Detector explainer | detect port scan in pcap | `/detect/port-scan` | Sunburst + port-scan finding screenshot |
| 8 | **Getting JA3/JA4 fingerprints from a pcap** | Detector explainer | JA3 fingerprint from pcap | `/detect/ja3-ja4` | Per-flow JA3/JA4 table screenshot |
| 9 | **How to find DNS tunneling & DGA in a pcap** | Detector explainer | detect DNS tunneling in pcap | `/detect/dns-tunneling` | DGA host lighting up the threat graph |
| 10 | **Finding cleartext credentials in a pcap (T1552)** | Detector explainer | extract credentials from pcap | `/detect/cleartext-creds` | Redacted cred-exposure finding card |
| 11 | **From pcap to STIX/MISP/Sigma: IOC export for SOC workflows** | Tutorial / workflow | pcap to STIX MISP | export page | "One pcap → MISP event + Sigma rules, copy-paste into your SIEM" |
| 12 | **Sample-capture walkthrough: triaging a real malware pcap end-to-end** | Sample walkthrough / **pillar** | analyze malware pcap | `/analyze-pcap-online` | Full incident-hero screenshot + recap thread |

**Reusable detector-post template** (weeks 4,5,7,8,9,10 — write once, swap the detector):
```
H1: How to detect {THREAT} in a pcap (online, no upload)
1. What {THREAT} looks like on the wire (2–3 sentences, the signature)
2. The manual way in Wireshark (the filter, why it's slow/easy to miss)
3. The one-click way: drop the pcap into PacketPilot → {finding} fires → MITRE {ID}
   [screenshot of the finding card]
4. Why this runs entirely in your browser (privacy/compliance angle)
5. Try it on a sample capture → [link to /detect/{slug} + a malware-traffic-analysis.net pcap]
CTA: analyze your own — nothing uploaded.
```

**Repurposing loop (every post):** blog post → (a) Mastodon + X finding-GIF → (b) one Reddit value-comment where someone asked "how do I find {X}" → (c) if technically meaty, an r/netsec method writeup → (d) internal link added to the matching tool page. One write-up, four distribution surfaces.

---

### 3. Community Strategy

**The universal rule for security communities:** the tool *is* the value — free, no signup, nothing leaves the browser, so you can post the working tool, not a teaser. **Always disclose authorship** ("Full disclosure: I built this"). Obey the site-wide Reddit **90/10 rule** (≤10% self-promo); build comment karma 2–3 weeks in each sub *before* your first tool post. Never cross-post the same thing to multiple subs the same day.

#### 3a. Reddit (start here — channel rules that matter)

| Sub | Size | Role | How to act |
|---|---|---|---|
| **r/blueteamsec** | ~70k | **First tool post — best fit** | Revolves around GitHub tools + detection eng. "Client-side pcap triage, ~20 behavioral detectors (C2, port scan, DGA, file carving)" is exactly its content. |
| **r/dfir** | — | First tool post | IR folks live in pcaps; lead with "evidence stays local / chain-of-custody" + file carving + IOC export. |
| **r/AskNetsec** | ~110k | **Ongoing — answer, don't post** | Search "analyze pcap", "Wireshark alternative", "tool to find X" → genuinely help, link only when it's the literal answer. Highest-trust, lowest-risk; feeds everything else. |
| **r/netsec** | ~500k | The prize — **technical writeup only** | Curated/moderated; product posts rejected. Use its Saturday self-promo thread for the tool drop; save the front page for a *method* post ("decrypting QUIC Initial client-side to extract SNI"). |
| **r/networking** | ~600k | Troubleshooting frame | Strict self-promo enforcement. Frame as "paste a pcap → top talkers / retransmits / TLS versions in-browser," **not** security. Contribute first. |
| **r/cybersecurity** | ~600k | Use sparingly | Noisy, learner-heavy; use its Self-Promo/Mentorship-Monday thread only. |
| **r/Malware, r/Pentesting** | ~90k | Niche, high-intent | Malware folks care about carving + STIX/MISP/CEF export. |

**Reddit cadence:** weeks 1–2 build karma in r/AskNetsec + answer questions; week 2–3 first tool post in **r/blueteamsec** then **r/dfir** (different days); r/netsec only once a meaty writeup exists (week 4+).

#### 3b. Discord / forums

- [ ] **DFIR Discord** (the big community-run one) — share once in `#tools`/`#network-forensics`, read pinned promo rules first.
- [ ] **TCM Security, InfoSec Prep, SANS Offensive Ops, Bishop Fox** Discords — one share each in `#tools`/`#resources`, with disclosure.
- [ ] Find live servers + their promo norms via maintained lists: `github.com/Matthew-Imaginary/Hacker_Discords`, BushidoToken's "Infosec Discord Servers", Lesley Carhart's infosec lists.
- [ ] **`ask.wireshark.org`** + **Network Engineering StackExchange** + **Stack Overflow** — answer real "how do I read this pcap / convert to csv / find X" questions. These rank in Google for *years* = compounding referral traffic.

#### 3c. X / Mastodon / HN

- **Mastodon (infosec.exchange, ioc.exchange)** — where serious DFIR/netsec migrated; high engagement. Post every finding-GIF here.
- **X/Twitter infosec** — biggest reach; post the same finding-GIFs, reply into "Wireshark is so slow / how do I triage this pcap" threads.
- **Best-performing format on both:** *not* "check out my tool" — a screenshot/GIF of a finding ("loaded a malware pcap, flagged the C2 beacon + carved the dropped EXE in one click, fully offline").
- **Hacker News — Show HN (your #1 launch event, week 4):** qualifies perfectly (try-in-browser, no signup). Title: `Show HN: PacketPilot – Analyze pcaps in your browser, nothing leaves your machine`. First comment = the why (client-side WASM, detector list, one honest limitation). Be in-thread all day; never solicit upvotes; post Tue–Thu ~9am ET.

#### 3d. Value-first tactics that work in security communities

- **Answer the question, link as the answer** — your highest-trust move (r/AskNetsec, ask.wireshark.org). Help is the content; the link is incidental.
- **Lead with method, not product** — a "how we decrypt QUIC Initial client-side" writeup earns r/netsec front page; a product pitch gets rejected.
- **Show, don't tell** — a finding-GIF that does what Wireshark makes you work for beats any description.
- **Privacy as the unforgeable hook** — "nothing leaves your machine" is the one claim competitors can't copy; it converts "looks cool" into "I'll run tonight's real alert through it."
- **Submit to awesome-lists (set-and-forget backlinks + discovery):** PR to `caesar0301/awesome-pcaptools` (Traffic Analysis), `paulveillard/cybersecurity-pcap-tools`, `meirwah/awesome-incident-response`; add to AlternativeTo as a Wireshark/CloudShark alternative.
- **Pitch tool-roundup newsletters (warmest $0 channel):** tl;dr sec (Clint Gibler) and This Week in 4n6 (Phill Moore) both feature tool releases weekly — a 2-sentence "new free, client-side pcap tool" note. Full submittable set in `TalEliyahu/awesome-security-newsletters`.

---

### 4. Lead Magnets & Growth Loops

Each turns the free tool into acquisition. All respect the privacy invariant (sample/derived data only; raw captures never server-side).

| Loop | What it is | Why it compounds | Build effort |
|---|---|---|---|
| **1. Shareable HTML report (the core loop)** | Every analysis already produces a polished HTML report (existing export). Add a footer: "Analyzed with PacketPilot — nothing left this browser" + link. | Every report an analyst pastes into a ticket/Slack/blog is a free ad seen by their team. Self-propagating: colleague asks "how'd you do that so fast?" Per the activation insight, the **copy-paste-able output is the share artifact.** | **Low** — add a branded footer/OG to the existing report export. |
| **2. Public "Is this pcap malicious?" landing tool** | The `/private-pcap-analyzer` page IS this magnet: drop a pcap → instant verdict (malicious/benign + top findings + MITRE), no signup, in-browser. | Directly answers the highest-intent search ("is this pcap malicious"), fills the dead-PacketTotal void ("PacketTotal, but private"), and is the exact thing curators/HN reward (try-in-browser, no upload). Doubles as the SEO Tier-1 page. | **Low–Med** — it's a landing route over the existing engine + clear verdict framing. |
| **3. Curated sample-capture gallery** | A `/samples` page of pre-loaded interesting captures (link to malware-traffic-analysis.net pcaps + a "Load this sample" button → instant analysis). Each sample = the walkthrough in Week 12. | SEO long-tail ("{malware} pcap analysis"), gives social posts a one-click "try it yourself" link, and lets evaluators feel value with zero file of their own — the friction-free first run that converts. Feeds every detector post's step 5. | **Low** — static gallery + `loadSample` (opt-in, already exists; no recordRecent). |

**Email-capture seam for launch (ties to MRR):** none of the above requires signup (protects virality), but add **one** non-blocking capture — "Save/email this report" or "Notify me about Pro" — on the report export and the verdict screen. This builds the launch list the playbook needs without gating the aha. The user who just saw a critical finding is your hottest lead; capture the email there, nurture toward the founder/trial offer.

---

**The one rule across all four sections:** in every channel the tool *is* the value — free, no signup, **nothing leaves the browser** — so deliver it, never tease it, and always disclose you built it. Privacy + auto-triage + MITRE is the lane no competitor occupies; say it everywhere, exactly, without inflating the detector count.

---

<a id="6"></a>

## 6. Self-Serve Funnel, Activation & Retention

The whole funnel is engineered around one truth: PacketPilot's anonymous, no-upload, no-signup tool means **value is delivered before identity is captured**. That inverts the usual funnel — most users will hit their "aha" as anonymous visitors. The job is to convert that proven value into an email, then a paid seat, without ever adding friction to the core loop.

### The funnel at a glance

| Stage | Definition | Key metric | Target (90-day) | Main leak | The fix |
|---|---|---|---|---|---|
| **Visit** | Lands on `/` or an SEO tool route | Visit→Try rate | 35–50% | Bounce: "is this another upload tool / a viewer?" | Above-fold drag-drop + "Nothing leaves your browser. No signup." badge; "Load a sample capture" button for the curious-but-fileless |
| **Try** (anon) | Analyzes a capture, sees findings | Try→Activate rate | 40–60% | Drops a small/quiet pcap, sees no findings, leaves unconvinced | Default to a *loud* sample pcap; always show the dashboard (protocol mix, top talkers, flows) even on a clean capture so the tool never feels empty |
| **Signup** | Creates an account / starts reverse trial | Activate→Signup rate | 20–35% | No reason to sign up — the tool already worked anonymously | Tie signup to *keeping* value: "Save this report," "Start free Pro trial to export," not a generic wall |
| **Activate** | Completes the core value loop (see below) | % of signups activated | 60%+ | Signed up at a gate, never re-ran on a real capture | Onboarding routes straight back to "analyze your capture," not a settings tour |
| **Pay** | Converts to Pro (monthly/annual/founder) | Trial→paid / Free→paid | 25%+ trial / 3–4% free | Trial expires, value forgotten | Loss-aversion expiry: "You exported 4 reports + ran AI 11× during your trial. Keep them — $19/mo" |
| **Retain** | Stays subscribed M2+ | Logo + revenue churn | <5% monthly | Bursty usage (incident over → app idle) | Habit + lifecycle email + annual lock-in; re-engage on cadence, not just at renewal |
| **Refer / Expand** | Brings a colleague / team upgrades | Referral signups; seat expansion | — | Solo love never travels to the team | Shareable HTML report w/ footer attribution; "invite your lead" + Team tier; light human touch on multi-seat intent |

### Activation — defined precisely

Activation is **not** signup and **not** "explored a feature." It is the value triad, completed in one session:

> **Activated = (1) analyzed a real capture → (2) viewed at least one finding or the triage dashboard → (3) took an output action (copied a finding, exported a report, or carved/drilled into a flow).**

- **Anonymous activation** (the leading indicator of everything): the triad above, no account required. Instrument it client-side. This is your true top-of-funnel health metric.
- **Account activation** (the leading indicator of *paid*): a signed-up user completes the triad on **their own** capture (not the sample) within the first session. This is the number to optimize for conversion.
- **The "magic" window:** target the full triad inside the first **3 minutes** and first session. Users who export or copy an output in session one are your paid pipeline; users who only view findings and leave are not yet activated — that's the gap onboarding must close.

Instrument these four events minimum: `capture_analyzed`, `finding_viewed`, `output_action` (copy/export/carve/drilldown), `paywall_hit {trigger}`. The funnel is unmanageable without them — wire analytics before launch.

---

### Onboarding / first-run

The product already nails the hardest part: zero-install, zero-signup, instant value. First-run's only job is to guarantee the user reaches the value triad fast — even with no file of their own.

**First-run checklist:**
- [ ] **Loud sample is one click.** "Load a sample capture" runs a deliberately eventful pcap (C2 beacon, a port scan, a cleartext cred, a carvable file) so the very first screen shows critical findings + the MITRE matrix lit up — never a clean, boring capture.
- [ ] **Drop zone is the hero.** Above-fold drag-drop with the trust line baked in: *"Drag a .pcap here. Analysis runs in your browser — your capture never leaves your machine. No signup."*
- [ ] **First-finding spotlight.** On first analysis, briefly highlight the top finding + a one-line "what this means" + the copy-to-ticket button — point the user at the output action, not the feature menu.
- [ ] **Soft, dismissible tour (≤3 steps), not a wall:** Findings → Export → AI Analyst. No modal gauntlet before the user has seen their own results.
- [ ] **No signup until a gate.** Identity is requested only when the user reaches for something worth keeping (export, AI, carve, 6th capture, >50MB). Never gate the first analysis.
- [ ] **Reverse-trial primed at signup.** The moment they sign up at a gate, full Pro unlocks for 14 days (no card) — they should immediately *get* the thing they signed up for, then keep tasting Pro.
- [ ] **Returning-user state = re-entry, not a dashboard.** Workspace Overview surfaces a prominent "Analyze a capture" CTA + recent activity, so the habit loop restarts in one click.

---

### In-app upgrade prompts & paywall placement

**Principle: never block the aha; block the *next action a satisfied user wants to take*.** The user who just saw a critical finding is the hottest lead in the app — monetize that exact moment, softly.

| # | Trigger (the moment) | Why it converts | Prompt copy | Placement |
|---|---|---|---|---|
| 1 | Click any structured export (STIX / CSV / MISP / CEF / Sigma) | Highest intent — they found something and want to act/hand off | "Export to STIX/MISP is Pro. Start your free 14-day Pro trial — no card." | Modal over a **blurred preview** of the real formatted output |
| 2 | 6th capture in a calendar month | Catches your most *engaged* free users (already habituated) | "You've analyzed 5 captures this month. Go unlimited with Pro." | Inline banner on upload |
| 3 | Upload > 50 MB | They have a *real* capture, not a sample | "This capture is 180 MB. Free covers 50 MB — Pro handles up to 1 GB." | Upload dialog |
| 4 | Click "Ask AI Analyst" / "Run reputation enrichment" | Highest perceived-value features | Blur the AI summary, show the first sentence, gate the rest | In-panel soft blur + inline "Unlock with Pro" |
| 5 | Click "Carve PCAP" / "Carve files" / "Apply rules" | "I'm doing real IR work" — strongest professional signal | "PCAP carving is Pro — for when triage becomes a real investigation." | Inline on the action button |
| 6 | Multi-capture diff / compare | Self-selects retained, repeat users | "Compare captures over time with Pro." | Inline in the compare view |

**Paywall design rules:**
- Soft blur over the *real* UI/output, never a hard wall or an empty page — seeing the value beats being told about it.
- Every paywall offers the **trial first** (no card), not an immediate price ask.
- One persistent, low-key **reverse-trial countdown** ("9 days of Pro left") — never a nag.
- On expiry: **downgrade gracefully (keep their data)** and show a usage-based loss-aversion recap of exactly which Pro features they used.
- Protect virality — **never** gate: the core analysis loop, all ~20 finding kinds, the dashboards, or the browser HTML report (every shared report is an ad).

---

### Lifecycle email sequence

Email is the only channel that re-engages the 95%+ who don't pay on day one — and the only way to reach an anonymous user is to earn the address at a value moment ("save your report," "start trial"). Keep it founder-voiced, plain-text, one CTA each.

| # | Email | Trigger / timing | Purpose | Core message + CTA |
|---|---|---|---|---|
| 1 | **Welcome** | Immediately on signup | Confirm value, set the privacy frame, point back to the loop | "You're in. Reminder: your captures never leave your browser. Here's the 60-second path to your first triage report." → *Analyze a capture* |
| 2 | **Activation nudge** | 24–48h if **no own-capture analysis** | Close the activation gap for signups who haven't run a real file | "Got a real capture? Drop it in — findings, MITRE mapping, and a copy-paste ticket summary in seconds." → *Open PacketPilot* |
| 3 | **Feature/value education** | Day 3–4, during trial | Drive trial users to the Pro features that create lock-in | "Your trial unlocks the SOC workflow: STIX/MISP export, AI Analyst, PCAP carving. Here's a 90-sec tour." → *Try an export* |
| 4 | **Upgrade (trial → paid)** | Day 11–12 (≈2–3 days pre-expiry) | Convert with loss-aversion, not feature lists | "Your Pro trial ends Thursday. You ran AI analysis 11× and exported 4 reports — keep them for $19/mo (or $149/yr founder rate)." → *Keep Pro* |
| 5 | **Trial-expired down-sell** | Day 1 post-expiry | Catch the not-yet-ready; reassure data is safe | "Your trial ended — your captures and reports are still here. Founder annual is $149 (first 200 only). [counter] left." → *Lock founder rate* |
| 6 | **Win-back** | 21–30 days inactive (free or churned) | Reactivate with new value, not a discount beg | "New since you left: [detector / export / feature]. Got a capture to triage? One click, nothing uploaded." → *Come back* |
| 7 | **Engaged-free → paid** | On hitting a usage ceiling (5 captures / repeated gate) | Convert the habituated free user | "You've triaged 5 captures this month — you're clearly using this for real work. Pro is unlimited + exports + AI for $19." → *Upgrade* |

**Email rules:** one CTA per email; founder name in the From; no-reply forbidden (replies are your best customer-dev channel and a "light human touch" opening); suppress upgrade emails for users already paid; gate-hit and trial-state emails are behavioral (highest-converting), not just scheduled.

---

### Churn & retention levers

The structural retention risk for this ICP is **bursty usage**: an analyst hammers it during an incident, then the app goes quiet until the next one. Levers, by impact:

| Lever | Mechanism | Why it works for this ICP |
|---|---|---|
| **Annual + founder lock-in** | Default the pricing toggle to annual ($190, 2 mo free); founder annual $149 (first 200) | Removes the monthly churn decision entirely for 12 months; pulls cash forward — the #1 bootstrapped-MRR stabilizer |
| **Graceful downgrade, never delete** | Trial/sub end → drop to Free, keep saved filters, rule sets, annotations, reports | Their accumulated config is the switching cost; deleting it forfeits all re-conversion |
| **Behavioral re-engagement** | Win-back + new-feature emails on inactivity cadence, not just at renewal | Bridges the quiet gaps between incidents so the habit (and subscription) survives |
| **Ship + announce detectors as mini-launches** | Each new detector/export = changelog email + in-app "new" badge | Continuous visible progress is the strongest "this tool is alive, worth keeping" signal |
| **Sticky workspace artifacts** | Saved rule sets, filter profiles, per-host triage annotations, multi-capture diff history | Each saved object deepens lock-in; diff/annotations specifically reward *repeat* use |
| **Pre-renewal annual check-in** | Personal founder email ~2 weeks before annual renewal | Annual cohorts churn at the 12-month cliff — a human touch pre-empts it |
| **Reply-driven save** | Every lifecycle email is reply-enabled; founder personally answers churn/cancel replies | At this scale, one founder reply can save a seat *and* surface the real churn reason |

---

### Objections table

| Objection | Response |
|---|---|
| **"Privacy — I can't send capture data to a SaaS."** | You don't. Analysis runs **entirely in your browser** via a Rust→WebAssembly engine — the capture never leaves your machine, works offline, and needs no signup to run. Only an *optional, opt-in* derived summary + public IPs transit the backend for AI/reputation enrichment, and only if you turn it on. It's the air-gap/compliance story competitors charge for on-prem to deliver — by default. |
| **"Wireshark is free and does more."** | And it always will — Wireshark is the substrate we hand off to (carve a flow/host back out to a pcap anytime). The difference is *time*: Wireshark gives you a packet list to interpret; PacketPilot gives you the **verdict** — ranked findings, severity scoring, MITRE ATT&CK mapping, and a copy-paste ticket summary in seconds, not the 15 minutes of manual filtering per alert. We triage *for* you, then hand off to Wireshark for deep dives. |
| **"Why should I trust a new tool / unknown vendor?"** | The detectors are **deterministic and transparent** — every finding shows its evidence and a score waterfall, not a black-box verdict. Nothing's uploaded, so there's nothing to breach. Try it anonymously on a capture you already understand and check our work — no account, no risk. |
| **"How accurate is the auto-detection?"** | Detections are **behavioral and MITRE-mapped** (T1110, T1046, T1496, T1105…), each with transparent evidence and severity scoring you can audit — plus IP/domain reputation (AbuseIPDB / GreyNoise / VirusTotal) and Suricata rule import to apply your own/community rules. It's first-pass triage to cut the queue, with full drill-down to verify — not a magic oracle replacing the analyst. |
| **"$19/mo — why not just use the free stuff?"** | If you analyze a capture or two a month, the free tier is genuinely yours forever. Pro is for people doing this as *work*: unlimited captures, 1 GB files, AI Analyst, all SOC exports (STIX/MISP/CEF/Sigma), PCAP carving, multi-capture diff. For a working analyst it pays for itself the first time it saves an afternoon — and the founder annual is $149/yr (first 200). |

---

### Where a light human touch converts teams later

Self-serve PLG lands the *individual*. Teams are won with a small, well-timed human nudge — the founder personally, at exactly these signals:

- **Multi-seat / team intent:** several signups from the **same email domain**, or a "do you have team pricing?" reply → personal founder email: "Saw a few folks from [company] using PacketPilot — happy to set up shared rule sets + seats. 15 min?"
- **Power-user / champion:** a free or Pro user who exports heavily or analyzes many captures → "You're clearly running this for real work — want me to help your team standardize on it?" The heavy individual user is the team champion.
- **Annual renewal & cancel replies:** founder answers personally — saves the seat and surfaces the real reason.
- **Post-launch inbound:** every lifecycle email is reply-enabled; a single founder reply to a high-intent question routinely converts a fence-sitter and is the seed of the eventual Team upsell.

Keep it scrappy: no sales team, just the founder watching for **same-domain clusters + heavy usage** and sending a short, human, no-pressure note. That is the entire "sales motion" until Team revenue justifies more.

---

<a id="7"></a>

## 7. Sales & Launch Collateral Kit (copy-ready)

> **How to use this kit:** Everything below is final copy — paste verbatim. Square brackets `[ ]` mark the only fields you fill in (dates, counts, links). Default live URL: `https://packet-pilot.vercel.app`. One non-negotiable before any of this ships: **flip Stripe to live mode** and wire the Founder annual offer (first 200 @ $149/yr), or every CTA below sends traffic to a dead checkout.

---

### 1. Homepage hero

**Headline:**
> Triage a packet capture in seconds — without it ever leaving your browser.

**Subhead:**
> PacketPilot is a browser-based PCAP analyzer that auto-detects threats, scores the incident, and maps findings to MITRE ATT&CK — then hands you an analyst-grade report. The capture is parsed locally by a Rust→WebAssembly engine. Nothing is uploaded. No install, no signup to start.

**3 benefit bullets:**
- **Nothing leaves your machine.** The engine runs client-side in WebAssembly — your capture is never uploaded to a server. The kind of privacy regulated teams normally pay for on-prem, by default.
- **A verdict, not a packet list.** Drop a `.pcap`/`.pcapng`/`.cap`/`.gz` and get ranked findings, severity scoring, and MITRE ATT&CK mapping across ~20 behavioral detectors — C2 beaconing, port scans, cleartext creds, file carving, DGA, and more.
- **Built for SOC/IR handoff.** Export the result as an HTML report, STIX 2.1, MISP, CEF, CSV, or Sigma rules. Carve a flow or a host to a fresh pcap. Import Suricata rules.

**Primary CTA:**
> Analyze a capture — free, no signup

**Secondary CTA (link below button):**
> Don't have one handy? Load a sample capture →

---

### 2. Pitches

**One-line pitch:**
> PacketPilot is a browser-based PCAP analyzer that auto-triages captures into ranked, MITRE-mapped threat findings — with the packets never leaving your machine.

**50-word elevator pitch:**
> Wireshark shows you packets; PacketPilot tells you what's wrong. Drop a capture in your browser and a Rust-to-WebAssembly engine triages it locally — ~20 behavioral detectors, severity scoring, MITRE ATT&CK mapping, analyst-grade exports (STIX, MISP, Sigma). Nothing is uploaded. It's the private, instant triage layer that sits between tcpdump and an expensive NDR.

---

### 3. Product Hunt launch post

**Tagline (60 char max):**
> Browser-based PCAP triage. Your packets never leave your machine.

**Description:**
> PacketPilot turns a raw packet capture into a triaged incident — in your browser, with nothing uploaded.
>
> Drop a `.pcap`, `.pcapng`, `.cap`, or `.gz` and a Rust→WebAssembly engine analyzes it locally on your machine. You get:
>
> • ~20 behavioral detectors mapped to MITRE ATT&CK — C2 beaconing, port scans, brute force, lateral movement, cleartext creds, PII exposure, DGA, cryptomining, ARP spoof, SYN flood, malware download with SHA-256 file carving, and more
> • Severity-scored findings + an incident overview, threat-relationship graph, protocol sunburst, and a findings triage table
> • Fingerprinting: JA3/JA4/JA4-Q (incl. QUIC/HTTP3), JA3S, HASSH
> • Optional enrichment (opt-in, login): IP/domain reputation via AbuseIPDB, GreyNoise, VirusTotal + an AI analyst summary — over a derived summary only, never your raw packets
> • SOC/IR-ready exports: HTML report, STIX 2.1, MISP, CEF, CSV, Sigma rules + PCAP carving
> • Suricata rule import, multi-capture diff, saved filters, per-host triage notes
>
> The whole analysis runs client-side. No upload, no install, no signup to try. It's the private alternative to cloud uploaders — and the auto-triage layer Wireshark never had.
>
> Free to use. Pro ($19/mo) unlocks unlimited captures, larger files, exports, carving, AI assist, and reputation enrichment. Founder pricing for early adopters — link in the comments.

**First comment (maker):**
> Maker here. I built PacketPilot because the two things I wanted in a pcap tool never came together: **instant + private**.
>
> The web tools (A-Packets, CloudShark, the new AI ones) are fast but they upload your capture to someone else's server — and on some free tiers your results are even public. The private tools (Wireshark, NetworkMiner, Brim) never upload, but they're desktop installs and they hand you a packet list, not a verdict.
>
> So PacketPilot runs the entire analysis engine in your browser via Rust compiled to WebAssembly. The capture is parsed on your machine and never leaves it. The only thing that can ever touch the backend is an optional, opt-in derived summary (plus public IPs) if you turn on reputation/AI enrichment — your raw packets never do, by design.
>
> On top of that it does what Wireshark makes you do by hand: ~20 behavioral detectors, severity scoring, and a MITRE ATT&CK matrix, then exports straight into SOC/IR workflows (STIX/MISP/CEF/Sigma) or carves a flow back out to a pcap.
>
> One honest limitation: it's behavioral/heuristic triage, not a replacement for deep manual dissection — the workflow I intend is "PacketPilot triages it in one click, then you pivot to Wireshark on the flows that matter." It's also early: solo-built, and I'd genuinely love your teardown.
>
> Try it with no signup: https://packet-pilot.vercel.app — happy to answer anything technical in here all day.

---

### 4. Show HN

**Title:**
> Show HN: PacketPilot – Browser-based PCAP triage, packets never leave your machine

**Post body (first comment):**
> Hi HN. PacketPilot analyzes packet captures entirely in the browser — the capture is parsed by a Rust→WebAssembly engine on your own machine and is never uploaded.
>
> Why I built it: every instant "analyze pcap online" tool (A-Packets, CloudShark, the newer AI ones) uploads your capture to a server, and on some free tiers the results are public. The tools that never upload (Wireshark, NetworkMiner, Brim) are desktop installs that hand you a packet list, not a verdict. I wanted both — web-instant and local-private — so the engine ships as WASM and runs client-side.
>
> What it does beyond viewing: drop a .pcap/.pcapng/.cap/.gz and it runs ~20 behavioral detectors (C2 beaconing, port scan, brute force, lateral movement, cleartext creds, PII exposure, DGA, cryptomining/Stratum, ARP spoof, SYN flood, ICMP tunneling, disguised + malware downloads with SHA-256 file carving, weak/deprecated TLS, encrypted DNS), scores severity, and maps findings to MITRE ATT&CK. It does JA3/JA4/JA4-Q (incl. QUIC Initial), JA3S, and HASSH fingerprinting, plus Suricata rule import. Output exports to HTML/STIX/MISP/CEF/CSV/Sigma, and it can carve a flow or a host back out to a new pcap.
>
> On privacy specifically: the only data that can reach the backend is an optional, opt-in derived summary plus public IPs, and only if you enable reputation (AbuseIPDB/GreyNoise/VirusTotal) or the AI summary. Raw packets never transit the backend under any path. The app works fully offline/anonymous; there's a Tauri desktop build for a fully local-first path too.
>
> Stack: Rust core compiled to WASM, React SPA, deployed on Vercel. QUIC v1 Initial decryption and the fingerprint hashes are hand-rolled/vendored so the engine stays dependency-light and C-free for WASM.
>
> Honest limitations: it's heuristic behavioral triage, not a substitute for deep manual dissection — the intended flow is "triage in one click, then pivot to Wireshark on the flows that matter." Detectors target common LAN/host patterns; I'd love adversarial pcaps that break them. Solo-built and early.
>
> Try it with no signup: https://packet-pilot.vercel.app — feedback and teardowns very welcome.

---

### 5. Value-first community post (r/blueteamsec / r/dfir style)

> **Title:** I built a client-side PCAP triage tool (nothing uploaded) — 20 MITRE-mapped detectors, would love a teardown
>
> Full disclosure up front: I built this, it's a commercial product with a free tier, and I'm posting because I think the privacy model is genuinely relevant here — not to spam. Mods, remove if it's not a fit.
>
> The itch I was scratching: when an alert hands me a pcap, my options were (a) upload it to a web analyzer and hope nothing sensitive is in it, or (b) open Wireshark and start grinding through it by hand. I wanted the speed of (a) with the data-handling of (b).
>
> So the analysis engine is compiled to WebAssembly and runs **in the browser** — the capture is parsed on your machine and never uploaded. The only thing that can ever hit the backend is an optional, opt-in derived summary (+ public IPs) if you turn on reputation or the AI summary; raw packets never do. Works offline/anonymous, no signup to try.
>
> What it actually does (the part I'd want feedback on):
> - ~20 behavioral detectors, severity-scored and mapped to MITRE ATT&CK: C2 beaconing, port scan (T1046), brute force (T1110), lateral movement, cleartext creds (T1552), PII exposure (T1040), DGA (T1568.002), cryptomining/Stratum (T1496), ARP spoof (T1557.002), SYN flood (T1499.001), ICMP tunneling, exposed remote access (T1133), disguised + malware downloads with SHA-256 file carving (T1105, T1036), weak/deprecated TLS
> - Fingerprinting: JA3/JA4/JA4-Q (incl. QUIC/HTTP3 Initial), JA3S, HASSH (client + server)
> - Suricata rule import → RuleMatch findings
> - Exports into real workflows: HTML report, STIX 2.1, MISP, CEF, Sigma, CSV — plus PCAP carving (pull one flow or one host's traffic to a fresh pcap)
>
> What I'm specifically asking: throw a capture you know the answer to at it and tell me where the detectors are wrong — false positives, missed obvious things, scoring that doesn't match your mental model. Adversarial pcaps especially welcome.
>
> Link (no signup, runs locally): https://packet-pilot.vercel.app
>
> Not trying to replace Wireshark — the workflow I'm going for is "triage in one click, then pivot to Wireshark on the flows that matter." Happy to go deep on the detector logic in the comments.

---

### 6. Cold DM / email templates

**Template A — short DM (Mastodon / X / Discord, to a practitioner):**

> Subject (if email): a private, in-browser pcap triage tool — would value your eye
>
> Hi [name] — saw your [post/writeup on pcap triage / the Wireshark-is-slow thread]. I built a thing you might have an opinion on.
>
> It's a pcap analyzer that runs **entirely in your browser** (Rust→WASM) — the capture never leaves your machine, no upload, no signup. It auto-triages into MITRE-mapped findings (C2, port scan, file carving, etc.) and exports to STIX/MISP/Sigma.
>
> Not selling you anything — I'd just genuinely value 10 minutes of "here's where it's wrong" from someone who does this for real: https://packet-pilot.vercel.app
>
> Either way, thanks for the [post] — it was useful.

**Template B — slightly longer email (to a DFIR/SOC practitioner or blogger):**

> Subject: in-browser pcap triage (nothing uploaded) — feedback from a real analyst?
>
> Hi [name],
>
> I follow your work on [specific thing — a blog post, a tool, a talk], so you're exactly the person whose opinion I want before I push this harder.
>
> I built PacketPilot — a PCAP analyzer that runs the whole engine client-side in WebAssembly. You drop a `.pcap`/`.pcapng` in the browser and it triages it locally: ~20 behavioral detectors (C2 beaconing, port scan, cleartext creds, DGA, malware download + SHA-256 file carving…), severity scoring, and a MITRE ATT&CK mapping — then exports to HTML/STIX/MISP/CEF/Sigma or carves a flow back to a pcap. The capture is never uploaded; the only thing that can reach the backend is an optional opt-in derived summary if you enable reputation/AI enrichment.
>
> The reason I'm reaching out specifically to you: I want to know where the detectors break on real captures, and whether the "private by default, runs in the browser" model actually changes whether you'd reach for it during an incident.
>
> No ask beyond your honest reaction — it's free and needs no signup: https://packet-pilot.vercel.app
>
> If it's useful, I'd also be glad to give you a Pro account, no strings.
>
> Thanks either way,
> [Your name]

---

### 7. 60-second demo / Loom script

| Time | On screen | Say (verbatim) |
|---|---|---|
| 0:00–0:08 | Landing page, then drag a pcap onto it | "This is PacketPilot. I'm going to drop a packet capture into my browser — and watch the network tab: nothing gets uploaded. The whole engine is Rust compiled to WebAssembly, so the capture is analyzed right here on my machine." |
| 0:08–0:20 | Analysis completes, dashboard/incident overview appears | "A second later, I don't get a packet list — I get a verdict. Here's the incident overview: ranked findings, severity-scored, with the highest-risk stuff up top." |
| 0:20–0:32 | Open the Findings table + MITRE ATT&CK matrix | "Every finding is mapped to MITRE ATT&CK. Here it's flagged C2 beaconing, a port scan, and cleartext credentials — each one links to the technique and shows the evidence behind the score. No manual filtering." |
| 0:32–0:42 | Click into a finding → file carving / SHA-256 | "It carved the file that was downloaded over HTTP and hashed it — there's the SHA-256, ready to drop into your IOC workflow." |
| 0:42–0:52 | Open Export menu, show STIX/MISP/CEF/Sigma + PCAP carve | "When I'm done, I export straight into the tools I already use — STIX, MISP, CEF, Sigma rules, or a clean HTML report — or carve just this flow back out to a new pcap." |
| 0:52–1:00 | Back to landing page / URL on screen | "Instant, MITRE-mapped triage — and the capture never left my browser. It's free to try, no signup, at packet-pilot.vercel.app." |

> **Recording notes:** Use a real-but-safe capture (a CTF/malware-traffic-analysis sample). Keep the browser dev-tools Network panel visible during 0:00–0:08 — the "nothing uploaded" proof is the most persuasive 8 seconds in the video. No talking-head, no intro card; start on the drop.

---

### 8. Comparison-page angles

**Angle A — PacketPilot vs Wireshark** (frame as complement, never "better than"; security folks revere Wireshark):

> **Headline:** PacketPilot vs Wireshark: triage first, then dissect
>
> **The honest positioning:** Wireshark is the gold standard for deep, manual packet dissection — 3,000+ protocols, and nothing replaces it when you need to read the wire byte by byte. But it doesn't tell you *what's wrong*: there's no auto-triage, no severity scoring, no MITRE ATT&CK rollup. You bring the expertise and the time. PacketPilot is the layer in front of it: drop a capture, get ranked MITRE-mapped findings in seconds, then **carve the flows that matter and pivot to Wireshark** on just those. One triages, one dissects.

| | Wireshark | PacketPilot |
|---|---|---|
| Core job | Manual deep dissection | Automated triage + verdict |
| Threat findings / severity | None (manual) | ~20 behavioral detectors, scored |
| MITRE ATT&CK mapping | No | Yes, per-finding |
| Setup | Desktop install | Browser, zero install |
| Data handling | Local (never leaves) | Local — runs in-browser, never uploaded |
| SOC/IR exports | PCAP / packet detail | HTML, STIX, MISP, CEF, Sigma, CSV |
| Best at | Reading the wire | Knowing where to look first |

> **The line:** *Wireshark shows you packets. PacketPilot tells you what's wrong — then hands the right flows back to Wireshark.*

**Angle B — PacketPilot vs cloud uploaders** (A-Packets / CloudShark / cloud AI analyzers — lead with the trust/compliance wedge):

> **Headline:** PacketPilot vs cloud PCAP analyzers: same speed, your data stays put
>
> **The honest positioning:** Online analyzers like A-Packets and CloudShark are fast and convenient — but they work by **uploading your capture to their servers**, and on some free tiers your results are publicly accessible. A packet capture is some of the most sensitive data you handle: internal IPs, hostnames, credentials, payloads. For regulated or air-gapped teams, "it leaves the boundary" is a non-starter — which is exactly why those vendors sell pricey on-prem editions. PacketPilot gives you the convenience of a web tool with the data-handling of a local one: the engine is WebAssembly and runs **in your browser**, so the capture never leaves your machine — on-prem-grade privacy with zero deployment, by default.

| | Cloud uploaders (A-Packets / CloudShark / cloud AI) | PacketPilot |
|---|---|---|
| Where your capture goes | Uploaded to their servers | Stays in your browser — never uploaded |
| Results privacy | Public on some free tiers | Always private; runs on your machine |
| Auto-triage + severity | Pattern hints / viewer-led | ~20 detectors, scored, MITRE-mapped |
| Compliance / air-gap story | Buy the on-prem edition | Default — no backend touches the capture |
| Setup / cost to start | Account / upload | Zero install, no signup, free to try |
| What touches the backend | The full capture | Only an opt-in derived summary, if you enable enrichment |

> **The line:** *Every other instant pcap tool uploads your packets. PacketPilot is the one that doesn't.*

---

### Pre-flight checklist (do these before sending traffic to any CTA above)

- [ ] **Flip Stripe from TEST → LIVE** — the launch gate. Every CTA is dead without it.
- [ ] **Stand up the Founder annual offer** ($149/yr, first 200) with a visible counter, so launch-day traffic converts to cash-forward MRR instead of $19 monthlies.
- [ ] **Wire the reverse-trial** (14-day Pro, no card → auto-downgrade to Free) so launch visitors taste the gated features once.
- [ ] **Confirm "Load a sample capture"** works for visitors with no pcap on hand (hero secondary CTA depends on it).
- [ ] **Verify "no signup to try"** is actually true on the live URL — it's the load-bearing claim in every channel.
- [ ] **Cut the 60-sec demo video** (script in §7) — required asset for both Product Hunt and the X/Mastodon finding-GIF posts.
- [ ] **Load-test the WASM path** on a large capture — a front-page Show HN can bring 5k–30k visitors in 24h.
- [ ] **Decide the one honest limitation line** you'll repeat everywhere ("heuristic triage, then pivot to Wireshark") — consistency reads as credibility to this crowd.

---

<a id="8"></a>

## 8. Metrics, Financial Model & Launch-Readiness Checklist

### 1. North-Star Metric + 90-Day Funnel KPI Dashboard

**NORTH STAR: Weekly Captures Analyzed by Activated Users** — the count of pcaps successfully analyzed-to-verdict per week by users who've completed the activation triad (analyzed → verdict viewed → output/export used). It is the one metric that simultaneously proves *value delivered* (the core loop ran), *habit* (weekly recurrence), and *monetization readiness* (activated, recurring users are the paid pool). Revenue (MRR) is the *goal*; this is the *leading indicator* that predicts it.

> Why not "signups" or "MRR" as the North Star: signups are vanity (the product works anonymously, so a signup that never analyzes is noise); MRR is a lagging output you can't steer directly day-to-day. Captures-by-activated-users is the upstream lever that, when it climbs, drags MRR with it.

**Funnel KPI dashboard** — instrument every row from day one (these are the only numbers you check daily):

| Metric | Definition | 90-Day Target (exit) |
|---|---|---|
| **NORTH STAR — Weekly captures by activated users** | Pcaps analyzed-to-verdict/week by users who hit the activation triad | **400 / wk** |
| Weekly unique visitors | Distinct visitors to `/` + tool routes (launch spikes + organic) | 3,000 / wk steady (launch wk 15–30k) |
| First-capture rate | % of visitors who analyze ≥1 pcap (the anonymous core loop) | 25% of visitors |
| **Activation rate** | % of first-capture users who complete triad (analyze → verdict viewed → output copied/exported) in session 1 | **40%** of first-capture |
| Signup rate | % of visitors who create an account (only happens at a gate) | 8% of visitors |
| Trial start rate | % of signups who start the 14-day reverse-trial (auto = ~100%) | 95%+ of signups |
| **Trial → paid** | % of reverse-trials that convert to a paid plan | **6%** (no-card reverse-trial; PLG band 2–6%) |
| Free → paid (blended) | Paid subs ÷ all signups | 3–4% |
| **Net new MRR / wk** | New + expansion − churned MRR, weekly | climbing, +$150–300/wk by wk 12 |
| Paid logo churn | % of paying accounts that cancel/month | <5% / mo |
| Activation→paid lag | Median days from activation to first payment | <14 days (trial window) |
| Annual mix | % of paid revenue collected as annual (cash-forward) | ≥50% |

Instrument with a privacy-respecting, client-side-friendly analytics tool (Plausible or PostHog self-host) — fire events `capture_analyzed`, `verdict_viewed`, `output_copied`, `export_clicked`, `gate_hit{feature}`, `signup`, `trial_start`, `checkout_started`, `subscribed`. Never send pcap contents — only event names + counts (consistent with the privacy invariant).

---

### 2. 90-Day MRR Model — 0 → Credible Target

Funnel chain: **organic visitors → first-capture% → activation% → signup% → trial→paid% → $/user**. The model assumes the reverse-trial + Founder-annual stack from the pricing brief. Marginal cost per analysis is **~$0** (the Rust→WASM engine runs in the user's browser; the backend only touches optional derived-summary enrichment), so every marginal dollar of revenue is near-pure contribution margin — the funnel is the only constraint, not infrastructure cost.

**Cumulative 90-day organic visitor assumptions** (one Show HN front-page + one Product Hunt + steady community/SEO; $0 ad spend):

| Scenario | 90-day total unique visitors | First-capture % | Activation % | Signup % | Trial→paid % | Blended ARPU/mo |
|---|---|---|---|---|---|---|
| **Low** | 18,000 | 20% | 30% | 5% | 4% | $17 |
| **Base** | 35,000 | 25% | 40% | 8% | 6% | $18 |
| **High** | 70,000 | 28% | 45% | 10% | 8% | $19 |

**Resulting paid customers + exit MRR** (paid = visitors × signup% × trial→paid%; annual subs counted at MRR-equivalent = annual price ÷ 12):

| Scenario | Signups (90d) | Paid customers (90d) | Monthly-equivalent MRR (exit day 90) | + Founder annual cohort (cash forward) |
|---|---|---|---|---|
| **Low** | 900 | ~36 | **~$610 MRR** | +30 founders × $149 = $4.5k cash (~$370 MRR-equiv) → **~$980** |
| **Base** | 2,800 | ~168 | **~$3,000 MRR** | +120 founders × $149 = $17.9k cash (~$1,490 MRR-equiv) → **~$4,500** |
| **High** | 7,000 | ~560 | **~$10,600 MRR** | +200 (cap) × $149 = $29.8k cash (~$2,483 MRR-equiv) → **~$13,100** |

**How to read it:** the *recurring* MRR (col 4) is the honest steady-state number; the Founder-annual cohort (col 5) is the cash-forward accelerant that makes the headline number land *now* instead of in month 9 — that's the entire point of the capped 200-seat $149 founder offer. **Base case = the credible 90-day target: ~$3k recurring MRR + ~$1.5k MRR-equivalent from the founder cohort ≈ ~$4.5k MRR-equivalent exiting day 90**, with ~$18k cash collected up front for runway.

**The three levers that move this most (in order):**
1. **Activation %** — doubling activation (30→40%→45%) is the cheapest MRR multiplier; it's a product/onboarding fix, not a traffic fix. Optimize the "drop pcap → verdict in <10s → copy-paste ticket text" path relentlessly.
2. **Traffic volume from launch spikes** — Show HN front page alone is the difference between Low and Base. One great launch ≈ the whole quarter's paid SEO equivalent at $0 cost.
3. **Annual mix** — every annual sale locks 12 months of retention and pulls cash forward; it doesn't raise *recurring* MRR much but it's the survival lever for a bootstrapped runway.

---

### 3. Unit Economics & Why the Model Is Capital-Efficient

| Metric | Value | Note |
|---|---|---|
| **Marginal cost per analysis** | **~$0** | Engine runs client-side (Rust→WASM); no per-pcap server compute, no pcap storage, no egress for captures |
| Variable cost per *paying* user / mo | **~$0.50–2** | Supabase row/auth + optional AI/reputation proxy calls (operator-funded, only for opt-in Pro users); Stripe takes 2.9%+30¢ |
| **Gross margin** | **~92–97%** | Among the highest possible for a SaaS — the compute that would normally cost money happens on the user's device |
| **CAC** | **~$0** | All channels organic/founder-led (Show HN, Reddit, newsletters, SEO, directories). No ad spend |
| LTV (Pro, 5%/mo churn) | $19 ÷ 0.05 ≈ **~$380** | At <5% logo churn; annual subs push effective churn far lower |
| **LTV:CAC** | **effectively ∞** (CAC≈0) | The bottleneck is founder *time*, not capital |
| Fixed monthly burn | **~$20–60/mo** | Vercel + Supabase + domain; sub-$100 to operate the whole business |

**Why it's capital-efficient:**
- **Compute is externalized to the client.** The single biggest cost line for every cloud-upload competitor (CloudShark, A-Packets, sandboxes) — server-side packet processing and storage — is *zero* here. Scaling from 100 to 100,000 analyses/week adds ~$0 to the bill. This is the privacy invariant paying a financial dividend.
- **CAC is time, not money.** A solo founder with $0 budget can hit the Base case because every channel is organic and the product (no-signup, nothing-uploaded) is *built* to be posted as the value itself in security communities. The constraint is launch execution, not spend.
- **Cash-forward via annual.** Founder-annual + standard-annual collect 12 months up front at ~95% margin, funding runway without dilution or debt. ~$18k of base-case cash on <$100/mo burn is a >180-month runway from launch proceeds alone.
- **The model breaks even at ~2 paying customers.** Fixed burn is so low that the business is profitable almost immediately; everything past that is reinvestable margin.

---

### 4. Launch-Readiness Checklist

A launch spike is wasted if monetization, trust, and basic ops aren't live *on day one*. Gate the launch on every Technical + Trust/Legal item; Marketing items can lag by days but not weeks.

#### Technical (hard launch gates)
- [ ] **Flip Stripe TEST → LIVE.** Create live products/prices ($19/mo, $190/yr, $149 Founder annual), swap live publishable + secret keys, point webhooks at the prod Edge Function, run one real card end-to-end (subscribe → webhook → entitlement flips → cancel). *This is THE go-live gate — no live Stripe, no launch.*
- [ ] **Production env vars set in Vercel** — `VITE_SUPABASE_URL`, `VITE_SUPABASE_ANON_KEY`, Stripe live keys, AI/reputation secret keys (`AI_API_KEY`, `ABUSEIPDB/GREYNOISE/VIRUSTOTAL_KEY`) on the Edge Functions only (never in the browser bundle). Verify `/admin` + accounts work on the deployed domain.
- [ ] **Rotate the temp admin password** (the bootstrap admin account) to a strong unique secret + enable 2FA on Supabase, Stripe, Vercel, GitHub, domain registrar.
- [ ] **Error monitoring** — Sentry (free tier) on the React app + Edge Functions; alert on JS errors, the WASM-load path, and checkout failures.
- [ ] **Analytics / funnel tracking** — Plausible or PostHog wired to the §1 events; confirm `subscribed` fires on a real test purchase before launch.
- [ ] **Load-test the WASM path** — a front-page Show HN = 5k–30k uniques/24h. Confirm the engine loads under concurrency, the marketing routes are CDN-cached, and there's a static fallback if the SPA chokes.
- [ ] **Reverse-trial + contextual paywalls live** — 14-day Pro trial on signup, graceful auto-downgrade (no data loss), and the 6 gate triggers (export / 6th capture / >50MB / AI / carve / diff) firing the upgrade modal.
- [ ] **Status + support channel** — a status page (free: Instatus/BetterStack) + a real support inbox (`support@`) and a public response-time promise; auto-reply with docs link.
- [ ] **Backups + admin lockdown** — confirm Supabase RLS holds for anon/free, daily DB backup on, `/admin` non-public + role-gated.

#### Trust / Legal (a conversion asset for THIS product — not just compliance)
- [ ] **Terms of Service** — standard SaaS ToS (Termly/Termageddon generator is fine for a solo founder, then a cheap legal review).
- [ ] **Privacy Policy** — must explicitly state what the backend *does* and *doesn't* see: captures never transit the backend; only opt-in derived summaries + public IPs do, and only for logged-in users who enable enrichment. This precision *is* the trust.
- [ ] **Security / "Your data never leaves your browser" trust page** — **the single highest-leverage conversion asset for this product.** A dedicated page explaining the client-side WASM architecture, what is and isn't transmitted, the air-gap/compliance story, and the contrast with cloud uploaders (A-Packets' free results are public; everyone else uploads). Link it from the landing hero, the pricing page, every gate modal, and use it as the lead in every launch post. This page converts the regulated/security-conscious buyer who *cannot* use upload tools.
- [ ] **GDPR posture** — because pcaps stay client-side, the GDPR surface is tiny: only account email + billing data is processed. Document it: data-processing basis, sub-processors (Supabase, Stripe, Vercel, analytics), data-deletion/export on request, EU data residency note, cookie/consent banner only if analytics needs it (Plausible is cookieless → likely none).
- [ ] **DPA + sub-processor list** available on request (some practitioner-buyers' employers will ask even at $19).

#### Marketing (can trail launch by days, not weeks)
- [ ] **Landing page** — 3-second value prop ("Wireshark-grade PCAP triage in your browser. Nothing leaves your machine."), the no-upload trust hook above the fold, a working/embedded analyze-a-sample CTA, pricing with annual toggle defaulted to annual + Founder counter.
- [ ] **OG images** — per-route social cards (landing, pricing, each SEO tool route) so HN/Reddit/X/PH shares render with a real preview, not a blank card.
- [ ] **Sample captures** — 3–5 curated demo pcaps ("malware C2 + dropped EXE", "port scan", "cleartext creds") behind a one-click "Try a sample" so visitors hit the aha without their own file. These are also your screenshot/GIF source for social.
- [ ] **Docs / help** — a lightweight docs site: quickstart, the detector list (link each to its SEO explainer page), export formats, FAQ ("Is my pcap uploaded?" answered first), keyboard shortcuts.
- [ ] **Demo video (60s)** — drop pcap → threats light up → carve a file → export report. Reused for Product Hunt, the landing page, and social.
- [ ] **SEO tool routes pre-rendered** — `/analyze-pcap-online`, `/pcap-viewer`, `/pcapng-analyzer`, `/pcap-to-csv`, `/wireshark-alternative`, `/extract-files-from-pcap` with real server-delivered title/meta/H1 + `SoftwareApplication` JSON-LD + sitemap.
- [ ] **Directory submissions queued** — PRs to `awesome-pcaptools`, `cybersecurity-pcap-tools`, `awesome-incident-response`; AlternativeTo entry as a Wireshark/CloudShark alternative.

---

### 5. Top 5 Risks + Mitigations

| # | Risk | Why it's real for a solo bootstrapped founder | Mitigation |
|---|---|---|---|
| **1** | **Launch fizzles — no front page, no spike** | Show HN/PH are binary; a flat title or weak first hour = the quarter's traffic plan evaporates, and there's no ad budget to backstop it. | Build a small pre-launch audience (build-in-public + waitlist, 500+ qualified) *before* launch so day-one isn't cold. Stack launches across a week (Mon waitlist → Tue Show HN → Wed PH → Thu Reddit/newsletters → Fri recap) so no single event is load-bearing. Treat SEO long-tail (detector posts) as the durable engine that doesn't depend on any spike. Have ≥2 backup launch dates. |
| **2** | **Traffic converts to free users but not to paid** | The free, no-signup, nothing-uploaded loop is so good it *satisfies* users completely — they never hit a reason to pay. Free→paid for dev tools is only 2–6%. | Gate the *next action a satisfied user wants* (export/carve/AI/diff), never the aha. Run the reverse-trial so every signup *tastes* Pro then feels the loss. Loss-aversion expiry framing ("you exported 4 reports during your trial — keep them for $19"). Wire all 6 contextual paywalls. Instrument `gate_hit{feature}` to find which gate actually converts and double down. |
| **3** | **A fast-follower clones the wedge** | The in-browser-WASM + auto-triage + MITRE pitch is visible and copyable; PacketSafari/PcapAI are already moving toward guided AI investigation. The privacy moat is architectural but not patentable. | Compound the moat that's *hard* to copy fast: breadth of behavioral detectors (~20, each an SEO long-tail page), the analyst-report/export surface (STIX/MISP/CEF/Sigma), and brand ownership of "private/client-side pcap triage" via Show HN + directories + the trust page. Ship a visible cadence (each detector = a mini-launch) so you out-run a cloner on momentum and SEO surface area. |
| **4** | **Solo-founder bandwidth / burnout** | One person covers eng, support, content, sales, and ops; a launch spike of support tickets + bug reports can swamp the founder and stall everything else. | Automate ruthlessly: status page, support auto-replies + docs FAQ deflection, error monitoring (catch bugs before users report). Pre-write the launch-week content so launch days are execution not creation. Cap support surface by keeping the free tier self-serve. Protect the SEO content cadence (1 detector post/week) as the non-negotiable that runs even on bad weeks. |
| **5** | **Trust/privacy claim breaks (or is perceived to)** | The *entire* positioning rests on "nothing leaves your browser." A single bug that sends pcap bytes to the backend, a sloppy privacy-policy line, or a "wait, the AI feature uploads my data?" misread destroys the one differentiator irrecoverably in a security audience. | Treat the privacy invariant as a hard, tested boundary: a CI/network assertion that no capture bytes hit the wire; the trust page + privacy policy state *precisely* what the opt-in enrichment sends (derived summary + public IPs, logged-in only). Make enrichment unmistakably opt-in with a clear consent moment. Never let marketing over-claim beyond what the architecture guarantees. A security crowd that catches you exaggerating is unforgiving; one that verifies your claim becomes your evangelist. |
