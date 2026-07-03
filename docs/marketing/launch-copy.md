# PacketPilot — Launch Copy & Playbook

Ready-to-post drafts for launch, written for each venue's norms. Everything here is
factually grounded in the product (20+ MITRE-mapped detectors, Rust→WASM, capture
never uploaded, 5 exports, free tier + $19/mo Pro). No invented stats, no fake
customers — infosec audiences punish that.

**Honesty notes baked in:** the tool is commercial (free tier + Pro), the engine is
not open source (yet), and analyzing *your own* captures needs a free account — but the
live **sample is no-signup** (`/app?sample=1`), so every "try it" link points there so
nobody feels baited.

---

## 0. Do this first

- **Finish the live Stripe checkout test.** Launch traffic converting into a broken
  checkout is the one unforced error. Verify one real (refundable) payment end-to-end.
- Have the **"verify in devtools" GIF/clip ready** (open devtools → drop a pcap → show
  zero upload requests). It's your single best trust asset; link it everywhere.

---

## 1. Hacker News — Show HN (your highest-leverage single post)

HN rewards: technical substance, humility, being present in the thread. It punishes:
hype words ("revolutionary", "the best"), and asking for upvotes.

**Title** (≤80 chars, no hype):
```
Show HN: PacketPilot – analyze a pcap in your browser, nothing gets uploaded
```

**URL:** `https://packetpilot.app/app?sample=1`  *(link straight to the no-signup sample so HN can try it in one click)*

**Text (the post body):**
```
I kept hitting the same wall doing network triage: the fastest way to check "is
this capture bad?" is to upload it to some online analyzer, but you can't upload
a production or client capture — it's full of internal IPs, hostnames, creds, and
payload bytes. So the sensitive captures, the ones you most need a fast read on,
are exactly the ones you can't paste into a cloud tool.

PacketPilot is an attempt to fix that. The analysis engine is written in Rust and
compiled to WebAssembly, so the whole thing — parsing, flow reconstruction, ~20
behavioral detectors, TLS/SSH fingerprinting (JA3/JA4/JA3S/HASSH), file carving —
runs inside your browser tab. The capture is never serialized into a network
request. It's not a policy promise; you can open devtools, drop a pcap, and watch
zero bytes leave. It also means it works offline and on locked-down/air-gapped
boxes where you can't install Wireshark.

You drop a .pcap/.pcapng (or .gz) and get a severity-ranked, MITRE ATT&CK-mapped
verdict in a few seconds instead of a raw packet list — beaconing, DGA, lateral
movement, exfil, cleartext creds, weak TLS, malware downloads (SHA-256 carved from
HTTP), etc. You can export STIX/MISP/CEF/Sigma/CSV and a standalone HTML report.

Honest disclosures: it's a commercial tool with a free tier (full analyzer, free
account) and a $19/mo Pro tier for exports + IP-reputation enrichment. The engine
isn't open source yet — but the no-upload claim is verifiable in devtools
regardless, which felt like the more important thing to get right. The live sample
above needs no account.

I'd genuinely like feedback from people who do this for a living — especially on
the detectors (false-positive rates, what's missing) and on the privacy model.
What would make this a tool you'd actually reach for?
```

**Your first comment (post it yourself right after, for technical depth):**
```
A few technical notes for the curious:

- The engine is ~pure Rust with vendored crypto; no C in the WASM build. Parsing is
  streaming/bounded so a big capture doesn't blow up the tab.
- "Never uploaded" is structural: capture bytes live in WASM linear memory and are
  never handed to fetch/XHR/WebSocket. The only outbound traffic is optional,
  off-by-default IP-reputation enrichment, and even that sends a derived summary +
  public IPs — never the capture.
- Detectors are behavioral + signature (you can import Suricata-style rules), each
  mapped to ATT&CK technique IDs so findings line up with how people already triage.
- TLS: JA3/JA4/JA4-Q/JA3S + HASSH per flow, SNI from TLS and QUIC/HTTP3, cert-health
  and weak-TLS checks.

Happy to go deep on any of it. Roasts welcome.
```

**HN posting tips:**
- Post **Tue–Thu, ~8:00–10:00am ET**. Avoid weekends.
- Do **not** ask for upvotes anywhere. Do reply to every substantive comment fast —
  thread engagement is what keeps it on the front page.
- If it doesn't catch the first time, you're allowed a second Show HN later with a
  meaningful change (dang/HN mods are lenient on genuine reposts of Show HNs).

---

## 2. Reddit

**Important — subreddit norms differ a lot:**
- **r/netsec is strict.** It's for substantive research/articles; a "check out my
  tool" post will likely be removed. Only post there when you have a real technical
  **writeup** (e.g. a malware-pcap teardown), linking the tool as part of the content.
- **Tool-sharing-friendly, technical:** r/blueteamsec, r/DFIR, r/networking.
- **Big but noisier:** r/cybersecurity, r/netsecstudents (great for the free/education
  angle).
- **Best "soft" channel:** r/AskNetsec — answer real questions where PacketPilot
  genuinely helps, disclosing you made it.
- Follow the **self-promo etiquette**: participate normally elsewhere, disclose you're
  the maker, don't blast the same post to 6 subs the same hour.

### r/blueteamsec (or r/DFIR) — value-first draft

**Title:**
```
I built a browser-local pcap triage tool — the capture never leaves the tab (Rust/WASM). Looking for blue-team feedback.
```

**Body:**
```
Sharing something I built and would like honest feedback on from people who triage
captures for a living.

The problem I kept hitting: the fastest "is this pcap malicious?" workflow is an
online analyzer, but you can't upload production/client captures — internal IPs,
hostnames, creds, payloads. So the sensitive ones are exactly the ones you can't use
those tools for.

PacketPilot runs the whole analysis in the browser via a Rust→WebAssembly engine.
Drop a .pcap/.pcapng and you get a severity-ranked, ATT&CK-mapped verdict in seconds:
~20 detectors (beaconing, DGA, lateral movement, exfil, cleartext creds, port/host
scan, ARP spoof, SYN flood, cryptomining, weak TLS, malware download via SHA-256
carving...), JA3/JA4/JA3S/HASSH fingerprints, and exports to STIX/MISP/CEF/Sigma/CSV.
The capture is never uploaded — you can verify it in devtools — so it works on
sensitive traffic and on air-gapped/locked-down hosts.

No-signup sample if you want to poke at it: https://packetpilot.app/app?sample=1

Disclosure: I'm the author; it's a free tier + a paid Pro tier. Not trying to replace
Wireshark — it's the fast, private first-pass triage, then you pivot to Wireshark for
the deep dive (it'll even carve a per-flow sub-pcap to hand over).

What I'd love feedback on:
- Detector false-positive rates on your real captures
- What detections/protocols you'd want that aren't there
- Whether the "runs in the browser, nothing uploaded" model is actually useful in
  your environment or if policy would block even that
```

### r/AskNetsec — soft, reply-style template

When someone asks "how do I analyze a suspicious pcap / a pcap without uploading it /
a Wireshark alternative for quick triage," reply helpfully first, mention the tool
with disclosure:
```
For a fast first pass I'd triage before going deep in Wireshark. [genuinely useful
answer about their actual question...]. Full disclosure I built a browser tool for
exactly this — PacketPilot — it runs the analysis locally in the tab so the capture
isn't uploaded, which matters for sensitive captures. Free no-signup sample:
packetpilot.app/app?sample=1 . Either way, for the deep dive Wireshark/tshark is
still the move.
```

---

## 3. Mastodon (infosec.exchange) / X

Short, technical, privacy-forward. Mastodon's infosec community is unusually receptive
to indie tools.

```
Built a network-forensics triage tool that runs 100% in your browser.

Drop a .pcap → severity-ranked, MITRE ATT&CK-mapped findings in seconds. Rust
compiled to WASM, so the capture never leaves the tab — no upload, verify it in
devtools. Works offline / air-gapped.

~20 detectors, JA3/JA4/HASSH, STIX/MISP/Sigma export.

No-signup demo 👇
https://packetpilot.app/app?sample=1

#infosec #DFIR #blueteam #netsec
```

---

## 4. Product Hunt (secondary — infosec isn't PH's core, but the tech angle lands)

**Tagline (≤60 chars):**
```
Analyze a packet capture in your browser — nothing uploaded
```

**Description:**
```
PacketPilot turns a raw .pcap into a severity-ranked, MITRE ATT&CK-mapped threat
verdict in seconds — with a Rust/WebAssembly engine that runs entirely in your
browser, so the capture never leaves your device. 20+ detectors, TLS/SSH
fingerprinting, file carving, and STIX/MISP/CEF/Sigma/CSV exports. Free tier;
no-signup live sample.
```

---

## 5. Reusable positioning lines

- **One-liner:** "Analyze a pcap in your browser — ranked, MITRE-mapped threats in
  seconds, and the capture never leaves your device."
- **The wedge (vs cloud analyzers):** "The online pcap analyzer you can actually use
  on sensitive captures — because it doesn't upload them."
- **The trust line:** "Don't take our word for it — open devtools and watch zero
  bytes leave."
- **vs Wireshark:** "Not a Wireshark replacement — the fast, private first pass before
  you go deep."

---

## 6. Launch-week sequence

1. **Mon:** confirm Stripe checkout works end-to-end; publish the "vs" and
   "alternative" pages are already live — good landing spots for launch traffic.
2. **Tue ~9am ET:** Show HN. Clear your calendar to sit in the thread all day.
3. **Tue/Wed:** post to r/blueteamsec (or r/DFIR), then Mastodon/X. Space them out.
4. **Throughout:** answer r/AskNetsec + r/netsecstudents questions where you genuinely
   help; disclose authorship.
5. **Following weeks:** ship one malware-pcap teardown post per week (each = SEO +
   credibility + a legit r/netsec-worthy link), and watch the sample→signup→Pro funnel
   in analytics to see which channel actually converts.

**Golden rules:** disclose you're the maker, lead with value not the pitch, never ask
for upvotes, and reply to everyone. For a security audience, being transparent and
technically honest *is* the marketing.
