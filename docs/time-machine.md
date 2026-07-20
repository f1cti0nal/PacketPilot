# Time Machine — retrospective re-scan

Threat intel is always catching up to reality. An IP, domain, or TLS fingerprint that
looked clean when you analyzed a capture last week can be published as malicious today.
**Time Machine** answers the question that follows: *did any capture I already cleared
actually talk to it?* — and it answers **without re-streaming the pcap**.

At analysis time PacketPilot can distil a capture into a compact **capture index**: the set
of network indicators it contained (external IPs, domains / TLS SNI / passive-DNS names, and
JA3/JA4 fingerprints), each tagged with whether it was *already* flagged then. Later, a
**rescan** re-evaluates that index against an updated threat feed and reports the indicators
that were clean at capture time but are dirty now.

Everything runs locally and offline — a pure transform over a small JSON sidecar and a feed
file. No packets or payloads are stored in the index, and nothing leaves the device.

> **Scope.** This is the local-first core: index + rescan over the offline threat feed
> (IP / domain / JA3 / JA4). Scheduled re-scans, live feed subscriptions (MISP/Sigma), a
> shared team case store, and file-hash re-matching are deliberately out of scope here and
> tracked as follow-ups.

---

## Workflow

```sh
# 1. Analyze as usual, and also emit a Time Machine index for the capture.
ppcap analyze capture.pcap --json out.json --hash --index capture.index.json

# 2. Weeks later, a feed update lands. Re-evaluate saved indices against it.
ppcap rescan capture.index.json --threat-feed updated-feed.json

#    ...or sweep a whole directory of saved indices at once:
ppcap rescan cases/*.index.json --threat-feed updated-feed.json --json report.json
```

`rescan` prints a human summary to stderr and, with `--json <path>` (or `--json -` for
stdout), writes the full structured report. Pass `--include-known` to also list indicators
that were *already* flagged at capture time (by default only the **newly** dirty ones are
shown — those are the actionable alerts).

Example:

```
rescan: 1 indices, 58 indicators evaluated — 1 newly flagged, 0 already known
  NEW  ip     203.0.113.7  (capture.index.json)  [Cobalt Strike]
```

`--hash` on the original `analyze` is recommended: it records the source SHA-256 in the
index so a rescan hit ties back to the exact capture file.

---

## The capture index

A small JSON sidecar — no packets, no payloads, only derived indicators and provenance:

```json
{
  "schema_version": 1,
  "engine_version": "0.1.0",
  "source_path": "capture.pcap",
  "source_sha256": "…",
  "analyzed_unix_secs": 1752000000,
  "first_ts_ns": 1700000000000000000,
  "last_ts_ns": 1700000100000000000,
  "indicators": [
    { "kind": "ip",     "value": "203.0.113.7",  "flagged_at_capture": false },
    { "kind": "domain", "value": "cdn.example",  "flagged_at_capture": false },
    { "kind": "ja3",    "value": "…",            "flagged_at_capture": false }
  ]
}
```

`flagged_at_capture` records whether the indicator was an IOC / malicious-reputation hit
*when the capture was analyzed*. That bit is what lets a rescan separate a **newly**-dirty
indicator (the alert) from one that was already known bad.

Indicator classes captured: `ip` (external IPs, including passive-DNS-resolved IPs),
`domain` (TLS SNI + passive-DNS names), `ja3`, `ja4`. These are exactly the classes the
offline threat feed can match.

---

## The rescan report

```json
{
  "newly_flagged": [
    {
      "source_path": "capture.pcap",
      "source_sha256": "…",
      "analyzed_unix_secs": 1752000000,
      "first_ts_ns": 1700000000000000000,
      "last_ts_ns": 1700000100000000000,
      "kind": "ip",
      "value": "203.0.113.7",
      "label": "Cobalt Strike",
      "was_flagged_at_capture": false
    }
  ],
  "still_flagged": [],
  "indices_scanned": 1,
  "indicators_evaluated": 58
}
```

- **`newly_flagged`** — dirty now, clean at capture time. The actionable alerts.
- **`still_flagged`** — dirty now and already known then (shown in the CLI only with
  `--include-known`).
- Each hit carries the source capture, its analysis time, and the capture window
  (`first_ts_ns`/`last_ts_ns`) so you can pivot straight to the relevant traffic.

The updated feed uses the same JSON format as `analyze --threat-feed` (`bad_ips`,
`bad_cidrs`, `bad_domains`, `bad_suffixes`, `bad_ja3`, `bad_ja4`).

---

## Guarantees, verified by tests

- **Correctness** — building an index collects the expected indicators and the
  `flagged_at_capture` bit; the index round-trips through JSON.
- **Retrospective detection** — a feed that newly lists a previously-clean IP / domain /
  JA3 surfaces it in `newly_flagged`; an indicator that was already an IOC at capture time
  lands in `still_flagged`, never as a false "new" alert.
- **Offline + bounded** — pure transforms over the summary and the feed; no packet re-read,
  no network.
