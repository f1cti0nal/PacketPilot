# Sharing captures safely (Safe Share)

Packet captures are among the most sensitive artifacts in an investigation: they contain
internal addressing, hostnames, credentials, and payload data. **Safe Share** produces a
sanitized/anonymized copy of a capture so you can send it to a vendor, a CERT, a customer, or
another team **without leaking that data** — while keeping the capture analyzable on the other
end.

Everything runs locally: natively in the desktop app / CLI, and in-browser via WebAssembly.
The original capture and the per-run mapping key never leave your device.

> **The wedge:** PacketPilot's promise is *"captures never leave the device by default."* Safe
> Share turns that into an active capability — the `sanitize → share → escalate` workflow.

---

## What it does

A single streaming pass reads the capture (pcap / pcapng, optionally gzip-wrapped), transforms
each packet **in place without changing any length**, recomputes checksums, and writes a valid
output capture plus a JSON **manifest** sidecar.

| Data | Transform |
|---|---|
| **IPv4 / IPv6 addresses** | Keyed, deterministic pseudonyms. Prefix-preserving by default (Crypto-PAn construction): hosts of one subnet stay grouped in a pseudonymous subnet. Special-use addresses (loopback, multicast, broadcast, unspecified) pass through; private/CGNAT/link-local/ULA block membership is always preserved. The mapping is bijective — distinct inputs never collide. |
| **MAC addresses** | Keyed pseudonyms (unicast, locally-administered) so flows stay linkable. Optionally keep the vendor OUI. Broadcast/multicast pass through. |
| **Application payloads** | **Scrub** (default): every payload byte zeroed — only headers, sizes, and timing remain. **Keep**: payloads retained for deeper analysis, with sensitive L7 fields redacted (below). |
| **DNS** | Query/answer names → stable per-label tokens; A/AAAA rdata pseudonymized with the same address mapping as the headers. |
| **HTTP** | Request target, `Host`, and credential headers (`Authorization`, `Cookie`, `Set-Cookie`, `WWW-Authenticate`, `X-API-Key`, …) → stable tokens. `Referer`/`Origin`/`Location` URLs tokenized (scheme kept). |
| **TLS** | ClientHello **SNI** hostname → per-label tokens (consistent with DNS/Host). |
| **Cleartext credentials** | `USER`/`PASS`/`LOGIN`/`AUTH` arguments on FTP/SMTP/POP3/IMAP/telnet-style lines → tokens. |
| **ICMP error bodies** | The embedded original IP header is pseudonymized too (so it can't leak the pre-NAT addresses). |
| **ARP / NDP** | Sender/target hardware + protocol addresses pseudonymized; NDP link-layer-address options rewritten. |
| **Checksums** | L3 (IPv4 header) and L4 (TCP/UDP/ICMP/ICMPv6/SCTP) recomputed so the output loads cleanly. Where snaplen truncation makes recomputation impossible, the checksum is zeroed. |
| **Timestamps** | Preserved by default. Optional constant time-shift blunts correlation against external logs while keeping relative timing intact. |

**Consistency guarantee:** within one run, the same input value always maps to the same output
value — across every packet and every protocol. So a sanitized capture stays *analyzable*: flows
still reconstruct, conversations still line up, and re-running PacketPilot on the output produces
the same packet and flow totals as the original.

### The manifest

Alongside `out.pcap`, Safe Share writes `out.pcap.manifest.json` for chain of custody. It records:

- the tool + version and creation time,
- the exact options used,
- **SHA-256 of the input and output** files,
- counts by category (addresses/MACs pseudonymized, names/fields/SNI/credentials redacted,
  payload bytes scrubbed, checksums recomputed, …).

The manifest contains **no original values and no key material** — it says *what kinds* of data
were transformed and *how much*, never *what* they were.

---

## What is and isn't protected

**Protected:** IP/MAC addresses (headers, ARP/NDP, DNS rdata, ICMP-embedded headers), DNS names,
HTTP host/target/credential headers, TLS SNI, cleartext credentials, and — in the default scrub
mode — *all* payload bytes.

**Not fully protected (know the limits):**

- **Traffic shape is intentionally preserved** — packet sizes, counts, timing, and (with
  prefix-preservation on) subnet structure. That's what keeps the capture analyzable, but it also
  means a determined analyst could still reason about *behavior*. Use the time-shift option and
  turn off prefix-preservation if that matters for your threat model.
- **Keep mode only redacts the L7 fields listed above.** Anything else in a retained payload
  (a body, an unrecognized protocol, a custom header) is kept **verbatim**. Keep mode is for
  captures you'd share with a *trusted* party; when in doubt, use the default scrub mode.
- **No reverse mapping is ever exported.** This is deliberate — Safe Share is not a
  de-anonymization oracle. The per-run key exists only in memory and is discarded when the
  process exits, so re-identification is not possible from the output or the manifest.

---

## Using it

### Desktop / Web UI

Load a capture, then **Export → "Sanitized capture (Safe Share)…"** (also in the ⌘K palette).
Choose the payload policy and options, click **Export**. On desktop you pick a save location and
the capture + manifest are written next to each other; in the browser both download. A summary
shows what was transformed.

### CLI

```sh
# Default: scrub payloads, prefix-preserving pseudonyms, L7 redaction, manifest sidecar
ppcap sanitize capture.pcap --out capture.sanitized.pcap

# Keep payloads but redact sensitive L7 fields; write pcapng; shift time back 1h
ppcap sanitize capture.pcapng --out clean.pcapng --payload keep --time-shift -3600

# Flat (non-prefix-preserving) mapping, keep vendor OUIs, custom manifest path
ppcap sanitize capture.pcap --out clean.pcap \
  --no-preserve-prefix --preserve-oui --manifest clean.manifest.json
```

| Flag | Effect |
|---|---|
| `--out <path>` | Output capture (`.pcapng` extension ⇒ pcapng, else classic pcap). |
| `--manifest <path>` | Manifest path (default `<out>.manifest.json`). |
| `--payload scrub\|keep` | Payload policy (default `scrub`). |
| `--keep-first <N>` | In scrub mode, retain the first N payload bytes per packet for protocol ID. |
| `--no-preserve-prefix` | Use a flat per-block permutation instead of prefix-preserving. |
| `--preserve-oui` | Keep MAC vendor prefixes. |
| `--no-redact` | Disable L7 field redaction. |
| `--time-shift <secs>` | Shift every timestamp by N seconds. |
| `--pcapng` | Force pcapng output regardless of the `--out` extension. |

---

## Guarantees, verified by tests

- **Correctness** — the output loads in Wireshark and re-analyzes in PacketPilot; L3/L4 checksums
  verify; packet and flow counts are preserved (round-trip integration test).
- **Consistency** — identical inputs map identically within a run; the address mapping is
  bijective (no collisions on a dense range); one hostname label maps to one token across DNS,
  HTTP, and TLS.
- **Privacy** — no original IP/MAC/SNI/DNS-name/credential/payload byte appears in the output or
  the manifest (a scanning test over crafted fixtures with known secrets).
- **Bounded memory** — a single streaming pass with the same memory discipline as `analyze`.
