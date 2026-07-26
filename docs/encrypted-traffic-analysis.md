# Encrypted Traffic Analysis

Most traffic worth triaging is encrypted, and PacketPilot never decrypts it during analysis.
Encrypted Traffic Analysis (ETA) is what the engine can still tell you: who the server is, what it
negotiated, and whether a channel's *shape* betrays something the protocol labels do not.

Everything here is **keyless**. It reads handshake plaintext (ClientHello, ServerHello, TLS ≤ 1.2
certificates), QUIC's version-public Initial protection (the RFC-published salt plus the
wire-visible connection ID — no session secrets), and wire statistics (byte distributions,
direction, volume). The separate opt-in key-log decryption feature is unchanged and stays out of
the analysis path entirely.

> **Scope.** Single-capture, offline, on-device. ETA does **not** decrypt, does not use ML, and
> does not need a sidecar or prior captures. It cannot see inside ECH (that is the point of ECH) or
> read TLS 1.3 certificates (encrypted by design). Packet-length-sequence behavioral features and
> JA4X certificate fingerprints are follow-ups, not part of this.

## What you get

**Server-side fingerprints.** Every TLS server handshake yields **JA4S** (the modern FoxIO server
fingerprint) alongside the legacy JA3S, plus the negotiated version and cipher. QUIC gets the same:
the server's Initial is opened keylessly, so QUIC flows are no longer server-side blind.

**A TLS posture rollup.** The dashboard's *TLS servers* card answers "what do my servers actually
negotiate?" per endpoint — version, cipher, JA4S — without querying the flow table.

**Three findings**, each explainable and each with its false positives designed out:

| Finding | Fires on | Severity |
|---|---|---|
| `encrypted_unknown_protocol` | A sustained, high-entropy channel that **no** payload sniffer can name — the shape of custom-crypto C2 or a hand-rolled tunnel | Medium (external) / Low |
| `missing_sni` | A completely-parsed ClientHello that named **no** server | Low |
| `port_protocol_mismatch` | TLS on a port naming no service, or an established **non**-TLS channel on 443 | Info → High |

**JA4S as an indicator.** Threat feeds can carry `bad_ja4s`, so a feed can name malicious *server
infrastructure* rather than only the client stack contacting it. JA4S hits score like any other
fingerprint IOC, export to STIX/MISP, and are re-scannable by Time Machine.

## Workflow

```sh
# ETA is on by default — nothing to enable.
ppcap analyze capture.pcap --json out.json

# Opt out of the detectors (fingerprint extraction is metadata and stays on):
ppcap analyze capture.pcap --no-encrypted-analysis

# A synthetic capture that exercises the whole path:
ppcap gen eta.pcap --scenario encrypted-anomaly --packets 200
ppcap analyze eta.pcap --json -

# Feed a known-bad server fingerprint:
#   feed.json → { "bad_ja4s": ["t130200_1301_234ea6891581"] }
ppcap analyze capture.pcap --threat-feed feed.json
```

On a capture with findings, stderr carries a one-line summary beside the existing ones:

```
encrypted-traffic: 3 findings
```

## What lands in the output

Flow rows (Parquet / the Flows table / the Query tab) gain three columns — schema **v11**:

| Column | Meaning |
|---|---|
| `ja4s` | Server fingerprint, TCP and QUIC |
| `entropy_c2s` / `entropy_s2c` | Payload entropy (bits/byte), **non-NULL only for flows no protocol identified** |

So the hunt is one query:

```sql
-- Unidentified traffic whose payload measures as ciphertext.
SELECT flow_id, src_ip, dst_ip, dst_port, entropy_c2s, entropy_s2c
FROM flow
WHERE app_proto IS NULL AND (entropy_c2s >= 7.2 OR entropy_s2c >= 7.2)
ORDER BY bytes_c2s + bytes_s2c DESC;
```

Both queries above ship as bundled samples in the **Query** tab.

## How the entropy signal avoids crying wolf

High entropy alone is a weak signal — compressed archives, media, and every sanctioned VPN look
like ciphertext too. The substrate is therefore narrow by construction:

- **Identified protocols are never measured.** Identification is tracked per *flow*, not per
  packet: post-handshake TLS packets look unidentifiable in isolation, so a per-packet test would
  measure ordinary HTTPS. A known protocol, an SSH fingerprint, or a STUN handshake parks the flow
  permanently.
- **Encrypted-by-design ports are excluded**, not merely down-ranked — WireGuard, IPsec, OpenVPN,
  QUIC, DoT, SSH/RDP/VNC, RTP/STUN/TURN. High entropy there is the protocol working.
- **Compressed streams are screened** by container magic (gzip, zstd, zip, 7z, xz…) before any
  measurement.
- **Mid-capture flows are excluded**: without an observed handshake, "unidentified" has a benign
  explanation.
- **Both directions must carry sampled payload** — a byte-level test, since packet counts are
  satisfied by bare ACKs.

The same discipline applies to the posture detectors: `missing_sni` requires a *completely parsed*
ClientHello (a segment-split hello whose SNI lies beyond the captured bytes proves nothing) and
excludes ECH flows, whose outer SNI is absent by design. The non-TLS-on-443 arm requires an
observed TCP handshake and offers an allowlist for sanctioned OpenVPN-over-443 gateways.

## Guarantees, verified by tests

- **Keyless** — the analysis path imports nothing from the decryption modules; every signal comes
  from handshake plaintext, version-public QUIC protection, or wire statistics. The QUIC server
  keys are pinned to the RFC 9001 §A.3 golden vector.
- **Correctness** — crafted captures raise each finding with the right attribution and severity;
  benign mixed traffic, mid-capture flows, named-SNI sessions, ECH flows, SSH on odd ports, and
  compressed transfers stay silent.
- **Bounded & offline** — all new state is capped by named constants (~7 MiB worst case for the
  entropy substrate); peak heap stays inside the engine's budget. Nothing leaves the device.
- **Deterministic** — identical input yields byte-identical findings, columns, and rollups.
- **Privacy-preserving** — only derived values are retained: fingerprint strings, entropy scalars,
  and boolean flags. No payload bytes, no certificates, no key material.

## Not in v1 (follow-ups)

- Packet-length/timing sequence features (the Cisco-ETA-style behavioral layer).
- JA4X and richer certificate metadata (serial, key type, issuer chain).
- SSH posture: banner retention, host-key algorithms, `bad_hassh` feed matching.
- First-seen-JA4S-per-host as a behavioral-baseline novelty axis.
- Curated known-bad JA4S seeding for the builtin fingerprint set.
