// ============================================================================
// PLACEHOLDER capture for the redesign demo. Typed against the REAL data model
// (../types) so every widget binds to production fields. Modeled on the bundled
// beacon-sample.pcap kill chain, nudged "hotter" (non-zero critical/high) so all
// five severity bands and every widget render with life. NOT real traffic.
// ============================================================================
import type {
  AnalysisOutput,
  CategoryBreakdownEntry,
  Finding,
  Incident,
  IpThreat,
  TimeHistogramEntry,
  TopTalker,
} from "../types";

const NS = 1_000_000_000;
const FIRST_TS_NS = 1_699_999_920 * NS;
const BUCKET_SECS = 120;
const N_BUCKETS = 96; // 96 × 120 s ≈ 3.2 h — dense enough for heatmap + sparklines

/**
 * Deterministic synthetic timeline (no RNG, identical every render). A baseline
 * diurnal web/DNS wave, a steady C2 beacon ripple, and one sharp exfil spike near
 * the tail — the shapes the heatmap + sparklines are meant to reveal.
 */
function buildTimeHistogram(): TimeHistogramEntry[] {
  const out: TimeHistogramEntry[] = [];
  for (let i = 0; i < N_BUCKETS; i++) {
    const t = i / N_BUCKETS;
    // Smooth baseline wave (two sines, no randomness).
    const wave =
      0.5 + 0.35 * Math.sin(t * Math.PI * 2 - 0.6) + 0.15 * Math.sin(t * Math.PI * 6);
    const baseline = 120 + Math.round(wave * 520);
    // Beacon ripple: a small, regular bump every 6th bucket (~12 min).
    const beacon = i % 6 === 0 ? 60 : 0;
    // Exfil spike: a single dramatic burst at ~82% through the capture.
    const exfil = i === Math.round(N_BUCKETS * 0.82) ? 1850 : 0;
    const pkts = baseline + beacon + exfil;
    const bytesPerPkt = exfil ? 1180 : 140 + ((i * 37) % 90); // exfil = big frames
    out.push({
      epoch_sec: Math.round((FIRST_TS_NS + i * BUCKET_SECS * NS) / NS),
      pkts,
      bytes: pkts * bytesPerPkt,
    });
  }
  return out;
}

const time_histogram = buildTimeHistogram();
const total_packets = time_histogram.reduce((s, h) => s + h.pkts, 0);
const total_bytes = time_histogram.reduce((s, h) => s + h.bytes, 0);

const category_breakdown: CategoryBreakdownEntry[] = [
  { category: "web", flows: 26_859, pkts: 27_758, bytes: 4_788_108 },
  { category: "dns", flows: 12_161, pkts: 12_162, bytes: 913_670 },
  { category: "remote-access", flows: 36, pkts: 54, bytes: 19_716 },
  { category: "file-transfer", flows: 25, pkts: 26, bytes: 1_439 },
  { category: "scan", flows: 24, pkts: 48, bytes: 3_072 },
  { category: "c2", flows: 8, pkts: 2_999, bytes: 404_865 },
  { category: "anomalous", flows: 4, pkts: 900, bytes: 1_308_600 },
  { category: "tunnel-vpn", flows: 40, pkts: 40, bytes: 4_520 },
  { category: "email", flows: 0, pkts: 0, bytes: 0 },
  { category: "voip", flows: 0, pkts: 0, bytes: 0 },
  { category: "iot-ot", flows: 0, pkts: 0, bytes: 0 },
  { category: "unknown", flows: 0, pkts: 0, bytes: 0 },
];

const total_flows = category_breakdown.reduce((s, c) => s + c.flows, 0);

const top_talkers: TopTalker[] = [
  { ip: "10.13.37.7", pkts: 4_017, bytes: 1_738_997, flows: 3_100 },
  { ip: "185.220.101.5", pkts: 900, bytes: 1_308_600, flows: 1 },
  { ip: "45.77.13.37", pkts: 2_999, bytes: 404_865, flows: 2_999 },
  { ip: "10.0.63.10", pkts: 1_181, bytes: 132_848, flows: 1_181 },
  { ip: "10.0.49.10", pkts: 1_176, bytes: 132_200, flows: 1_176 },
  { ip: "10.0.3.10", pkts: 1_188, bytes: 131_586, flows: 1_188 },
  { ip: "10.0.28.10", pkts: 1_189, bytes: 130_659, flows: 1_189 },
  { ip: "10.0.24.10", pkts: 1_173, bytes: 130_439, flows: 1_173 },
  { ip: "10.0.0.53", pkts: 980, bytes: 96_540, flows: 40 },
  { ip: "10.66.0.1", pkts: 612, bytes: 71_220, flows: 36 },
];

const ip_threats: IpThreat[] = [
  {
    ip: "10.13.37.7", ip_class: "private", severity: "critical", score: 89,
    flows: 3_100, bytes: 1_738_997, ioc: false, tags: ["internal"],
    attack: ["T1046", "T1110", "T1021", "T1071", "T1071.004", "T1048"],
    evidence: [
      "multi-stage kill chain: sweep → brute force → lateral → C2 → exfil",
      "beacons to 45.77.13.37:443 every ~30s (jitter CV 0.013)",
      "1.2 MB exfiltrated to external 185.220.101.5:443",
    ],
  },
  {
    ip: "45.77.13.37", ip_class: "public", severity: "high", score: 72,
    flows: 2_999, bytes: 404_865, ioc: true, tags: ["public", "c2"],
    attack: ["T1071"],
    evidence: [
      "periodic beaconing: 2999 contacts to 45.77.13.37:443",
      "interval ~30s, jitter CV 0.013 (low = machine-regular)",
      "on a known C2 indicator feed",
    ],
  },
  {
    ip: "185.220.101.5", ip_class: "public", severity: "high", score: 72,
    flows: 1, bytes: 1_308_600, ioc: true, tags: ["public", "tor-exit"],
    attack: ["T1048"],
    evidence: [
      "outbound 1.2 MB to external 185.220.101.5:443",
      "1308600× more out than in (asymmetric upload; 0 B in)",
      "known Tor exit node",
    ],
  },
  {
    ip: "10.0.0.53", ip_class: "private", severity: "high", score: 74,
    flows: 40, bytes: 4_520, ioc: false, tags: ["internal", "dns"],
    attack: ["T1071.004"],
    evidence: [
      "40 DNS queries with avg label entropy 4.22 (max 32 chars)",
      "high-entropy, long-label queries — data/C2 tunneled over DNS",
      "example: nqq7ry4ginbyiw6f3q3zmhm2kq5ydexx.tunnel.exfil.example",
    ],
  },
  {
    ip: "10.66.0.1", ip_class: "private", severity: "medium", score: 48,
    flows: 36, bytes: 71_220, ioc: false, tags: ["internal", "ssh"],
    attack: ["T1110"],
    evidence: [
      "target of 30 SSH connection attempts from 10.13.37.7",
      "many separate logins to one auth service — password guessing",
    ],
  },
  {
    ip: "10.0.0.50", ip_class: "private", severity: "medium", score: 44,
    flows: 12, bytes: 18_400, ioc: false, tags: ["internal"],
    attack: ["T1552"],
    evidence: ["sent HTTP Basic auth in cleartext to 10.0.0.80:80 (5 exposures)"],
  },
];

// ---- Findings (the six stages of the headline incident + cleartext creds) ----
const f = (p: Partial<Finding> & Pick<Finding, "kind" | "severity" | "score" | "title" | "src_ip">): Finding => ({
  dst_ip: null, dst_port: null, attack: [], evidence: [],
  interval_ns: null, jitter_cv: null, contacts: null, ...p,
});

const incident1Findings: Finding[] = [
  f({ kind: "host_sweep", severity: "high", score: 65, src_ip: "10.13.37.7", dst_port: 445,
    title: "Host sweep: 10.13.37.7 probed 24 hosts on port 445", attack: ["T1046"], contacts: 24,
    evidence: ["24 distinct destination hosts contacted on port 445", "horizontal scan / remote-system discovery"] }),
  f({ kind: "brute_force", severity: "high", score: 68, src_ip: "10.13.37.7", dst_ip: "10.66.0.1", dst_port: 22,
    title: "Brute force: 10.13.37.7 → 10.66.0.1:22 (30 SSH attempts)", attack: ["T1110"], contacts: 30,
    evidence: ["30 connection attempts to SSH 10.66.0.1:22", "many separate logins to one auth service — password guessing"] }),
  f({ kind: "lateral_movement", severity: "high", score: 70, src_ip: "10.13.37.7", dst_port: 3389,
    title: "Lateral movement: 10.13.37.7 → 6 internal hosts over RDP (3389)", attack: ["T1021"], contacts: 6,
    evidence: ["RDP sessions to 6 distinct internal hosts on port 3389", "e.g. 10.66.0.1, 10.66.0.2, 10.66.0.3", "east-west admin sessions — pivoting / remote execution"] }),
  f({ kind: "beacon", severity: "high", score: 70, src_ip: "10.13.37.7", dst_ip: "45.77.13.37", dst_port: 443,
    title: "Periodic beacon: 10.13.37.7 → 45.77.13.37:443 every ~30s", attack: ["T1071"],
    interval_ns: 29_999_902_800, jitter_cv: 0.013473454, contacts: 2_999,
    evidence: ["periodic beaconing: 2999 contacts to 45.77.13.37:443", "interval ~30s, jitter CV 0.013 (low = machine-regular)", "external destination"] }),
  f({ kind: "dns_tunnel", severity: "high", score: 74, src_ip: "10.13.37.7", dst_ip: "10.0.0.53", dst_port: 53,
    title: "DNS tunneling: 10.13.37.7 → 10.0.0.53 (40 high-entropy queries)", attack: ["T1071.004"], contacts: 40,
    evidence: ["40 DNS queries with avg label entropy 4.22 (max 32 chars)", "high-entropy, long-label queries — data/C2 tunneled over DNS", "example: nqq7ry4ginbyiw6f3q3zmhm2kq5ydexx.tunnel.exfil.example"] }),
  f({ kind: "data_exfil", severity: "high", score: 72, src_ip: "10.13.37.7", dst_ip: "185.220.101.5", dst_port: 443,
    title: "Data exfiltration: 10.13.37.7 → 185.220.101.5:443 (1.2 MB out)", attack: ["T1048"],
    evidence: ["outbound 1.2 MB to external 185.220.101.5:443", "1308600× more out than in (asymmetric upload; 0 B in)", "external destination"] }),
];

const incidents: Incident[] = [
  {
    host: "10.13.37.7", severity: "critical", score: 89,
    title: "Multi-stage incident on 10.13.37.7",
    narrative:
      "10.13.37.7 swept the network, then brute-forced credentials, then moved laterally, then beaconed to a C2, then tunneled data over DNS, then exfiltrated data.",
    stages: ["Discovery", "Credential Access", "Lateral Movement", "Command & Control", "Exfiltration"],
    attack: ["T1046", "T1110", "T1021", "T1071", "T1071.004", "T1048"],
    findings: incident1Findings,
  },
  {
    host: "10.0.0.50", severity: "high", score: 66,
    title: "Cleartext credentials: 10.0.0.50 → 10.0.0.80:80 (HTTP Basic auth)",
    narrative: "Cleartext credentials: 10.0.0.50 → 10.0.0.80:80 (HTTP Basic auth).",
    stages: ["Credential Access"], attack: ["T1552"],
    findings: [
      f({ kind: "cleartext_creds", severity: "high", score: 66, src_ip: "10.0.0.50", dst_ip: "10.0.0.80", dst_port: 80,
        title: "Cleartext credentials: 10.0.0.50 → 10.0.0.80:80 (HTTP Basic auth)", attack: ["T1552"], contacts: 5,
        evidence: ["HTTP Basic auth sent in cleartext to 10.0.0.80:80 (5 exposures)", "credentials readable to anyone on-path — use TLS"] }),
    ],
  },
  {
    host: "10.0.0.51", severity: "high", score: 66,
    title: "Cleartext credentials: 10.0.0.51 → 10.0.0.91:21 (FTP login)",
    narrative: "Cleartext credentials: 10.0.0.51 → 10.0.0.91:21 (FTP login).",
    stages: ["Credential Access"], attack: ["T1552"],
    findings: [
      f({ kind: "cleartext_creds", severity: "high", score: 66, src_ip: "10.0.0.51", dst_ip: "10.0.0.91", dst_port: 21,
        title: "Cleartext credentials: 10.0.0.51 → 10.0.0.91:21 (FTP login)", attack: ["T1552"], contacts: 2,
        evidence: ["FTP login sent in cleartext to 10.0.0.91:21 (2 exposures)", "credentials readable to anyone on-path — use TLS"] }),
    ],
  },
];

const findings: Finding[] = [...incident1Findings, ...incidents[1].findings, ...incidents[2].findings];

export const MOCK_OUTPUT: AnalysisOutput = {
  schema_version: 1,
  engine_version: "0.1.0",
  source_path: "captures/beacon-sample.pcap",
  source_sha256: "3f1c9a2be4d77c0a1e5b8d4f6029a7c3b9e1d2f4a6c8071539ade2bc4f6178e0",
  source_bytes: 6_362_957,
  link_type: "EN10MB",
  elapsed_ms: 412,
  summary: {
    total_packets,
    total_bytes,
    captured_bytes: total_bytes,
    total_flows,
    decode_errors: 0,
    non_ip_frames: 0,
    proto: {
      tcp: 27_838, udp: 12_162, dns: 12_162, http: 11_922, tls: 15_836,
      other_tcp: 80, other_udp: 0, truncated: 0, non_ipv4: 0,
    },
    first_ts_ns: FIRST_TS_NS,
    last_ts_ns: FIRST_TS_NS + (N_BUCKETS - 1) * BUCKET_SECS * NS,
    duration_ns: (N_BUCKETS - 1) * BUCKET_SECS * NS,
    unique_hosts: 96,
    top_talkers,
    protocol_hierarchy: [],
    port_histogram: [],
    time_histogram,
    time_bucket_secs: BUCKET_SECS,
    category_breakdown,
    // Honors the design's data trap: ZERO critical FLOWS even though a CRITICAL
    // incident exists — the verdict is the incident counter, not this ring. Sums
    // to total_flows (39,157) so cross-widget invariants hold.
    severity_counts: { critical: 0, high: 12, medium: 280, low: 3_000, info: 35_865 },
    ip_threats,
    findings,
    incidents,
  },
};

export default MOCK_OUTPUT;
