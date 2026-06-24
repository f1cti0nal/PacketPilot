import type { AnalysisOutput, Finding, FlowPackets, FlowRow, IpThreat, PacketRow } from "../types";

const f = (p: Partial<Finding> & Pick<Finding, "kind" | "severity" | "score" | "title" | "src_ip">): Finding => ({
  dst_ip: null, dst_port: null, attack: [], evidence: [],
  interval_ns: null, jitter_cv: null, contacts: null, ...p,
});

const incident1Findings: Finding[] = [
  f({ kind: "host_sweep", severity: "high", score: 65, src_ip: "10.13.37.7", dst_port: 445,
      title: "Host sweep: 10.13.37.7 probed 24 hosts on port 445", attack: ["T1046"], contacts: 24 }),
  f({ kind: "beacon", severity: "high", score: 70, src_ip: "10.13.37.7", dst_ip: "45.77.13.37", dst_port: 443,
      title: "Periodic beacon: 10.13.37.7 -> 45.77.13.37:443", attack: ["T1071"],
      interval_ns: 30_000_000_000, jitter_cv: 0.013, contacts: 2999 }),
  f({ kind: "data_exfil", severity: "high", score: 72, src_ip: "10.13.37.7", dst_ip: "185.220.101.5", dst_port: 443,
      title: "Data exfiltration: 10.13.37.7 -> 185.220.101.5:443 (1.2 MB out)", attack: ["T1048"] }),
];

const ip_threats: IpThreat[] = [
  { ip: "10.13.37.7", ip_class: "private", severity: "critical", score: 89, flows: 3100, bytes: 1_738_997,
    ioc: false, tags: ["internal"], attack: ["T1046", "T1071", "T1048"], evidence: ["multi-stage kill chain"] },
  { ip: "45.77.13.37", ip_class: "public", severity: "high", score: 72, flows: 2999, bytes: 404_865,
    ioc: true, tags: ["public", "c2"], attack: ["T1071"], evidence: ["periodic beaconing to 45.77.13.37:443"] },
];

// time_histogram: flat baseline + one exfil peak (max bytes) at index 5.
const time_histogram = Array.from({ length: 12 }, (_, i) => ({
  epoch_sec: 1_700_000_000 + i * 120,
  pkts: i === 5 ? 1850 : 120,
  bytes: i === 5 ? 1_180_000 : 16_000,
}));

/** overrides are shallow-merged at the AnalysisOutput level; to patch summary fields, spread makeOutput().summary explicitly. */
export function makeOutput(overrides: Partial<AnalysisOutput> = {}): AnalysisOutput {
  return {
    schema_version: 1, engine_version: "0.1.0",
    source_path: "captures/test.pcap", source_sha256: "deadbeef".repeat(8),
    source_bytes: 6_000_000, link_type: "EN10MB", elapsed_ms: 100,
    summary: {
      total_packets: 40_000, total_bytes: 5_700_000, captured_bytes: 5_700_000,
      total_flows: 39_000, decode_errors: 0, non_ip_frames: 0,
      proto: { tcp: 27_838, udp: 12_162, dns: 12_162, http: 11_922, tls: 15_836, other_tcp: 80, other_udp: 0, truncated: 0, non_ipv4: 0 },
      first_ts_ns: 1_700_000_000_000_000_000, last_ts_ns: 1_700_000_120_000_000_000, duration_ns: 120_000_000_000,
      unique_hosts: 96,
      top_talkers: [
        { ip: "10.13.37.7", pkts: 4017, bytes: 1_738_997, flows: 3100 },
        { ip: "45.77.13.37", pkts: 2999, bytes: 404_865, flows: 2999 },
        { ip: "10.0.0.9", pkts: 1181, bytes: 132_848, flows: 1181 },
      ],
      protocol_hierarchy: [], port_histogram: [], time_histogram, time_bucket_secs: 120,
      category_breakdown: [
        { category: "web", flows: 26_859, pkts: 27_758, bytes: 4_788_108 },
        { category: "c2", flows: 8, pkts: 2999, bytes: 404_865 },
      ],
      severity_counts: { critical: 0, high: 12, medium: 280, low: 3000, info: 35_708 },
      ip_threats,
      findings: incident1Findings,
      incidents: [
        { host: "10.13.37.7", severity: "critical", score: 89,
          title: "Multi-stage incident on 10.13.37.7",
          narrative: "10.13.37.7 swept the network, then beaconed to a C2, then exfiltrated data.",
          stages: ["Discovery", "Command & Control", "Exfiltration"],
          attack: ["T1046", "T1071", "T1048"], findings: incident1Findings },
      ],
    },
    ...overrides,
  };
}

export function makeFlows(n = 5): FlowRow[] {
  return Array.from({ length: n }, (_, i): FlowRow => ({
    flowId: i, flowIdBig: BigInt(i), captureId: 0,
    srcIp: "10.0.0.1", dstIp: i === 0 ? "185.220.101.5" : "10.0.0.2",
    srcPort: 40000 + i, dstPort: 443, proto: 6, protoLabel: "TCP",
    appProto: "TLS", appProtoSrc: "payload", sni: null, ja3: null, ja4: null,
    tlsVersion: i === 0 ? "TLS 1.2" : null, tlsCipher: i === 0 ? "TLS_AES_128_GCM_SHA256" : null,
    hassh: i === 1 ? "0df0d56bc302d51d6f1e1c1e0b3e4a5b" : null,
    bytesC2s: i === 0 ? 1_200_000 : 1000, bytesS2c: 500,
    bytesTotal: (i === 0 ? 1_200_000 : 1000) + 500,
    pkts: 10, startMs: 1_700_000_000_000 + i * 1000, endMs: 1_700_000_001_000 + i * 1000, durationMs: 1000,
    tcpFlagsC2s: 0, tcpFlagsS2c: 0, ttlMinC2s: 64, category: "web", severity: "info", threatScore: 0, ioc: false,
  }));
}

export function makePackets(over: Partial<FlowPackets> = {}): FlowPackets {
  const mk = (i: number, dir: "c2s" | "s2c", payload: string): PacketRow => ({
    index: i, tsNs: 1_700_000_000_000_000_000 + i * 1_000_000, relMs: i,
    direction: dir, wireLen: 60 + payload.length, capLen: 60 + payload.length,
    tcpFlags: 0x18, seq: i, ack: i, payloadLen: payload.length,
    payload: new TextEncoder().encode(payload), payloadTruncated: false,
  });
  return { total: 3, truncated: false, packets: [mk(0, "c2s", "GET / HTTP/1.1\r\n"), mk(1, "s2c", "HTTP/1.1 200 OK\r\n"), mk(2, "c2s", "")], ...over };
}
