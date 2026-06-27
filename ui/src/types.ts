// ============================================================================
// PacketPilot Phase-1 — canonical types. Mirrors summary.json + flows.parquet.
// VERIFIED against real files: UInt64 -> bigint, Timestamp(ns) -> JS Date.
// ============================================================================

// ---------- summary.json (AnalysisOutput) ----------
export interface ProtoCounts {
  tcp: number;
  udp: number;
  dns: number;
  http: number;
  tls: number;
  other_tcp: number;
  other_udp: number;
  truncated: number;
  non_ipv4: number;
}

export interface TopTalker {
  ip: string;
  pkts: number;
  bytes: number;
  flows: number;
}

export interface ProtocolHierarchyNode {
  path: string;
  pkts: number;
  bytes: number;
}

export type Transport = "TCP" | "UDP";

export interface PortHistogramEntry {
  port: number;
  transport: Transport;
  pkts: number;
  bytes: number;
}

export interface TimeHistogramEntry {
  epoch_sec: number;
  pkts: number;
  bytes: number;
}

/** One packet-size-distribution bucket; the top bucket is open-ended (max === 4294967295). */
export interface SizeBucket {
  label: string;
  min: number;
  max: number;
  pkts: number;
}

/** One TTL/hop-limit-distribution row: a distinct observed TTL and its packet count. */
export interface TtlCount {
  ttl: number;
  pkts: number;
}

/** summary.json uses KEBAB-case tokens. */
export type SummaryCategory =
  | "web"
  | "dns"
  | "email"
  | "file-transfer"
  | "remote-access"
  | "voip"
  | "iot-ot"
  | "tunnel-vpn"
  | "scan"
  | "c2"
  | "anomalous"
  | "unknown";

export interface CategoryBreakdownEntry {
  category: SummaryCategory;
  flows: number;
  pkts: number;
  bytes: number;
}

export interface Summary {
  total_packets: number;
  total_bytes: number;
  captured_bytes: number;
  total_flows: number;
  decode_errors: number;
  non_ip_frames: number;
  proto: ProtoCounts;
  first_ts_ns: number; // i64 ns, safe in f64 for display
  last_ts_ns: number;
  duration_ns: number;
  unique_hosts: number;
  top_talkers: TopTalker[];
  protocol_hierarchy: ProtocolHierarchyNode[];
  port_histogram: PortHistogramEntry[];
  time_histogram: TimeHistogramEntry[];
  /**
   * Width, in seconds, of each {@link TimeHistogramEntry} bucket (>= 1). 1 = per-second; widens
   * to a "nice" interval for long captures so the series stays bounded. Absent (=> treat as 1)
   * in summaries written before adaptive bucketing.
   */
  time_bucket_secs?: number;
  /** Packet-size distribution across fixed wire-length buckets; absent in older summaries. */
  size_distribution?: SizeBucket[];
  /** TTL/hop-limit distribution ranked by packet count; absent in older summaries. */
  ttl_distribution?: TtlCount[];
  category_breakdown: CategoryBreakdownEntry[];
  severity_counts?: SeverityCounts;
  ip_threats?: IpThreat[];
  domain_threats?: DomainThreat[];
  /** Top HTTP request Host headers by flow count; absent in older summaries. */
  http_hosts?: HttpHostCount[];
  /** Top HTTP request User-Agent headers by flow count; absent in older summaries. */
  user_agents?: UserAgentCount[];
  /** Passive DNS: resolved-IP → domain mappings from DNS answers; absent in older summaries. */
  resolved_ips?: ResolvedDomain[];
  /** L2 host identity: IP → MAC bindings observed via ARP; absent in older summaries. */
  arp_hosts?: ArpHost[];
  /** DHCP passive identity: client MAC → hostname / vendor class; absent in older summaries. */
  dhcp_hosts?: DhcpHost[];
  /** Downloads overview: notable file classes served over HTTP; absent in older summaries. */
  downloads?: DownloadEvent[];
  /** Encrypted DNS (DoH/DoT): hosts whose DNS is hidden from passive DNS; absent in older summaries. */
  encrypted_dns?: EncryptedDnsHost[];
  /** Carved HTTP downloads with their SHA-256 (IOC) + known-bad flag; absent in older summaries. */
  carved_files?: CarvedFile[];
  /** Cross-flow behavioral findings (beaconing, sweeps, exfil); absent in older summaries. */
  findings?: Finding[];
  /** Findings correlated into per-host incidents; absent in older summaries. */
  incidents?: Incident[];
}

export interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export type RepStatus =
  | "malicious" | "benign" | "clean" | "unknown" | "notfound" | "unavailable";

export interface ReputationVerdict {
  source: string;            // "abuseipdb" | "greynoise" | "virustotal"
  status: RepStatus;
  malicious: boolean;
  score: number | null;      // 0..=100; 0 when clean; null when unknown/notfound/unavailable
  tags: string[];
  link: string | null;
  fetched_at: number;        // unix seconds
}

export interface FingerprintHit {
  ja3: string | null;
  ja4: string | null;
  label: string;
}

/** One additive scoring contribution — mirrors engine ScoreTerm. */
export interface ScoreTerm {
  label: string;
  points: number;
}

export interface IpThreat {
  ip: string;
  ip_class: string;
  severity: Severity;
  score: number;
  flows: number;
  bytes: number;
  ioc: boolean;
  tags: string[];
  attack: string[];
  evidence: string[];
  reputation?: ReputationVerdict[];
  fingerprints?: FingerprintHit[];
  score_terms?: ScoreTerm[];
}

export interface DomainThreat {
  host: string;
  flows: number;
  bytes: number;
  reputation?: ReputationVerdict[];
}

/** One HTTP request-Host rollup row: the host and how many flows carried it. */
export interface HttpHostCount {
  host: string;
  flows: number;
}

/** One HTTP request-User-Agent rollup row: the UA and how many flows carried it. */
export interface UserAgentCount {
  user_agent: string;
  flows: number;
}

/** One passive-DNS rollup row: a resolved IP, the domain a DNS answer mapped it from, and count. */
export interface ResolvedDomain {
  ip: string;
  domain: string;
  resolutions: number;
}

/** One L2 host: an IP and the MAC that claimed it via ARP (the OUI identifies the device vendor). */
export interface ArpHost {
  ip: string;
  mac: string;
}

/** DHCP passive identity: a client MAC and its self-reported hostname / vendor class. */
export interface DhcpHost {
  mac: string;
  hostname?: string | null;
  vendor_class?: string | null;
}

/** One encrypted-DNS row: a client host resolving via DoH/DoT, the resolver, and flow count. */
export interface EncryptedDnsHost {
  host: string;
  resolver: string;
  flows: number;
}

/** One carved HTTP download: client, server, the body's SHA-256 (IOC), size, and known-bad flag. */
export interface CarvedFile {
  client: string;
  server: string;
  sha256: string;
  size: number;
  known_bad: boolean;
}

/** One downloads-overview row: a client that received a notable file class over HTTP from a server. */
export interface DownloadEvent {
  client: string;
  server: string;
  /** "executable" | "script" | "installer" | "archive". */
  kind: string;
  count: number;
}

/** Cross-flow behavioral detection kind (engine `FindingKind`, snake-case wire token). */
export type FindingKind =
  | "beacon"
  | "host_sweep"
  | "brute_force"
  | "cleartext_creds"
  | "pii_exposure"
  | "lateral_movement"
  | "data_exfil"
  | "dns_tunnel"
  | "rule_match"
  | "tls_cert_health"
  | "weak_tls"
  | "icmp_tunnel"
  | "dga"
  | "port_scan"
  | "arp_spoof"
  | "syn_flood"
  | "suspicious_ua"
  | "disguised_download"
  | "cryptomining"
  | "malware_download"
  | "exposed_remote_access";

/**
 * A cross-flow behavioral finding (engine `detect` stage). Unlike a per-IP threat card, a
 * finding is a *named* conclusion across many flows ("host X is beaconing to Y") that can reach
 * High/Critical from behavior alone — no threat-feed hit required.
 */
export interface Finding {
  kind: FindingKind;
  severity: Severity;
  score: number;
  title: string;
  src_ip: string;
  dst_ip: string | null;
  dst_port: number | null;
  attack: string[];
  evidence: string[];
  /** Beacon period in nanoseconds; null for non-beacon findings. */
  interval_ns: number | null;
  /** Beacon jitter (coefficient of variation); null otherwise. */
  jitter_cv: number | null;
  /** Contributing contact / connection count. */
  contacts: number | null;
}

/**
 * A per-host incident: one or more findings correlated into a single ranked story, ordered
 * along the kill chain. A host that did two or more distinct stages is escalated above any
 * single finding's severity.
 */
export interface Incident {
  host: string;
  severity: Severity;
  score: number;
  title: string;
  narrative: string;
  /** Kill-chain stage labels, in order, e.g. ["Discovery", "Command & Control"]. */
  stages: string[];
  attack: string[];
  /** Contributing findings, ordered by kill-chain stage. */
  findings: Finding[];
}

export interface AnalysisOutput {
  schema_version: number;
  engine_version: string;
  source_path: string;
  source_sha256: string;
  source_bytes: number;
  link_type: string;
  summary: Summary;
  flows_parquet_path?: string; // present in sample; ignored at runtime
  elapsed_ms?: number;
}

// ---------- flows.parquet ----------
export const FLOW_COLUMNS = [
  "flow_id",
  "capture_id",
  "src_ip",
  "dst_ip",
  "src_port",
  "dst_port",
  "proto",
  "app_proto",
  "bytes_c2s",
  "bytes_s2c",
  "pkts",
  "start_ts",
  "end_ts",
  "tcp_flags_c2s",
  "tcp_flags_s2c",
  "ttl_min_c2s",
  "category",
  "app_proto_src",
  "sni",
  "severity",
  "threat_score",
  "ioc",
] as const;
export type FlowColumn = (typeof FLOW_COLUMNS)[number];

/** parquet `category` column uses SNAKE-case tokens (verified: "scan","web",...). */
export type FlowCategory =
  | "web"
  | "dns"
  | "email"
  | "file_transfer"
  | "remote_access"
  | "voip"
  | "iot_ot"
  | "tunnel_vpn"
  | "scan"
  | "c2"
  | "anomalous"
  | "unknown";

/**
 * RAW row exactly as hyparquet.parquetReadObjects returns it. VERIFIED:
 *   UInt64 -> bigint | UInt16/UInt8 -> number | Utf8 -> string|null
 *   Timestamp(ns,UTC) -> JS Date (sub-ms precision lost; fine for triage).
 */
export interface RawFlowRow {
  flow_id: bigint;
  capture_id: bigint;
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  proto: number;
  app_proto: string | null;
  bytes_c2s: bigint;
  bytes_s2c: bigint;
  pkts: bigint;
  start_ts: Date;
  end_ts: Date;
  tcp_flags_c2s: number;
  tcp_flags_s2c: number;
  ttl_min_c2s: number;
  category: string;
  app_proto_src: string | null;
  sni: string | null;
  ja3: string | null;
  ja4: string | null;
  ja3s: string | null;
  http_host: string | null;
  http_ua: string | null;
  tls_version: string | null;
  tls_cipher: string | null;
  hassh: string | null;
  hassh_server: string | null;
  severity: string | null;
  threat_score: number;
  ioc: boolean;
}

/**
 * One flow row as returned by the WebAssembly engine (`ppcap-wasm`). Mirrors {@link RawFlowRow}
 * but in JS-native types: 64-bit ints arrive as plain `number`s and timestamps as nanoseconds
 * since the epoch (the parquet path uses `bigint`/`Date`). `serde-wasm-bindgen` emits absent
 * `Option`s as `undefined`, so nullable fields are `... | null | undefined`.
 */
export interface WasmFlow {
  flow_id: number;
  capture_id: number;
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  proto: number;
  app_proto: string | null;
  bytes_c2s: number;
  bytes_s2c: number;
  pkts: number;
  start_ts_ns: number;
  end_ts_ns: number;
  tcp_flags_c2s: number;
  tcp_flags_s2c: number;
  ttl_min_c2s: number;
  category: string;
  app_proto_src: string | null;
  sni: string | null;
  ja3: string | null;
  ja4: string | null;
  ja3s: string | null;
  http_host: string | null;
  http_ua: string | null;
  tls_version: string | null;
  tls_cipher: string | null;
  hassh: string | null;
  hassh_server: string | null;
  severity: string;
  threat_score: number;
  ioc: boolean;
}

export type Severity =
  | "critical"
  | "high"
  | "medium"
  | "low"
  | "info"
  | "none";

/** Normalized UI row: bigint->number, Date->ms, derived fields precomputed once. */
export interface FlowRow {
  flowId: number; // Number(flow_id) — safe, ids < 2^53
  flowIdBig: bigint; // exact identity key
  captureId: number;
  srcIp: string;
  dstIp: string;
  srcPort: number;
  dstPort: number;
  proto: number;
  protoLabel: string; // "TCP"/"UDP"/"ICMP"/"ICMPv6"/"SCTP"/`IP/${n}`
  appProto: string | null;
  appProtoSrc: string | null; // "payload" | "port" | null — how appProto was derived
  sni: string | null; // TLS SNI host from the ClientHello, if captured
  ja3: string | null; // TLS JA3 fingerprint, if captured
  ja4: string | null; // TLS JA4 fingerprint, if captured
  ja3s: string | null; // TLS JA3S server fingerprint from the ServerHello, if captured
  httpHost: string | null; // HTTP request Host header, if captured
  httpUa: string | null; // HTTP request User-Agent header, if captured
  tlsVersion: string | null; // negotiated TLS version label from the ServerHello, if captured
  tlsCipher: string | null; // negotiated TLS cipher-suite label, if captured
  hassh: string | null; // SSH client HASSH (MD5) fingerprint, if captured
  hasshServer: string | null; // SSH server HASSHServer (MD5) fingerprint, if captured
  bytesC2s: number;
  bytesS2c: number;
  bytesTotal: number; // derived
  pkts: number;
  startMs: number; // start_ts.getTime()
  endMs: number;
  durationMs: number; // endMs - startMs
  tcpFlagsC2s: number;
  tcpFlagsS2c: number;
  ttlMinC2s: number;
  category: FlowCategory; // normalized snake-case
  severity: Severity; // engine-sourced (column) with category heuristic fallback
  threatScore: number; // engine threat_score 0-100
  ioc: boolean; // engine IOC flag
}

// ---------- load state ----------
export type TabId = "dashboard" | "flows" | "findings" | "recent" | "compare";

/** How a capture entered the app — drives whether it can be re-analyzed in place. */
export type RecentOrigin = "native" | "wasm" | "upload" | "sample";

/**
 * A persisted "last opened capture" record. The cached {@link AnalysisOutput} lets the
 * Recent tab render a card — and restore the dashboard — instantly, with no re-analysis.
 * Flows are cached separately (IndexedDB, keyed by {@link id}) because they are large.
 */
export interface RecentEntry {
  /** Stable identity: source SHA-256 when known, else a name+size+time digest. */
  id: string;
  /** Display name (basename of the source path / dropped file name). */
  name: string;
  /** Absolute file path — present for native (desktop) loads; enables in-place re-analyze. */
  path?: string;
  /** On-disk source size in bytes. */
  sizeBytes: number;
  /** Lowercase hex SHA-256 of the source, when computed. */
  sha256?: string;
  /** When this capture was last analyzed (epoch ms). */
  analyzedAt: number;
  /** Engine version that produced the cached summary. */
  engineVersion: string;
  /** Entry provenance. */
  origin: RecentOrigin;
  /** Cached capture-wide stats — enough to render the full dashboard offline. */
  summary: AnalysisOutput;
  /** Number of flows in the capture (shown on the card even if flows aren't cached). */
  flowCount: number;
  /** Whether the normalized flows are cached in IndexedDB under {@link id}. */
  flowsCached: boolean;
}

// ---------- per-flow packet extraction (wire contract, snake_case) ----------

/** One extracted packet as returned by the `extract_flow_packets` Tauri command. */
export interface WirePacket {
  index: number;
  ts_ns: number;
  direction: "c2s" | "s2c";
  wire_len: number;
  cap_len: number;
  tcp_flags: number;
  seq: number | null;
  ack: number | null;
  payload_len: number;
  payload_b64: string;
  payload_truncated: boolean;
}

/** The result of `extract_flow_packets`: bounded packet list for one flow. */
export interface WireFlowPackets {
  total: number;
  truncated: boolean;
  packets: WirePacket[];
}

export interface PacketRow {
  index: number; tsNs: number; relMs: number;
  direction: "c2s" | "s2c"; wireLen: number; capLen: number;
  tcpFlags: number; seq: number | null; ack: number | null;
  payloadLen: number; payload: Uint8Array; payloadTruncated: boolean;
}
export interface FlowPackets { total: number; truncated: boolean; packets: PacketRow[]; }

/** Active capture source — drives whether packet drill-down is available and which backend serves it. */
export type ActiveSource = { kind: "path"; path: string } | { kind: "bytes"; bytes: ArrayBuffer } | null;

/** Query passed to carve_pcap / carve_pcap_to — either a host (IP) or a 5-tuple flow, plus a time window. */
export interface CarveQuery {
  host?: string;
  src_ip?: string;
  dst_ip?: string;
  src_port?: number;
  dst_port?: number;
  proto?: number;
  start_ns: number;
  end_ns: number;
}

export interface SummaryState {
  status: "idle" | "loading" | "ready" | "error";
  data?: AnalysisOutput;
  error?: string;
}

export interface FlowsState {
  status: "idle" | "loading" | "ready" | "error";
  rows: FlowRow[];
  error?: string;
}

export interface AiConfig { enabled: boolean; baseUrl: string; model: string; apiKey: string; }

export interface AiSummaryEntry { text: string; model: string; cached_at: number; }
