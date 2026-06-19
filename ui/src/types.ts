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
  category_breakdown: CategoryBreakdownEntry[];
  severity_counts?: SeverityCounts;
  ip_threats?: IpThreat[];
}

export interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
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
  severity: string | null;
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
export type TabId = "dashboard" | "flows";

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
