import {
  asyncBufferFromUrl,
  cachedAsyncBuffer,
  parquetReadObjects,
  type AsyncBuffer,
} from "hyparquet";
import type {
  AnalysisOutput,
  RawFlowRow,
  WasmFlow,
  FlowRow,
  FlowCategory,
  Severity,
} from "../types";
import { severityForCategory, normCategory } from "./severity";

// ---- summary ----
export async function loadSummary(
  url = "/sample/summary.json",
): Promise<AnalysisOutput> {
  const res = await fetch(url, { cache: "no-cache" });
  if (!res.ok) throw new Error(`summary.json ${res.status} ${res.statusText}`);
  return (await res.json()) as AnalysisOutput;
}

// ---- flows ----
const PROTO_NAMES: Record<number, string> = {
  1: "ICMP",
  6: "TCP",
  17: "UDP",
  58: "ICMPv6",
  132: "SCTP",
};
const protoName = (p: number): string => PROTO_NAMES[p] ?? `IP/${p}`;

async function toAsyncBuffer(
  src: string | ArrayBuffer | AsyncBuffer,
): Promise<AsyncBuffer> {
  if (typeof src === "string")
    return cachedAsyncBuffer(await asyncBufferFromUrl({ url: src }));
  if (src instanceof ArrayBuffer)
    return { byteLength: src.byteLength, slice: (s, e) => src.slice(s, e) };
  return src;
}

/**
 * Loads ALL ~120k rows in one pass. Snappy is built into hyparquet — NO
 * `compressors` option. utf8 defaults true. Returns normalized FlowRow[].
 */
export async function loadFlows(
  src: string | ArrayBuffer | AsyncBuffer = "/sample/flows.parquet",
): Promise<FlowRow[]> {
  const file = await toAsyncBuffer(src);
  const raw = (await parquetReadObjects({
    file,
    rowFormat: "object",
  })) as unknown as RawFlowRow[];
  return raw.map(normalizeFlow);
}

/**
 * True if `ip` is a routable/external address worth a reputation lookup.
 * Mirrors the engine's `IpClass::is_external` (Public + CGNAT) — engine-computed `ip_class`
 * is authoritative; this is a TS-side backstop for flows where `ip_class` isn't available.
 */
export function isPublicIp(ip: string): boolean {
  const m = ip.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (!m) return ip.includes(":") ? !/^(fe80|::1|fc|fd)/i.test(ip) : false; // coarse IPv6
  const [a, b, c] = [Number(m[1]), Number(m[2]), Number(m[3])];
  if (a === 10 || a === 127 || a === 0) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && b === 168) return false;
  if (a === 169 && b === 254) return false;
  // CGNAT (100.64/10, RFC6598) is carrier space = a real off-network peer -> external (matches engine).
  if (a >= 224) return false;                          // multicast/reserved
  // RFC 5737 documentation ranges (engine classifies these as Documentation = non-external)
  if (a === 192 && b === 0 && c === 2) return false;   // 192.0.2.0/24
  if (a === 198 && b === 51 && c === 100) return false; // 198.51.100.0/24
  if (a === 203 && b === 0 && c === 113) return false;  // 203.0.113.0/24
  // IETF protocol assignments (RFC 6890)
  if (a === 192 && b === 0 && c === 0) return false;   // 192.0.0.0/24
  return true;
}

export function normalizeFlow(r: RawFlowRow): FlowRow {
  const bytesC2s = Number(r.bytes_c2s);
  const bytesS2c = Number(r.bytes_s2c);
  const startMs = r.start_ts.getTime();
  const endMs = r.end_ts.getTime();
  const category = normCategory(r.category) as FlowCategory;
  return {
    flowId: Number(r.flow_id),
    flowIdBig: r.flow_id,
    captureId: Number(r.capture_id),
    srcIp: r.src_ip,
    dstIp: r.dst_ip,
    srcPort: r.src_port,
    dstPort: r.dst_port,
    proto: r.proto,
    protoLabel: protoName(r.proto),
    appProto: r.app_proto,
    appProtoSrc: r.app_proto_src,
    sni: r.sni,
    ja3: r.ja3,
    ja4: r.ja4,
    ja3s: r.ja3s,
    httpHost: r.http_host,
    httpUa: r.http_ua,
    tlsVersion: r.tls_version,
    tlsCipher: r.tls_cipher,
    hassh: r.hassh,
    hasshServer: r.hassh_server,
    bytesC2s,
    bytesS2c,
    bytesTotal: bytesC2s + bytesS2c,
    pkts: Number(r.pkts),
    startMs,
    endMs,
    durationMs: endMs - startMs,
    tcpFlagsC2s: r.tcp_flags_c2s,
    tcpFlagsS2c: r.tcp_flags_s2c,
    ttlMinC2s: r.ttl_min_c2s,
    category,
    severity: ((r.severity as Severity) || severityForCategory(category)),
    threatScore: r.threat_score ?? 0,
    ioc: !!r.ioc,
  };
}

/**
 * Normalize a {@link WasmFlow} row (from the in-browser WebAssembly engine) into a
 * {@link FlowRow}. Same shape as {@link normalizeFlow}, but the source ints are plain numbers
 * and timestamps are epoch nanoseconds (so we divide to ms instead of reading a `Date`).
 */
export function flowRowFromWasm(r: WasmFlow): FlowRow {
  const bytesC2s = Number(r.bytes_c2s);
  const bytesS2c = Number(r.bytes_s2c);
  const startMs = r.start_ts_ns / 1e6;
  const endMs = r.end_ts_ns / 1e6;
  const category = normCategory(r.category) as FlowCategory;
  return {
    flowId: r.flow_id,
    flowIdBig: BigInt(r.flow_id),
    captureId: r.capture_id,
    srcIp: r.src_ip,
    dstIp: r.dst_ip,
    srcPort: r.src_port,
    dstPort: r.dst_port,
    proto: r.proto,
    protoLabel: protoName(r.proto),
    appProto: r.app_proto ?? null,
    appProtoSrc: r.app_proto_src ?? null,
    sni: r.sni ?? null,
    ja3: r.ja3 ?? null,
    ja4: r.ja4 ?? null,
    ja3s: r.ja3s ?? null,
    httpHost: r.http_host ?? null,
    httpUa: r.http_ua ?? null,
    tlsVersion: r.tls_version ?? null,
    tlsCipher: r.tls_cipher ?? null,
    hassh: r.hassh ?? null,
    hasshServer: r.hassh_server ?? null,
    bytesC2s,
    bytesS2c,
    bytesTotal: bytesC2s + bytesS2c,
    pkts: Number(r.pkts),
    startMs,
    endMs,
    durationMs: endMs - startMs,
    tcpFlagsC2s: r.tcp_flags_c2s,
    tcpFlagsS2c: r.tcp_flags_s2c,
    ttlMinC2s: r.ttl_min_c2s,
    category,
    severity: ((r.severity as Severity) || severityForCategory(category)),
    threatScore: r.threat_score ?? 0,
    ioc: !!r.ioc,
  };
}
