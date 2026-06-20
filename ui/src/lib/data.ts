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
