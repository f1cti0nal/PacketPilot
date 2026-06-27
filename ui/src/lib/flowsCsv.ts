// Serialize normalized flow rows to CSV for the Flows view's "Export filtered flows" action.
// Pure and dependency-free so it stays unit-testable.
import type { FlowRow } from "../types";

const COLUMNS: { header: string; get: (r: FlowRow) => string | number }[] = [
  { header: "flow_id", get: (r) => r.flowId },
  { header: "src_ip", get: (r) => r.srcIp },
  { header: "src_port", get: (r) => r.srcPort },
  { header: "dst_ip", get: (r) => r.dstIp },
  { header: "dst_port", get: (r) => r.dstPort },
  { header: "proto", get: (r) => r.protoLabel },
  { header: "app_proto", get: (r) => r.appProto ?? "" },
  { header: "category", get: (r) => r.category },
  { header: "severity", get: (r) => r.severity },
  { header: "threat_score", get: (r) => r.threatScore },
  { header: "ioc", get: (r) => (r.ioc ? "true" : "false") },
  { header: "bytes_c2s", get: (r) => r.bytesC2s },
  { header: "bytes_s2c", get: (r) => r.bytesS2c },
  { header: "bytes_total", get: (r) => r.bytesTotal },
  { header: "pkts", get: (r) => r.pkts },
  { header: "start", get: (r) => new Date(r.startMs).toISOString() },
  { header: "end", get: (r) => new Date(r.endMs).toISOString() },
  { header: "duration_ms", get: (r) => r.durationMs },
  { header: "sni", get: (r) => r.sni ?? "" },
  { header: "http_host", get: (r) => r.httpHost ?? "" },
  { header: "http_ua", get: (r) => r.httpUa ?? "" },
  { header: "ja3", get: (r) => r.ja3 ?? "" },
  { header: "ja4", get: (r) => r.ja4 ?? "" },
  { header: "ja3s", get: (r) => r.ja3s ?? "" },
  { header: "tls_version", get: (r) => r.tlsVersion ?? "" },
  { header: "tls_cipher", get: (r) => r.tlsCipher ?? "" },
  { header: "hassh", get: (r) => r.hassh ?? "" },
  { header: "hassh_server", get: (r) => r.hasshServer ?? "" },
];

/** RFC-4180 field escape: quote-wrap and double internal quotes when the value holds a comma, quote, or newline. */
function escapeCsv(value: string | number): string {
  const s = String(value);
  return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

/** Serialize flows to CSV (header row + one row per flow), CRLF-terminated. */
export function flowsToCsv(rows: FlowRow[]): string {
  const header = COLUMNS.map((c) => c.header).join(",");
  const lines = rows.map((r) => COLUMNS.map((c) => escapeCsv(c.get(r))).join(","));
  return [header, ...lines].join("\r\n");
}
