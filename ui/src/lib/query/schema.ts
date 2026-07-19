/**
 * Browser-side flow schema for the NLQ query engine — the single UI source for
 * DuckDB column types, nullability, and per-column semantics (the semantics feed
 * the NL→SQL prompt in a later phase).
 *
 * Column NAMES and ORDER come from {@link FLOW_COLUMNS} (canonical Parquet order,
 * engine schema v10). This module only attaches DuckDB types to them; the
 * `Record<FlowColumn, …>` key type makes the compiler reject a missing or extra
 * column, and schema.test.ts guards order against the shared flow_columns.json
 * fixture (which the engine's `schema_drift` test also checks).
 */

import { FLOW_COLUMNS, type FlowColumn } from "../../types";

/**
 * Mirrors `FLOW_PARQUET_VERSION` in engine/crates/ppcap-core/src/columnar/schema.rs.
 * Bump in lockstep whenever the engine bumps (the fixture test enforces agreement).
 */
export const FLOW_SCHEMA_VERSION = 10;

/** DuckDB column types used by the browser `flow` table. */
export type DuckDbType =
  | "UBIGINT"
  | "USMALLINT"
  | "UTINYINT"
  | "VARCHAR"
  | "TIMESTAMP"
  | "BOOLEAN";

export interface FlowColumnSpec {
  type: DuckDbType;
  nullable: boolean;
  /** One-line semantics, phrased for the NL→SQL system prompt. */
  comment: string;
}

/**
 * Types/semantics per column. The engine's Parquet stores `start_ts`/`end_ts` as
 * ns-precision TIMESTAMPTZ; the browser table is built from normalized FlowRow
 * milliseconds, so plain TIMESTAMP (UTC wall clock, ms precision) is truthful here.
 */
export const FLOW_COLUMN_TYPES: Record<FlowColumn, FlowColumnSpec> = {
  flow_id: { type: "UBIGINT", nullable: false, comment: "monotonic flow id, unique per capture" },
  capture_id: { type: "UBIGINT", nullable: false, comment: "capture this flow belongs to" },
  src_ip: { type: "VARCHAR", nullable: false, comment: "initiator IP (SYN sender / first packet)" },
  dst_ip: { type: "VARCHAR", nullable: false, comment: "responder IP" },
  src_port: { type: "USMALLINT", nullable: false, comment: "initiator port; 0 for portless L4" },
  dst_port: { type: "USMALLINT", nullable: false, comment: "responder port; 0 for portless L4" },
  proto: { type: "UTINYINT", nullable: false, comment: "IANA L4 protocol number (6=TCP, 17=UDP, 1=ICMP, 58=ICMPv6, 132=SCTP)" },
  app_proto: { type: "VARCHAR", nullable: true, comment: "application protocol token, e.g. 'dns'/'https'; NULL if unknown" },
  bytes_c2s: { type: "UBIGINT", nullable: false, comment: "bytes initiator→responder (uploads)" },
  bytes_s2c: { type: "UBIGINT", nullable: false, comment: "bytes responder→initiator (downloads)" },
  pkts: { type: "UBIGINT", nullable: false, comment: "total packets, both directions" },
  start_ts: { type: "TIMESTAMP", nullable: false, comment: "first packet time, UTC" },
  end_ts: { type: "TIMESTAMP", nullable: false, comment: "last packet time, UTC" },
  tcp_flags_c2s: { type: "UTINYINT", nullable: false, comment: "OR of initiator-side TCP flags" },
  tcp_flags_s2c: { type: "UTINYINT", nullable: false, comment: "OR of responder-side TCP flags" },
  ttl_min_c2s: { type: "UTINYINT", nullable: false, comment: "minimum initiator-side IP TTL" },
  category: { type: "VARCHAR", nullable: false, comment: "traffic category token (see category list); never NULL ('unknown')" },
  app_proto_src: { type: "VARCHAR", nullable: true, comment: "how app_proto was derived: 'payload' or 'port'; NULL when neither" },
  sni: { type: "VARCHAR", nullable: true, comment: "TLS SNI host from the ClientHello" },
  ja3: { type: "VARCHAR", nullable: true, comment: "TLS JA3 client fingerprint (MD5)" },
  ja4: { type: "VARCHAR", nullable: true, comment: "TLS JA4 client fingerprint" },
  tls_version: { type: "VARCHAR", nullable: true, comment: "negotiated TLS version label" },
  tls_cipher: { type: "VARCHAR", nullable: true, comment: "negotiated TLS cipher-suite label" },
  hassh: { type: "VARCHAR", nullable: true, comment: "SSH client HASSH fingerprint (MD5)" },
  hassh_server: { type: "VARCHAR", nullable: true, comment: "SSH server HASSHServer fingerprint (MD5)" },
  ja3s: { type: "VARCHAR", nullable: true, comment: "TLS JA3S server fingerprint (MD5)" },
  http_host: { type: "VARCHAR", nullable: true, comment: "HTTP request Host header" },
  http_ua: { type: "VARCHAR", nullable: true, comment: "HTTP request User-Agent header" },
  severity: { type: "VARCHAR", nullable: false, comment: "flow severity token (see severity list); never NULL ('info')" },
  threat_score: { type: "USMALLINT", nullable: false, comment: "explainable threat score, 0–100" },
  ioc: { type: "BOOLEAN", nullable: false, comment: "true when any threat-feed indicator matched this flow" },
};

/** Engine `category` column tokens (snake_case, matches FlowCategory). */
export const FLOW_CATEGORY_TOKENS = [
  "web",
  "dns",
  "email",
  "file_transfer",
  "remote_access",
  "voip",
  "iot_ot",
  "tunnel_vpn",
  "scan",
  "c2",
  "anomalous",
  "unknown",
  "network_service",
] as const;

/** Engine `severity` column tokens (lowercase; the column is never NULL). */
export const FLOW_SEVERITY_TOKENS = [
  "critical",
  "high",
  "medium",
  "low",
  "info",
] as const;

/** `CREATE TABLE flow (…)` DDL for the in-browser DuckDB, in canonical column order. */
export const FLOW_TABLE_DDL: string = [
  "CREATE TABLE flow (",
  FLOW_COLUMNS.map((name) => {
    const spec = FLOW_COLUMN_TYPES[name];
    return `  ${name} ${spec.type}${spec.nullable ? "" : " NOT NULL"}`;
  }).join(",\n"),
  ");",
].join("\n");
