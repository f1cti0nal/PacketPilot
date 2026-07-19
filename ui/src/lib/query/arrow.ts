/**
 * FlowRow[] → Arrow ingestion for the in-browser DuckDB `flow` table.
 *
 * The normalized in-memory `FlowRow[]` is the one flow representation shared by
 * all ingest paths (sample Parquet, WASM-analyzed pcaps, desktop, IndexedDB
 * restore), so it is the uniform source here. Columns are built column-major
 * into typed arrays and shipped as one Arrow table named `flow_ingest`; the
 * engine then INSERTs it into the DDL-typed `flow` table with explicit casts
 * (see {@link buildFlowInsertSql}), so the queryable table's types always match
 * FLOW_TABLE_DDL regardless of Arrow type inference.
 *
 * Timestamps travel as epoch-millisecond BIGINTs (`FlowRow.startMs`/`endMs` —
 * ns precision was already dropped by the existing normalization) and become
 * TIMESTAMP via `epoch_ms()` in the insert.
 */

import { Bool, DataType, Table, Utf8, makeVector, vectorFromArray } from "apache-arrow";

import { FLOW_COLUMNS, type FlowRow } from "../../types";
import { FLOW_COLUMN_TYPES } from "./schema";

/** Staging table the Arrow data lands in before the typed INSERT into `flow`. */
export const FLOW_INGEST_TABLE = "flow_ingest";

export function buildFlowArrowTable(rows: FlowRow[]): Table {
  const n = rows.length;

  const flowId = new BigUint64Array(n);
  const captureId = new BigUint64Array(n);
  const srcIp = new Array<string>(n);
  const dstIp = new Array<string>(n);
  const srcPort = new Uint16Array(n);
  const dstPort = new Uint16Array(n);
  const proto = new Uint8Array(n);
  const appProto = new Array<string | null>(n);
  const bytesC2s = new BigUint64Array(n);
  const bytesS2c = new BigUint64Array(n);
  const pkts = new BigUint64Array(n);
  const startTs = new BigInt64Array(n);
  const endTs = new BigInt64Array(n);
  const tcpFlagsC2s = new Uint8Array(n);
  const tcpFlagsS2c = new Uint8Array(n);
  const ttlMinC2s = new Uint8Array(n);
  const category = new Array<string>(n);
  const appProtoSrc = new Array<string | null>(n);
  const sni = new Array<string | null>(n);
  const ja3 = new Array<string | null>(n);
  const ja4 = new Array<string | null>(n);
  const tlsVersion = new Array<string | null>(n);
  const tlsCipher = new Array<string | null>(n);
  const hassh = new Array<string | null>(n);
  const hasshServer = new Array<string | null>(n);
  const ja3s = new Array<string | null>(n);
  const httpHost = new Array<string | null>(n);
  const httpUa = new Array<string | null>(n);
  const severity = new Array<string>(n);
  const threatScore = new Uint16Array(n);
  const ioc = new Array<boolean>(n);

  for (let i = 0; i < n; i++) {
    const r = rows[i];
    flowId[i] = r.flowIdBig;
    captureId[i] = BigInt(r.captureId);
    srcIp[i] = r.srcIp;
    dstIp[i] = r.dstIp;
    srcPort[i] = r.srcPort;
    dstPort[i] = r.dstPort;
    proto[i] = r.proto;
    appProto[i] = r.appProto;
    bytesC2s[i] = BigInt(r.bytesC2s);
    bytesS2c[i] = BigInt(r.bytesS2c);
    pkts[i] = BigInt(r.pkts);
    startTs[i] = BigInt(r.startMs);
    endTs[i] = BigInt(r.endMs);
    tcpFlagsC2s[i] = r.tcpFlagsC2s;
    tcpFlagsS2c[i] = r.tcpFlagsS2c;
    ttlMinC2s[i] = r.ttlMinC2s;
    category[i] = r.category;
    appProtoSrc[i] = r.appProtoSrc;
    sni[i] = r.sni;
    ja3[i] = r.ja3;
    ja4[i] = r.ja4;
    tlsVersion[i] = r.tlsVersion;
    tlsCipher[i] = r.tlsCipher;
    hassh[i] = r.hassh;
    hasshServer[i] = r.hasshServer;
    ja3s[i] = r.ja3s;
    httpHost[i] = r.httpHost;
    httpUa[i] = r.httpUa;
    severity[i] = r.severity;
    threatScore[i] = r.threatScore;
    ioc[i] = r.ioc;
  }

  const utf8 = () => new Utf8();
  // Key order == canonical column order (guarded by arrow.test.ts).
  return new Table({
    flow_id: makeVector(flowId),
    capture_id: makeVector(captureId),
    src_ip: vectorFromArray(srcIp, utf8()),
    dst_ip: vectorFromArray(dstIp, utf8()),
    src_port: makeVector(srcPort),
    dst_port: makeVector(dstPort),
    proto: makeVector(proto),
    app_proto: vectorFromArray(appProto, utf8()),
    bytes_c2s: makeVector(bytesC2s),
    bytes_s2c: makeVector(bytesS2c),
    pkts: makeVector(pkts),
    start_ts: makeVector(startTs),
    end_ts: makeVector(endTs),
    tcp_flags_c2s: makeVector(tcpFlagsC2s),
    tcp_flags_s2c: makeVector(tcpFlagsS2c),
    ttl_min_c2s: makeVector(ttlMinC2s),
    category: vectorFromArray(category, utf8()),
    app_proto_src: vectorFromArray(appProtoSrc, utf8()),
    sni: vectorFromArray(sni, utf8()),
    ja3: vectorFromArray(ja3, utf8()),
    ja4: vectorFromArray(ja4, utf8()),
    tls_version: vectorFromArray(tlsVersion, utf8()),
    tls_cipher: vectorFromArray(tlsCipher, utf8()),
    hassh: vectorFromArray(hassh, utf8()),
    hassh_server: vectorFromArray(hasshServer, utf8()),
    ja3s: vectorFromArray(ja3s, utf8()),
    http_host: vectorFromArray(httpHost, utf8()),
    http_ua: vectorFromArray(httpUa, utf8()),
    severity: vectorFromArray(severity, utf8()),
    threat_score: makeVector(threatScore),
    ioc: vectorFromArray(ioc, new Bool()),
  });
}

/**
 * `INSERT INTO flow SELECT … FROM flow_ingest` with an explicit cast per column
 * (epoch-ms BIGINT → TIMESTAMP via `epoch_ms()`), generated from the schema
 * spec so the SELECT list can never drift from FLOW_COLUMNS.
 */
/**
 * Decode an Arrow decimal value (little-endian 32-bit limbs, two's-complement)
 * into a BigInt of the unscaled digits. DuckDB surfaces HUGEINT results (e.g.
 * SUM over UBIGINT) as Decimal128, which Arrow JS hands back as raw limbs.
 */
export function decodeDecimal(limbs: Uint32Array): bigint {
  let x = 0n;
  for (let i = limbs.length - 1; i >= 0; i--) {
    x = (x << 32n) | BigInt(limbs[i]);
  }
  const bits = BigInt(limbs.length * 32);
  if (x >= 1n << (bits - 1n)) x -= 1n << bits;
  return x;
}

/**
 * Per-column result-value converter: decimals become BigInt (scale 0) or a
 * scaled number; everything else passes through as Arrow returned it.
 */
export function makeValueConverter(type: DataType): (v: unknown) => unknown {
  if (DataType.isDecimal(type)) {
    const scale = type.scale;
    return (v) => {
      if (v == null) return null;
      const digits = decodeDecimal(v as Uint32Array);
      return scale === 0 ? digits : Number(digits) / 10 ** scale;
    };
  }
  return (v) => v;
}

export function buildFlowInsertSql(): string {
  const cols = FLOW_COLUMNS.map((name) => {
    const spec = FLOW_COLUMN_TYPES[name];
    return spec.type === "TIMESTAMP"
      ? `epoch_ms(${name}) AS ${name}`
      : `CAST(${name} AS ${spec.type}) AS ${name}`;
  });
  return `INSERT INTO flow SELECT ${cols.join(", ")} FROM ${FLOW_INGEST_TABLE}`;
}
