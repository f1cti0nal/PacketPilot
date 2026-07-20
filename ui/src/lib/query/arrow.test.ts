import { Decimal, Utf8 } from "apache-arrow";
import { describe, expect, it } from "vitest";

import { FLOW_COLUMNS, type FlowRow } from "../../types";
import {
  FLOW_INGEST_TABLE,
  buildFlowArrowTable,
  buildFlowInsertSql,
  decodeDecimal,
  makeValueConverter,
} from "./arrow";

function makeFlowRow(overrides: Partial<FlowRow> = {}): FlowRow {
  return {
    flowId: 1,
    flowIdBig: 1n,
    captureId: 0,
    srcIp: "10.0.0.1",
    dstIp: "93.184.216.34",
    srcPort: 51000,
    dstPort: 443,
    proto: 6,
    protoLabel: "TCP",
    appProto: "https",
    appProtoSrc: "payload",
    sni: "example.com",
    ja3: null,
    ja4: null,
    ja3s: null,
    httpHost: null,
    httpUa: null,
    tlsVersion: "TLS 1.3",
    tlsCipher: null,
    hassh: null,
    hasshServer: null,
    bytesC2s: 1200,
    bytesS2c: 48000,
    bytesTotal: 49200,
    pkts: 42,
    startMs: 1752900000000,
    endMs: 1752900004500,
    durationMs: 4500,
    tcpFlagsC2s: 0x1b,
    tcpFlagsS2c: 0x1b,
    ttlMinC2s: 64,
    category: "web",
    severity: "info",
    threatScore: 0,
    ioc: false,
    ...overrides,
  };
}

describe("buildFlowArrowTable", () => {
  const rows: FlowRow[] = [
    makeFlowRow(),
    makeFlowRow({
      flowId: 2,
      flowIdBig: 2n,
      appProto: null,
      appProtoSrc: null,
      sni: null,
      tlsVersion: null,
      category: "dns",
      proto: 17,
      protoLabel: "UDP",
    }),
    makeFlowRow({
      flowId: 3,
      flowIdBig: 1n << 40n,
      srcIp: "2001:db8::1",
      severity: "critical",
      threatScore: 97,
      ioc: true,
      bytesC2s: 5_000_000_000,
      bytesTotal: 5_000_048_000,
    }),
  ];
  const table = buildFlowArrowTable(rows);

  it("has one field per canonical column, in canonical order", () => {
    expect(table.schema.fields.map((f) => f.name)).toEqual([...FLOW_COLUMNS]);
    expect(table.numRows).toBe(3);
  });

  it("maps values faithfully (strings, nulls, bigints, booleans)", () => {
    expect(table.getChild("src_ip")?.get(0)).toBe("10.0.0.1");
    expect(table.getChild("sni")?.get(0)).toBe("example.com");
    expect(table.getChild("sni")?.get(1)).toBeNull();
    expect(table.getChild("app_proto")?.get(1)).toBeNull();
    expect(table.getChild("category")?.get(1)).toBe("dns");
    expect(table.getChild("flow_id")?.get(2)).toBe(1n << 40n);
    expect(table.getChild("bytes_c2s")?.get(2)).toBe(5_000_000_000n);
    expect(table.getChild("threat_score")?.get(2)).toBe(97);
    expect(table.getChild("ioc")?.get(2)).toBe(true);
    expect(table.getChild("ioc")?.get(0)).toBe(false);
  });

  it("carries timestamps as epoch-ms 64-bit ints", () => {
    expect(table.getChild("start_ts")?.get(0)).toBe(1752900000000n);
    expect(table.getChild("end_ts")?.get(0)).toBe(1752900004500n);
  });

  it("rounds fractional ms (wasm-analyzed captures: start_ts_ns / 1e6)", () => {
    // Regression: BigInt(1700000000000.827) throws — one such row must not
    // brick the table build.
    const t = buildFlowArrowTable([
      makeFlowRow({ startMs: 1700000000000.827, endMs: 1700000001000.4 }),
    ]);
    expect(t.getChild("start_ts")?.get(0)).toBe(1700000000001n);
    expect(t.getChild("end_ts")?.get(0)).toBe(1700000001000n);
  });
});

describe("buildFlowInsertSql", () => {
  const sql = buildFlowInsertSql();

  it("is a typed INSERT from the ingest table covering every column", () => {
    expect(sql.startsWith("INSERT INTO flow SELECT ")).toBe(true);
    expect(sql.endsWith(`FROM ${FLOW_INGEST_TABLE}`)).toBe(true);
    for (const name of FLOW_COLUMNS) {
      expect(sql).toContain(` AS ${name}`);
    }
    // One select item per column.
    const selectList = sql.slice("INSERT INTO flow SELECT ".length, sql.indexOf(" FROM "));
    expect(selectList.split(", ")).toHaveLength(FLOW_COLUMNS.length);
  });

  it("converts epoch-ms ints to TIMESTAMP via epoch_ms()", () => {
    expect(sql).toContain("epoch_ms(start_ts) AS start_ts");
    expect(sql).toContain("epoch_ms(end_ts) AS end_ts");
    expect(sql).toContain("CAST(flow_id AS UBIGINT) AS flow_id");
    expect(sql).toContain("CAST(ioc AS BOOLEAN) AS ioc");
  });
});

describe("decodeDecimal / makeValueConverter", () => {
  // 128-bit little-endian 32-bit limbs (how Arrow JS hands back DuckDB
  // HUGEINT/DECIMAL values, e.g. from SUM over UBIGINT).
  const limbs = (a: number, b = 0, c = 0, d = 0) => new Uint32Array([a, b, c, d]);

  it("decodes small, large, and negative 128-bit values", () => {
    expect(decodeDecimal(limbs(10000))).toBe(10000n);
    expect(decodeDecimal(limbs(0, 1))).toBe(1n << 32n);
    expect(decodeDecimal(limbs(0, 0, 0, 0x80000000))).toBe(-(1n << 127n));
    expect(decodeDecimal(new Uint32Array([0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff]))).toBe(
      -1n,
    );
  });

  it("converter maps scale-0 decimals to BigInt and scaled ones to number", () => {
    const int = makeValueConverter(new Decimal(0, 38, 128));
    expect(int(limbs(4100))).toBe(4100n);
    expect(int(null)).toBeNull();

    const scaled = makeValueConverter(new Decimal(2, 38, 128));
    expect(scaled(limbs(123456))).toBe(1234.56);
  });

  it("non-decimal types pass values through untouched", () => {
    const conv = makeValueConverter(new Utf8());
    expect(conv("web")).toBe("web");
    expect(conv(null)).toBeNull();
  });
});
