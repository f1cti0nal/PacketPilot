import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import type { RawFlowRow, WasmFlow } from "../types";
import { normalizeFlow, flowRowFromWasm, loadSummary } from "./data";
import { makeOutput } from "../test/fixtures";

const startDate = new Date(1_700_000_000_000);
const endDate = new Date(1_700_000_001_000);

const rawRow: RawFlowRow = {
  flow_id: BigInt(42),
  capture_id: BigInt(1),
  src_ip: "10.0.0.1",
  dst_ip: "185.220.101.5",
  src_port: 40000,
  dst_port: 443,
  proto: 6,
  app_proto: "TLS",
  bytes_c2s: BigInt(1_200_000),
  bytes_s2c: BigInt(500),
  pkts: BigInt(10),
  start_ts: startDate,
  end_ts: endDate,
  tcp_flags_c2s: 0,
  tcp_flags_s2c: 0,
  ttl_min_c2s: 64,
  category: "web",
  app_proto_src: "payload",
  sni: null,
  severity: null,
  threat_score: 0,
  ioc: false,
};

describe("loadSummary", () => {
  const originalFetch = globalThis.fetch;

  beforeEach(() => {
    globalThis.fetch = vi.fn();
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it("returns parsed JSON when fetch succeeds", async () => {
    const output = makeOutput();
    (globalThis.fetch as ReturnType<typeof vi.fn>).mockResolvedValue({
      ok: true,
      json: async () => output,
    });
    const result = await loadSummary("/fake/summary.json");
    expect(result.schema_version).toBe(1);
    expect(result.source_path).toBe("captures/test.pcap");
  });

  it("throws when the response is not ok", async () => {
    (globalThis.fetch as ReturnType<typeof vi.fn>).mockResolvedValue({
      ok: false,
      status: 404,
      statusText: "Not Found",
    });
    await expect(loadSummary("/fake/summary.json")).rejects.toThrow("404");
  });
});

describe("normalizeFlow", () => {
  const row = normalizeFlow(rawRow);

  it("flowId and captureId are numbers", () => {
    expect(typeof row.flowId).toBe("number");
    expect(row.flowId).toBe(42);
    expect(typeof row.captureId).toBe("number");
    expect(row.captureId).toBe(1);
  });

  it("bytesTotal === bytesC2s + bytesS2c", () => {
    expect(row.bytesTotal).toBe(row.bytesC2s + row.bytesS2c);
    expect(row.bytesTotal).toBe(1_200_500);
  });

  it("durationMs === endMs - startMs", () => {
    expect(row.durationMs).toBe(row.endMs - row.startMs);
    expect(row.durationMs).toBe(1000);
  });

  it("protoLabel is TCP for proto 6", () => {
    expect(row.protoLabel).toBe("TCP");
  });

  it("severity falls back via category when column is null", () => {
    // severity column is null, category is "web" -> severityForCategory("web") = "info"
    expect(row.severity).toBe("info");
  });
});

describe("flowRowFromWasm", () => {
  const wasmRow: WasmFlow = {
    flow_id: 99,
    capture_id: 2,
    src_ip: "192.168.1.5",
    dst_ip: "8.8.8.8",
    src_port: 50000,
    dst_port: 53,
    proto: 17,
    app_proto: "DNS",
    bytes_c2s: 300,
    bytes_s2c: 200,
    pkts: 4,
    start_ts_ns: 1_700_000_000_000_000_000,
    end_ts_ns: 1_700_000_001_000_000_000,
    tcp_flags_c2s: 0,
    tcp_flags_s2c: 0,
    ttl_min_c2s: 64,
    category: "dns",
    app_proto_src: "payload",
    sni: null,
    severity: "info",
    threat_score: 0,
    ioc: false,
  };

  const row = flowRowFromWasm(wasmRow);

  it("flowId is the plain number from the wasm row", () => {
    expect(row.flowId).toBe(99);
    expect(typeof row.flowId).toBe("number");
  });

  it("flowIdBig is BigInt(flow_id)", () => {
    expect(row.flowIdBig).toBe(BigInt(99));
  });

  it("bytesTotal === bytesC2s + bytesS2c", () => {
    expect(row.bytesTotal).toBe(500);
  });

  it("timestamps convert from nanoseconds to milliseconds", () => {
    // 1_700_000_000_000_000_000 ns / 1e6 = 1_700_000_000_000 ms
    expect(row.startMs).toBeCloseTo(1_700_000_000_000, 0);
    expect(row.durationMs).toBeCloseTo(1_000, 0);
  });

  it("protoLabel is UDP for proto 17", () => {
    expect(row.protoLabel).toBe("UDP");
  });

  it("null app_proto_src and sni are preserved as null", () => {
    const r2 = flowRowFromWasm({ ...wasmRow, app_proto_src: null, sni: null });
    expect(r2.appProtoSrc).toBeNull();
    expect(r2.sni).toBeNull();
  });
});
