import { describe, it, expect } from "vitest";
import type { RawFlowRow } from "../types";
import { normalizeFlow } from "./data";

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
