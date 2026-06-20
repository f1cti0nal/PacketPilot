import { describe, it, expect } from "vitest";
import { makeOutput } from "./fixtures";

describe("makeOutput fixture", () => {
  const o = makeOutput();
  const p = o.summary.proto;
  it("proto leaf invariants hold", () => {
    expect(p.tls + p.http + p.other_tcp).toBe(p.tcp);
    expect(p.dns + p.other_udp).toBe(p.udp);
    expect(p.tcp + p.udp + p.non_ipv4).toBe(o.summary.total_packets);
  });
  it("has zero critical flows but a critical incident (data trap)", () => {
    expect(o.summary.severity_counts!.critical).toBe(0);
    expect(o.summary.incidents!.some((i) => i.severity === "critical")).toBe(true);
  });
  it("has a data_exfil finding and an exfil-peak bucket", () => {
    expect(o.summary.findings!.some((f) => f.kind === "data_exfil")).toBe(true);
    const max = Math.max(...o.summary.time_histogram.map((b) => b.bytes));
    expect(o.summary.time_histogram[5].bytes).toBe(max);
  });
});
