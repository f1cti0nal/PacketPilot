import { describe, it, expect } from "vitest";
import { buildContext } from "./context";
import { makeOutput } from "../../test/fixtures";
import type { AnalysisOutput } from "../../types";

describe("buildContext", () => {
  it("includes capture metadata, severity, and top incidents/threats; never raw flows", () => {
    const out = makeOutput();
    const ctx = buildContext(out);
    expect(ctx).toContain("# PacketPilot analysis summary");
    expect(ctx.toLowerCase()).toContain("severity");
    // incidents from the fixture appear by host
    const firstIncident = out.summary.incidents?.[0];
    if (firstIncident) expect(ctx).toContain(firstIncident.host);
    // no raw-flow leakage markers
    expect(ctx).not.toContain("payload");
    // bounded: stays compact even with many threats
    expect(ctx.length).toBeLessThan(20000);
  });

  it("is resilient to missing optional sections", () => {
    const out = makeOutput();
    out.summary.incidents = undefined;
    out.summary.ip_threats = undefined;
    expect(() => buildContext(out)).not.toThrow();
  });

  it("formats bytes under 1 KB as '<n> B'", () => {
    const out = makeOutput();
    // Set total_bytes to a small number so fmtBytes takes the B branch
    out.summary.total_bytes = 500;
    const ctx = buildContext(out);
    expect(ctx).toContain("500 B");
  });

  it("includes reputation annotations when threats have reputation data", () => {
    const out = makeOutput();
    const threats = out.summary.ip_threats ?? [];
    if (threats.length > 0) {
      threats[0].reputation = [{ source: "abuseipdb", status: "malicious", score: 95 }];
    }
    const ctx = buildContext(out);
    expect(ctx).toContain("reputation:");
    expect(ctx).toContain("abuseipdb:malicious");
  });

  it("omits reputation line when threats have no reputation field", () => {
    const out = makeOutput();
    const threats = out.summary.ip_threats ?? [];
    if (threats.length > 0) {
      threats[0].reputation = undefined;
    }
    const ctx = buildContext(out);
    // No reputation line for that threat
    expect(ctx).not.toMatch(/reputation: abuseipdb/);
  });

  it("truncates incidents list when more than TOP_INCIDENTS exist", () => {
    const out = makeOutput();
    // Add >10 incidents
    const base = out.summary.incidents?.[0];
    if (base) {
      out.summary.incidents = Array.from({ length: 12 }, (_, i) => ({ ...base, host: `host${i}` }));
    }
    const ctx = buildContext(out);
    expect(ctx).toContain("…and 2 more.");
  });
});
