import { describe, it, expect } from "vitest";
import { normCategory, severityForCategory, SEVERITY_ORDER, rollupSeverity } from "./severity";

describe("normCategory", () => {
  it("converts kebab to snake and trims/lowercases", () => {
    expect(normCategory("file-transfer")).toBe("file_transfer");
    expect(normCategory("  FILE-Transfer  ")).toBe("file_transfer");
    expect(normCategory("remote-access")).toBe("remote_access");
  });
});

describe("severityForCategory", () => {
  it("c2 -> critical", () => {
    expect(severityForCategory("c2")).toBe("critical");
  });
  it("scan -> high", () => {
    expect(severityForCategory("scan")).toBe("high");
  });
  it("web -> info", () => {
    expect(severityForCategory("web")).toBe("info");
  });
  it("unknown token -> none", () => {
    expect(severityForCategory("notaknowncategory")).toBe("none");
  });
});

describe("SEVERITY_ORDER", () => {
  it("is critical,high,medium,low,info in that order", () => {
    expect(SEVERITY_ORDER).toEqual(["critical", "high", "medium", "low", "info"]);
  });
});

describe("rollupSeverity", () => {
  it("puts c2 flows under critical and web flows under info, total sums correctly", () => {
    const result = rollupSeverity([
      { category: "c2", flows: 8, pkts: 2999, bytes: 404865 },
      { category: "web", flows: 100, pkts: 100, bytes: 100 },
    ]);
    expect(result.bySeverity["critical"].flows).toBe(8);
    expect(result.bySeverity["info"].flows).toBe(100);
    expect(result.total.flows).toBe(108);
  });

  it("does not throw on an uncategorized (none-severity) breakdown row", () => {
    // severityForCategory('unknown') === 'none', which SEVERITY_ORDER omits — the
    // accumulator must still have a 'none' bucket or this threw.
    // 'unknown' isn't a SummaryCategory literal, but it reaches rollupSeverity at runtime
    // from engine JSON (severityForCategory maps it to 'none').
    const breakdown = [{ category: "unknown", flows: 5, pkts: 10, bytes: 100 }] as Parameters<typeof rollupSeverity>[0];
    expect(() => rollupSeverity(breakdown)).not.toThrow();
    const r = rollupSeverity(breakdown);
    expect(r.bySeverity["none"].flows).toBe(5);
    expect(r.total.flows).toBe(5);
  });
});
