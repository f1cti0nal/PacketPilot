import { describe, it, expect, beforeEach } from "vitest";
import { buildContext } from "./context";
import { makeOutput } from "../../test/fixtures";
import type { DomainThreat, RepStatus } from "../../types";
import { humanBytes, humanNumber, compactNumber, shortHash, basename, durationHumanMs } from "../../lib/format";
import { rollupSeverity } from "../../lib/severity";
import { getProxyUrl, setProxyUrl } from "./settings";

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
      threats[0].reputation = [{ source: "abuseipdb", status: "malicious", score: 95, malicious: true, tags: [], link: null, fetched_at: 0 }];
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

  it("formats bytes >= 1 GB as '<n.n> GB'", () => {
    const out = makeOutput();
    out.summary.total_bytes = 2_500_000_000;
    const ctx = buildContext(out);
    expect(ctx).toContain("GB");
  });

  it("formats bytes >= 1 KB as '<n.n> KB'", () => {
    const out = makeOutput();
    out.summary.total_bytes = 4096;
    const ctx = buildContext(out);
    expect(ctx).toContain("KB");
  });

  it("omits attack/stages annotation when incident has empty arrays", () => {
    const out = makeOutput();
    out.summary.incidents = [{
      host: "192.168.1.1", severity: "low", score: 10,
      title: "Bare incident", narrative: "Nothing notable.",
      stages: [], attack: [], findings: [],
    }];
    const ctx = buildContext(out);
    expect(ctx).toContain("192.168.1.1");
    expect(ctx).not.toContain("stages:");
    expect(ctx).not.toContain("[T");
  });

  it("omits tags/evidence annotation when threat has empty arrays", () => {
    const out = makeOutput();
    out.summary.ip_threats = [{
      ip: "1.2.3.4", ip_class: "public", severity: "info", score: 5,
      flows: 1, bytes: 100, ioc: false, tags: [], attack: [], evidence: [],
    }];
    const ctx = buildContext(out);
    expect(ctx).toContain("1.2.3.4");
    // no tags: or evidence: lines for this threat
    expect(ctx).not.toContain("tags:[");
  });

  it("omits severity section when severity_counts is absent", () => {
    const out = makeOutput();
    out.summary.severity_counts = undefined as any;
    const ctx = buildContext(out);
    expect(ctx).not.toContain("## Severity");
  });

  it("omits category breakdown section when category_breakdown is absent", () => {
    const out = makeOutput();
    out.summary.category_breakdown = undefined as any;
    const ctx = buildContext(out);
    expect(ctx).not.toContain("## Traffic categories");
  });

  it("omits top talkers section when top_talkers is absent", () => {
    const out = makeOutput();
    out.summary.top_talkers = undefined as any;
    const ctx = buildContext(out);
    expect(ctx).not.toContain("## Top talkers");
  });

  it("includes IOC marker when threat has ioc=true", () => {
    const out = makeOutput();
    out.summary.ip_threats = [{
      ip: "5.6.7.8", ip_class: "public", severity: "high", score: 75,
      flows: 10, bytes: 5000, ioc: true, tags: [], attack: [], evidence: [],
    }];
    const ctx = buildContext(out);
    expect(ctx).toContain("IOC");
  });

  it("handles missing duration_ns (falls back to 0)", () => {
    const out = makeOutput();
    (out.summary as any).duration_ns = undefined;
    const ctx = buildContext(out);
    expect(ctx).toContain("~0s");
  });

  it("names matched fingerprint families in the threat line", () => {
    const out = makeOutput();
    out.summary.ip_threats = [{
      ip: "1.2.3.4", ip_class: "public", severity: "high", score: 75,
      flows: 10, bytes: 5000, ioc: false, tags: [], attack: [], evidence: [],
      fingerprints: [{ ja3: "abc", ja4: null, label: "CobaltStrike" }],
    }];
    expect(buildContext(out)).toContain("fingerprint: CobaltStrike");
  });
});

// Additional branch-coverage tests for pure utility functions used by context.ts
describe("format helpers — branch coverage", () => {
  it("humanBytes returns '—' for non-finite input", () => {
    expect(humanBytes(Infinity)).toBe("—");
    expect(humanBytes(NaN)).toBe("—");
  });
  it("humanNumber returns '—' for non-finite input", () => {
    expect(humanNumber(Infinity)).toBe("—");
    expect(humanNumber(NaN)).toBe("—");
  });
  it("compactNumber returns '—' for non-finite input", () => {
    expect(compactNumber(NaN)).toBe("—");
  });
  it("shortHash returns the full hash when it is short enough", () => {
    expect(shortHash("abc", 8, 6)).toBe("abc");
  });
  it("basename returns path unchanged when there are no slash separators", () => {
    // "noSlash".split(/[\\/]/) yields ["noSlash"]; last element is non-empty, returned as-is
    expect(basename("file.pcap")).toBe("file.pcap");
  });
  it("durationHumanMs covers sub-1ms branch", () => {
    expect(durationHumanMs(0.4)).toBe("0 ms");
  });
  it("humanBytes formats values >= 100 in a given unit with 0 decimal places", () => {
    // 100 KB = 102400 bytes → value/1024 = 100 KB → digits = 0 (value >= 100)
    expect(humanBytes(102400)).toBe("100 KB");
  });
  it("humanBytes formats values between 10 and 100 in a given unit with 1 decimal place", () => {
    // 15 KB = 15360 bytes → value/1024 = 15 KB → digits = 1 (value >= 10, value < 100)
    expect(humanBytes(15360)).toBe("15.0 KB");
  });
  it("humanBytes formats values under 10 in a given unit with 2 decimal places", () => {
    // 5.5 KB = 5632 bytes → value/1024 = 5.5 KB → digits = 2 (value < 10)
    expect(humanBytes(5632)).toBe("5.50 KB");
  });
  it("basename returns path when it ends with a separator", () => {
    // "foo/".split(/[\\/]/) → ["foo", ""], last is "", which is falsy → returns original path
    expect(basename("foo/")).toBe("foo/");
  });
});

describe("severity helpers — branch coverage", () => {
  it("rollupSeverity skips category push when flows == 0", () => {
    const result = rollupSeverity([
      { category: "c2", flows: 0, pkts: 0, bytes: 0 },
    ]);
    // flows == 0, so category should NOT be pushed
    expect(result.bySeverity["critical"].categories).toEqual([]);
    expect(result.bySeverity["critical"].flows).toBe(0);
  });
});

describe("ai/settings proxy URL — branch coverage", () => {
  beforeEach(() => localStorage.clear());
  it("getProxyUrl returns empty string when not set (null-coalesce default)", () => {
    expect(getProxyUrl()).toBe("");
  });
  it("getProxyUrl returns stored value after setProxyUrl", () => {
    setProxyUrl("http://localhost:8788");
    expect(getProxyUrl()).toBe("http://localhost:8788");
  });
});

const vt = (status: RepStatus) => ({
  source: "virustotal", status, malicious: status === "malicious",
  score: status === "malicious" ? 90 : null, tags: [], link: null, fetched_at: 0,
});
const dom = (host: string, bytes: number, rep?: ReturnType<typeof vt>[]): DomainThreat => ({
  host, flows: 1, bytes, reputation: rep,
});

describe("buildContext — domains", () => {
  it("renders a Notable domains section, labels malicious, and lists malicious-first", () => {
    const out = makeOutput();
    out.summary.domain_threats = [
      dom("cdn.example.com", 5_000_000),                 // high traffic, no verdict
      dom("c2.evil.test", 1_000, [vt("malicious")]),     // low traffic, malicious
      dom("quota.example", 2_000, [vt("unavailable")]),  // quota placeholder — NOT malicious
    ];
    const ctx = buildContext(out);
    expect(ctx).toContain("## Notable domains (SNI)");
    expect(ctx).toContain("c2.evil.test");
    expect(ctx).toContain("MALICIOUS (virustotal)");
    // quota-unavailable shows its status but is never labeled MALICIOUS
    expect(ctx).toContain("quota.example");
    expect(ctx).toContain("virustotal:unavailable");
    // malicious-first: the low-traffic malicious domain precedes the high-traffic clean one
    expect(ctx.indexOf("c2.evil.test")).toBeLessThan(ctx.indexOf("cdn.example.com"));
    // privacy + bounds still hold
    expect(ctx).not.toContain("payload");
    expect(ctx.length).toBeLessThan(20000);
  });

  it("omits the section when there are no domains", () => {
    const out = makeOutput();
    out.summary.domain_threats = [];
    expect(buildContext(out)).not.toContain("## Notable domains (SNI)");
  });
});
