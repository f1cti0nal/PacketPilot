import { describe, it, expect, vi } from "vitest";
import "fake-indexeddb/auto";
import type { HttpGet } from "./http";
import { lookupReputation, lookupDomainReputation, lookupFileReputation } from "./orchestrator";
import * as budgetModule from "./budget";

const fakeAbuse: HttpGet = async () => ({ status: 200, body: JSON.stringify({ data: { abuseConfidenceScore: 96, totalReports: 3 } }) });

describe("lookupReputation", () => {
  it("only active providers run; keyed by ip; private IPs skipped", async () => {
    // 8.8.8.8 is a real public IP; 10.0.0.5 is private.
    const out = await lookupReputation(fakeAbuse, ["8.8.8.8", "10.0.0.5"], ["abuseipdb"], 1000);
    expect(Object.keys(out)).toEqual(["8.8.8.8"]);
    expect(out["8.8.8.8"][0].source).toBe("abuseipdb");
    expect(out["8.8.8.8"][0].status).toBe("malicious");
  });

  it("quota-exhausted path: returns unavailable verdict tagged 'quota' when budget is drained", async () => {
    // Stub makeBudget to return a fully-exhausted budget so the very first IP triggers quotaUnavailable.
    vi.spyOn(budgetModule, "makeBudget").mockReturnValue({ abuseipdb: 0, greynoise: 0, virustotal: 0 });

    const fetchSpy = vi.fn(async (_url: string, _headers: Record<string, string>) => ({ status: 200, body: JSON.stringify({ data: { abuseConfidenceScore: 10, totalReports: 1 } }) })) satisfies HttpGet;
    // Use a different public IP not already in the fake-indexeddb cache from the previous test.
    const out = await lookupReputation(fetchSpy, ["1.1.1.1"], ["abuseipdb"], 7000);

    expect(out["1.1.1.1"]).toBeDefined();
    const v = out["1.1.1.1"][0];
    expect(v.source).toBe("abuseipdb");
    expect(v.status).toBe("unavailable");
    expect(v.tags).toContain("quota");
    // The provider fetch should NOT have been called since budget was zero.
    expect(fetchSpy).not.toHaveBeenCalled();

    vi.restoreAllMocks();
  });

  it("no providers configured: returns empty verdicts for public IPs", async () => {
    const out = await lookupReputation(fakeAbuse, ["8.8.8.8"], [], 2000);
    // No providers means no lookups — public IP gets no verdicts, not included in output.
    expect(out["8.8.8.8"]).toBeUndefined();
  });

  it("unknown providers are ignored (only valid intersection)", async () => {
    const out = await lookupReputation(fakeAbuse, ["8.8.8.8"], ["badprovider", "abuseipdb"], 3000);
    expect(Object.keys(out)).toContain("8.8.8.8");
    expect(out["8.8.8.8"][0].source).toBe("abuseipdb");
  });
});

describe("lookupDomainReputation", () => {
  it("returns empty when hosts list is empty", async () => {
    const http = async () => ({ status: 200, body: "{}" });
    expect(await lookupDomainReputation(http, [], 0)).toEqual({});
  });

  it("looks up each host via VT (cache miss → fetch)", async () => {
    const vtDomainBody = JSON.stringify({
      data: {
        attributes: {
          last_analysis_stats: { malicious: 1, suspicious: 0, harmless: 9, undetected: 0 },
          tags: [],
        },
      },
    });
    const http = vi.fn(async () => ({ status: 200, body: vtDomainBody })) satisfies HttpGet;
    // Use a unique now timestamp to avoid cache hits from other tests.
    const out = await lookupDomainReputation(http, ["evil.example"], 99000);
    expect(out["evil.example"][0].status).toBe("malicious");
    expect(http).toHaveBeenCalledTimes(1);
  });
});

describe("lookupFileReputation", () => {
  const sha = "a".repeat(64);
  const vtFileBody = JSON.stringify({
    data: {
      attributes: {
        last_analysis_stats: { malicious: 42, suspicious: 3, harmless: 5, undetected: 20 },
        tags: ["peexe"],
        meaningful_name: "invoice.exe",
        popular_threat_classification: { suggested_threat_label: "trojan.emotet/x" },
      },
    },
  });

  it("looks up each well-formed sha256 via VT and folds the threat label into tags", async () => {
    const http = vi.fn(async () => ({ status: 200, body: vtFileBody })) satisfies HttpGet;
    const out = await lookupFileReputation(http, [sha], 123000);
    expect(out[sha][0].status).toBe("malicious");
    expect(out[sha][0].malicious).toBe(true);
    expect(http).toHaveBeenCalledTimes(1);
    expect(out[sha][0].tags[0]).toBe("trojan.emotet/x"); // file-only threat label, surfaced first
    expect(out[sha][0].tags).toContain("invoice.exe");
  });

  it("skips malformed (non-64-hex) inputs without a fetch", async () => {
    const http = vi.fn(async () => ({ status: 200, body: vtFileBody })) satisfies HttpGet;
    const out = await lookupFileReputation(http, ["not-a-hash", "ABC", "g".repeat(64)], 124000);
    expect(out).toEqual({});
    expect(http).not.toHaveBeenCalled();
  });

  it("normalizes the hash key to lowercase", async () => {
    const http = vi.fn(async () => ({ status: 404, body: "" })) satisfies HttpGet;
    const upper = "B".repeat(64);
    const out = await lookupFileReputation(http, [upper], 125000);
    expect(out[upper.toLowerCase()][0].status).toBe("notfound");
  });

  it("returns 'unavailable' tagged 'quota' and does NOT fetch when the VT budget is drained", async () => {
    vi.spyOn(budgetModule, "makeBudget").mockReturnValue({ abuseipdb: 0, greynoise: 0, virustotal: 0 });
    const http = vi.fn(async () => ({ status: 200, body: vtFileBody })) satisfies HttpGet;
    const out = await lookupFileReputation(http, ["d".repeat(64)], 126000);
    const v = out["d".repeat(64)][0];
    expect(v.status).toBe("unavailable");
    expect(v.tags).toContain("quota");
    expect(http).not.toHaveBeenCalled();
    vi.restoreAllMocks();
  });
});
