import { describe, it, expect, vi } from "vitest";
import "fake-indexeddb/auto";
import type { HttpGet } from "./http";
import { lookupReputation, lookupDomainReputation } from "./orchestrator";
import * as budgetModule from "./budget";

const fakeAbuse: HttpGet = async () => ({ status: 200, body: JSON.stringify({ data: { abuseConfidenceScore: 96, totalReports: 3 } }) });

describe("lookupReputation", () => {
  it("only active providers run; keyed by ip; private IPs skipped", async () => {
    // 8.8.8.8 is a real public IP; 10.0.0.5 is private.
    const out = await lookupReputation(fakeAbuse, ["8.8.8.8", "10.0.0.5"], { abuseipdb: "k" }, 1000);
    expect(Object.keys(out)).toEqual(["8.8.8.8"]);
    expect(out["8.8.8.8"][0].source).toBe("abuseipdb");
    expect(out["8.8.8.8"][0].status).toBe("malicious");
  });

  it("quota-exhausted path: returns unavailable verdict tagged 'quota' when budget is drained", async () => {
    // Stub makeBudget to return a fully-exhausted budget so the very first IP triggers quotaUnavailable.
    vi.spyOn(budgetModule, "makeBudget").mockReturnValue({ abuseipdb: 0, greynoise: 0, virustotal: 0 });

    const fetchSpy = vi.fn(async (_url: string, _headers: Record<string, string>) => ({ status: 200, body: JSON.stringify({ data: { abuseConfidenceScore: 10, totalReports: 1 } }) })) satisfies HttpGet;
    // Use a different public IP not already in the fake-indexeddb cache from the previous test.
    const out = await lookupReputation(fetchSpy, ["1.1.1.1"], { abuseipdb: "k" }, 7000);

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
    const out = await lookupReputation(fakeAbuse, ["8.8.8.8"], {}, 2000);
    // No keys means no providers — public IP gets an empty verdicts array, so not included in output.
    expect(out["8.8.8.8"]).toBeUndefined();
  });
});

describe("lookupDomainReputation", () => {
  it("returns empty without a VT key", async () => {
    const http = async () => ({ status: 200, body: "{}" });
    expect(await lookupDomainReputation(http, ["a.example"], "", 0)).toEqual({});
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
    const out = await lookupDomainReputation(http, ["evil.example"], "k", 99000);
    expect(out["evil.example"][0].status).toBe("malicious");
    expect(http).toHaveBeenCalledTimes(1);
  });
});
