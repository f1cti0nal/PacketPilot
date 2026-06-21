import { describe, it, expect } from "vitest";
import "fake-indexeddb/auto";
import type { HttpGet } from "./http";
import { lookupReputation } from "./orchestrator";

const fakeAbuse: HttpGet = async () => ({ status: 200, body: JSON.stringify({ data: { abuseConfidenceScore: 96, totalReports: 3 } }) });

describe("lookupReputation", () => {
  it("only active providers run; keyed by ip; private IPs skipped", async () => {
    // 8.8.8.8 is a real public IP; 203.0.113.x is RFC 5737 documentation space (non-public).
    const out = await lookupReputation(fakeAbuse, ["8.8.8.8", "10.0.0.5"], { abuseipdb: "k" }, 1000);
    expect(Object.keys(out)).toEqual(["8.8.8.8"]);
    expect(out["8.8.8.8"][0].source).toBe("abuseipdb");
    expect(out["8.8.8.8"][0].status).toBe("malicious");
  });
});
