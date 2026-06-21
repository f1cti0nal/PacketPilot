import { describe, it, expect } from "vitest";
import "fake-indexeddb/auto";
import type { HttpGet } from "./http";
import { lookupReputation } from "./orchestrator";

const fakeAbuse: HttpGet = async () => ({ status: 200, body: JSON.stringify({ data: { abuseConfidenceScore: 96, totalReports: 3 } }) });

describe("lookupReputation", () => {
  it("only active providers run; keyed by ip; private IPs skipped", async () => {
    const out = await lookupReputation(fakeAbuse, ["203.0.113.7", "10.0.0.5"], { abuseipdb: "k" }, 1000);
    expect(Object.keys(out)).toEqual(["203.0.113.7"]);
    expect(out["203.0.113.7"][0].source).toBe("abuseipdb");
    expect(out["203.0.113.7"][0].status).toBe("malicious");
  });
});
