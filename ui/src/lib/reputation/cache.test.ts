import { describe, it, expect } from "vitest";
import "fake-indexeddb/auto";
import { getReputation, putReputation } from "../recent";

describe("reputation cache", () => {
  it("hit within ttl, miss after", async () => {
    const v = { source: "abuseipdb", status: "malicious" as const, malicious: true, score: 90, tags: [], link: null, fetched_at: 1000 };
    await putReputation("abuseipdb", "203.0.113.7", v);
    expect(await getReputation("abuseipdb", "203.0.113.7", 1100, 600)).not.toBeNull();
    expect(await getReputation("abuseipdb", "203.0.113.7", 2000, 600)).toBeNull();
  });
});
