import { describe, it, expect } from "vitest";
import type { ReputationVerdict } from "./types";

describe("ReputationVerdict type", () => {
  it("accepts the wire shape emitted by the engine", () => {
    const v: ReputationVerdict = {
      source: "abuseipdb", status: "malicious", malicious: true, score: 96,
      tags: ["ssh"], link: "https://www.abuseipdb.com/check/203.0.113.7", fetched_at: 1750500000,
    };
    expect(v.status).toBe("malicious");
  });
});
