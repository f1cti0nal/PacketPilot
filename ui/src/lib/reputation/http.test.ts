import { describe, it, expect } from "vitest";
import { unavailable } from "./http";

describe("unavailable", () => {
  it("returns a well-formed unavailable verdict", () => {
    const v = unavailable("abuseipdb", 9999);
    expect(v.source).toBe("abuseipdb");
    expect(v.status).toBe("unavailable");
    expect(v.malicious).toBe(false);
    expect(v.score).toBeNull();
    expect(v.tags).toEqual([]);
    expect(v.link).toBeNull();
    expect(v.fetched_at).toBe(9999);
  });
});
