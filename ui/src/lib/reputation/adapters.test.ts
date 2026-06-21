import { describe, it, expect } from "vitest";
import type { HttpGet } from "./http";
import { abuseipdbVerdict } from "./abuseipdb";
import { greynoiseVerdict } from "./greynoise";
import { virustotalVerdictIp } from "./virustotal";

const fake = (status: number, body: string): HttpGet => async () => ({ status, body });

describe("reputation adapters", () => {
  it("abuseipdb high confidence -> malicious", async () => {
    const v = await abuseipdbVerdict(fake(200, JSON.stringify({ data: { abuseConfidenceScore: 96, totalReports: 5 } })), "k", "203.0.113.7", 1);
    expect(v.status).toBe("malicious");
    expect(v.score).toBe(96);
  });
  it("abuseipdb zero reports -> clean", async () => {
    const v = await abuseipdbVerdict(fake(200, JSON.stringify({ data: { abuseConfidenceScore: 0, totalReports: 0 } })), "k", "1.2.3.4", 1);
    expect(v.status).toBe("clean");
  });
  it("greynoise benign -> benign + actor tag", async () => {
    const v = await greynoiseVerdict(fake(200, JSON.stringify({ classification: "benign", riot: false, noise: true, name: "Shodan.io" })), "k", "203.0.113.7", 1);
    expect(v.status).toBe("benign");
    expect(v.tags).toContain("Shodan.io");
  });
  it("greynoise 404 -> notfound", async () => {
    const v = await greynoiseVerdict(fake(404, JSON.stringify({ message: "not observed" })), "k", "203.0.113.7", 1);
    expect(v.status).toBe("notfound");
  });
  it("virustotal malicious ratio", async () => {
    const body = JSON.stringify({ data: { attributes: { last_analysis_stats: { malicious: 8, suspicious: 2, harmless: 70, undetected: 10, timeout: 0 } } } });
    const v = await virustotalVerdictIp(fake(200, body), "k", "203.0.113.7", 1);
    expect(v.status).toBe("malicious");
    expect(v.score).toBe(9);
  });
});
