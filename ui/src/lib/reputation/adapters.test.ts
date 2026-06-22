import { describe, it, expect } from "vitest";
import type { HttpGet } from "./http";
import { abuseipdbVerdict } from "./abuseipdb";
import { greynoiseVerdict } from "./greynoise";
import { virustotalVerdictIp } from "./virustotal";

const fake = (status: number, body: string): HttpGet => async () => ({ status, body });

describe("reputation adapters", () => {
  // ── abuseipdb ─────────────────────────────────────────────────────────
  it("abuseipdb high confidence -> malicious", async () => {
    const v = await abuseipdbVerdict(fake(200, JSON.stringify({ data: { abuseConfidenceScore: 96, totalReports: 5 } })), "k", "203.0.113.7", 1);
    expect(v.status).toBe("malicious");
    expect(v.score).toBe(96);
  });
  it("abuseipdb zero reports -> clean", async () => {
    const v = await abuseipdbVerdict(fake(200, JSON.stringify({ data: { abuseConfidenceScore: 0, totalReports: 0 } })), "k", "1.2.3.4", 1);
    expect(v.status).toBe("clean");
  });
  it("abuseipdb medium confidence (25-74) -> unknown", async () => {
    const v = await abuseipdbVerdict(fake(200, JSON.stringify({ data: { abuseConfidenceScore: 40, totalReports: 3 } })), "k", "1.2.3.4", 1);
    expect(v.status).toBe("unknown");
  });
  it("abuseipdb low score but has reports -> unknown", async () => {
    const v = await abuseipdbVerdict(fake(200, JSON.stringify({ data: { abuseConfidenceScore: 0, totalReports: 2 } })), "k", "1.2.3.4", 1);
    expect(v.status).toBe("unknown");
  });
  it("abuseipdb non-200 status -> unavailable", async () => {
    const v = await abuseipdbVerdict(fake(500, "error"), "k", "1.2.3.4", 1);
    expect(v.status).toBe("unavailable");
  });
  it("abuseipdb bad JSON -> unavailable", async () => {
    const v = await abuseipdbVerdict(fake(200, "not-json"), "k", "1.2.3.4", 1);
    expect(v.status).toBe("unavailable");
  });
  it("abuseipdb tags: usageType, tor, countryCode", async () => {
    const v = await abuseipdbVerdict(fake(200, JSON.stringify({
      data: { abuseConfidenceScore: 90, totalReports: 5, usageType: "Data Center", isTor: true, countryCode: "RU" }
    })), "k", "1.2.3.4", 1);
    expect(v.tags).toContain("Data Center");
    expect(v.tags).toContain("tor");
    expect(v.tags).toContain("RU");
  });

  // ── greynoise ─────────────────────────────────────────────────────────
  it("greynoise benign -> benign + actor tag", async () => {
    const v = await greynoiseVerdict(fake(200, JSON.stringify({ classification: "benign", riot: false, noise: true, name: "Shodan.io" })), "k", "203.0.113.7", 1);
    expect(v.status).toBe("benign");
    expect(v.tags).toContain("Shodan.io");
  });
  it("greynoise 404 -> notfound", async () => {
    const v = await greynoiseVerdict(fake(404, JSON.stringify({ message: "not observed" })), "k", "203.0.113.7", 1);
    expect(v.status).toBe("notfound");
  });
  it("greynoise non-200/non-404 -> unavailable", async () => {
    const v = await greynoiseVerdict(fake(500, "server error"), "k", "1.2.3.4", 1);
    expect(v.status).toBe("unavailable");
  });
  it("greynoise bad JSON -> unavailable", async () => {
    const v = await greynoiseVerdict(fake(200, "bad-json"), "k", "1.2.3.4", 1);
    expect(v.status).toBe("unavailable");
  });
  it("greynoise malicious classification -> malicious", async () => {
    const v = await greynoiseVerdict(fake(200, JSON.stringify({ classification: "malicious", riot: false, noise: true })), "k", "1.2.3.4", 1);
    expect(v.status).toBe("malicious");
    expect(v.score).toBe(95);
  });
  it("greynoise riot=true (no classification) -> benign + business-service tag", async () => {
    const v = await greynoiseVerdict(fake(200, JSON.stringify({ classification: "unknown", riot: true, noise: false, name: "unknown" })), "k", "1.2.3.4", 1);
    expect(v.status).toBe("benign");
    expect(v.tags).toContain("business-service");
  });
  it("greynoise unknown + noise=false -> score 0", async () => {
    const v = await greynoiseVerdict(fake(200, JSON.stringify({ classification: "unknown", riot: false, noise: false })), "k", "1.2.3.4", 1);
    expect(v.status).toBe("unknown");
    expect(v.score).toBe(0);
  });
  it("greynoise includes link from response when present", async () => {
    const v = await greynoiseVerdict(fake(200, JSON.stringify({
      classification: "unknown", riot: false, noise: true, link: "https://viz.greynoise.io/ip/custom"
    })), "k", "1.2.3.4", 1);
    expect(v.link).toBe("https://viz.greynoise.io/ip/custom");
    expect(v.tags).toContain("internet-scanner");
  });

  // ── virustotal ────────────────────────────────────────────────────────
  it("virustotal malicious ratio", async () => {
    const body = JSON.stringify({ data: { attributes: { last_analysis_stats: { malicious: 8, suspicious: 2, harmless: 70, undetected: 10, timeout: 0 } } } });
    const v = await virustotalVerdictIp(fake(200, body), "k", "203.0.113.7", 1);
    expect(v.status).toBe("malicious");
    expect(v.score).toBe(9);
  });
  it("virustotal 404 -> notfound", async () => {
    const v = await virustotalVerdictIp(fake(404, ""), "k", "1.2.3.4", 1);
    expect(v.status).toBe("notfound");
  });
  it("virustotal non-200/non-404 -> unavailable", async () => {
    const v = await virustotalVerdictIp(fake(403, "forbidden"), "k", "1.2.3.4", 1);
    expect(v.status).toBe("unavailable");
  });
  it("virustotal bad JSON -> unavailable", async () => {
    const v = await virustotalVerdictIp(fake(200, "not-json"), "k", "1.2.3.4", 1);
    expect(v.status).toBe("unavailable");
  });
  it("virustotal missing last_analysis_stats -> unknown", async () => {
    const v = await virustotalVerdictIp(fake(200, JSON.stringify({ data: { attributes: {} } })), "k", "1.2.3.4", 1);
    expect(v.status).toBe("unknown");
  });
  it("virustotal all clean -> clean", async () => {
    const body = JSON.stringify({ data: { attributes: { last_analysis_stats: { malicious: 0, suspicious: 0, harmless: 80, undetected: 10 } } } });
    const v = await virustotalVerdictIp(fake(200, body), "k", "1.2.3.4", 1);
    expect(v.status).toBe("clean");
  });
  it("virustotal suspicious only -> unknown", async () => {
    const body = JSON.stringify({ data: { attributes: { last_analysis_stats: { malicious: 0, suspicious: 5, harmless: 0, undetected: 10 } } } });
    const v = await virustotalVerdictIp(fake(200, body), "k", "1.2.3.4", 1);
    expect(v.status).toBe("unknown");
  });
  it("virustotal tags: as_owner and country", async () => {
    const body = JSON.stringify({ data: { attributes: {
      last_analysis_stats: { malicious: 0, suspicious: 0, harmless: 10, undetected: 0 },
      tags: ["cdn"], as_owner: "Cloudflare, Inc.", country: "US",
    } } });
    const v = await virustotalVerdictIp(fake(200, body), "k", "1.2.3.4", 1);
    expect(v.tags).toContain("cdn");
    expect(v.tags).toContain("Cloudflare, Inc.");
    expect(v.tags).toContain("US");
  });
});
