import { describe, it, expect } from "vitest";
import { virustotalVerdictIp, virustotalVerdictDomain, virustotalVerdictFile } from "./virustotal";

const vtBody = (m: number) =>
  JSON.stringify({
    data: {
      attributes: {
        last_analysis_stats: { malicious: m, suspicious: 0, harmless: 5, undetected: 0 },
        tags: [],
      },
    },
  });

describe("virustotalVerdictIp", () => {
  it("parses a malicious IP", async () => {
    const http = async () => ({ status: 200, body: vtBody(3) });
    const v = await virustotalVerdictIp(http, "1.2.3.4", 0);
    expect(v.status).toBe("malicious");
    expect(v.link).toContain("/ip-address/1.2.3.4");
  });
  it("maps 404 to notfound", async () => {
    const http = async () => ({ status: 404, body: "" });
    expect((await virustotalVerdictIp(http, "1.2.3.4", 0)).status).toBe("notfound");
  });
});

describe("virustotalVerdictDomain", () => {
  it("parses a malicious domain", async () => {
    const http = async () => ({ status: 200, body: vtBody(3) });
    const v = await virustotalVerdictDomain(http, "evil.example", 0);
    expect(v.status).toBe("malicious");
    expect(v.link).toContain("/domain/evil.example");
  });
  it("maps 404 to notfound", async () => {
    const http = async () => ({ status: 404, body: "" });
    expect((await virustotalVerdictDomain(http, "x.example", 0)).status).toBe("notfound");
  });
});

describe("virustotalVerdictFile", () => {
  it("parses a malicious file and folds the threat label + name into tags", async () => {
    const body = JSON.stringify({ data: { attributes: {
      last_analysis_stats: { malicious: 40, suspicious: 0, harmless: 5, undetected: 25 },
      tags: ["peexe"], meaningful_name: "invoice.exe",
      popular_threat_classification: { suggested_threat_label: "trojan.x/y" },
    } } });
    const v = await virustotalVerdictFile(async () => ({ status: 200, body }), "a".repeat(64), 0);
    expect(v.status).toBe("malicious");
    expect(v.tags[0]).toBe("trojan.x/y"); // threat label surfaced first
    expect(v.tags).toContain("invoice.exe");
    expect(v.link).toContain(`/file/${"a".repeat(64)}`);
  });

  it("maps suspicious-only (malicious:0, suspicious>0) to 'unknown' — intentionally shows no malicious badge", async () => {
    const body = JSON.stringify({ data: { attributes: { last_analysis_stats: { malicious: 0, suspicious: 3, harmless: 0, undetected: 0 }, tags: [] } } });
    const v = await virustotalVerdictFile(async () => ({ status: 200, body }), "b".repeat(64), 0);
    expect(v.status).toBe("unknown");
    expect(v.malicious).toBe(false);
  });

  it("maps 404 to notfound", async () => {
    const v = await virustotalVerdictFile(async () => ({ status: 404, body: "" }), "c".repeat(64), 0);
    expect(v.status).toBe("notfound");
  });
});
