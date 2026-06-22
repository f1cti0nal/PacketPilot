import { describe, it, expect } from "vitest";
import { virustotalVerdictIp } from "./virustotal";
import { virustotalVerdictDomain } from "./virustotal";

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
    const v = await virustotalVerdictIp(http, "k", "1.2.3.4", 0);
    expect(v.status).toBe("malicious");
    expect(v.link).toContain("/ip-address/1.2.3.4");
  });
  it("maps 404 to notfound", async () => {
    const http = async () => ({ status: 404, body: "" });
    expect((await virustotalVerdictIp(http, "k", "1.2.3.4", 0)).status).toBe("notfound");
  });
});

describe("virustotalVerdictDomain", () => {
  it("parses a malicious domain", async () => {
    const http = async () => ({ status: 200, body: vtBody(3) });
    const v = await virustotalVerdictDomain(http, "k", "evil.example", 0);
    expect(v.status).toBe("malicious");
    expect(v.link).toContain("/domain/evil.example");
  });
  it("maps 404 to notfound", async () => {
    const http = async () => ({ status: 404, body: "" });
    expect((await virustotalVerdictDomain(http, "k", "x.example", 0)).status).toBe("notfound");
  });
});
