import { describe, it, expect } from "vitest";
import { parseIocs, matchIocs } from "./ioc";
import { makeOutput } from "../../test/fixtures";
import type { AnalysisOutput } from "../../types";

describe("parseIocs", () => {
  it("classifies IPs, domains, and hashes and ignores comments + junk", () => {
    const sha = "a".repeat(64);
    const iocs = parseIocs(
      [
        "# header comment",
        "45.77.13.37",
        "evil.example.com",
        `${sha}   // inline comment`,
        "garbage_token_no_dot",
        "192.168.0.1 # trailing comment",
      ].join("\n"),
    );
    expect([...iocs.ips].sort()).toEqual(["192.168.0.1", "45.77.13.37"]);
    expect(iocs.domains.has("evil.example.com")).toBe(true);
    expect(iocs.hashes.has(sha)).toBe(true);
    expect(iocs.count).toBe(4);
  });

  it("refangs defanged indicators and reduces URLs to a host", () => {
    const iocs = parseIocs("hxxps://bad[.]domain[.]net/payload?a=1\n5.6.7.8:8080");
    expect(iocs.domains.has("bad.domain.net")).toBe(true);
    expect(iocs.ips.has("5.6.7.8")).toBe(true);
  });

  it("lowercases and de-duplicates domains and hashes", () => {
    const md5 = "ABCDEF0123456789ABCDEF0123456789";
    const iocs = parseIocs(`Evil.Example.COM\nevil.example.com\n${md5}\n${md5.toLowerCase()}`);
    expect([...iocs.domains]).toEqual(["evil.example.com"]);
    expect([...iocs.hashes]).toEqual([md5.toLowerCase()]);
  });

  it("splits comma/semicolon/space-separated tokens on one line", () => {
    const iocs = parseIocs("1.1.1.1, 2.2.2.2; 3.3.3.3 4.4.4.4");
    expect(iocs.ips.size).toBe(4);
  });

  it("rejects out-of-range IPv4 octets (256.x / 999.x)", () => {
    const iocs = parseIocs("256.1.1.1\n999.0.0.1\n10.0.0.1");
    expect(iocs.ips.has("256.1.1.1")).toBe(false);
    expect(iocs.ips.has("10.0.0.1")).toBe(true);
    expect(iocs.ips.size).toBe(1);
  });
});

describe("matchIocs", () => {
  function withExtras(): AnalysisOutput {
    const base = makeOutput();
    return makeOutput({
      summary: {
        ...base.summary,
        domain_threats: [{ host: "evil.example.com", flows: 3, bytes: 100 }],
        carved_files: [
          { client: "10.0.0.9", server: "45.77.13.37", sha256: "f".repeat(64), size: 2048, known_bad: false },
        ],
      },
    });
  }

  it("emits one ioc_match finding per distinct hit (ip/domain High, hash Critical)", () => {
    const { output, matches } = matchIocs(
      withExtras(),
      parseIocs(`45.77.13.37\nevil.example.com\n${"f".repeat(64)}`),
    );
    expect(matches).toBe(3);
    const ioc = output.summary.findings!.filter((f) => f.kind === "ioc_match");
    expect(ioc).toHaveLength(3);
    expect(ioc.find((f) => f.title.includes("45.77.13.37"))!.severity).toBe("high");
    expect(ioc.find((f) => f.title.includes("evil.example.com"))!.severity).toBe("high");
    expect(ioc.find((f) => f.title.startsWith("IOC match: ffffffffffff"))!.severity).toBe("critical");
  });

  it("preserves existing behavioral findings and replaces (not stacks) on re-run", () => {
    const once = matchIocs(withExtras(), parseIocs("45.77.13.37")).output;
    const twice = matchIocs(once, parseIocs("45.77.13.37")).output;
    expect(twice.summary.findings!.filter((f) => f.kind === "ioc_match")).toHaveLength(1);
    expect(twice.summary.findings!.some((f) => f.kind === "beacon")).toBe(true);
  });

  it("returns zero matches when nothing intersects, without dropping findings", () => {
    const out = makeOutput();
    const before = out.summary.findings!.length;
    const { output, matches } = matchIocs(out, parseIocs("9.9.9.9\nnope.invalid"));
    expect(matches).toBe(0);
    expect(output.summary.findings!.length).toBe(before);
  });

  it("matches an IOC IP that is only an ordinary talker, not an elevated threat", () => {
    // 10.0.0.9 is in top_talkers but NOT ip_threats in the fixture — the headline IOC-sweep case.
    const { output, matches } = matchIocs(makeOutput(), parseIocs("10.0.0.9"));
    expect(matches).toBe(1);
    expect(output.summary.findings!.some((f) => f.kind === "ioc_match" && f.title.includes("10.0.0.9"))).toBe(true);
  });

  it("attributes a domain IOC to its resolved IP from passive DNS", () => {
    const base = makeOutput();
    const out = makeOutput({ summary: { ...base.summary, resolved_ips: [{ ip: "203.0.113.9", domain: "bad.example", resolutions: 3 }] } });
    const { output, matches } = matchIocs(out, parseIocs("bad.example"));
    expect(matches).toBe(1);
    const f = output.summary.findings!.find((x) => x.kind === "ioc_match" && x.title.includes("bad.example"))!;
    expect(f.src_ip).toBe("203.0.113.9");
  });

  it("leaves src_ip empty for a domain IOC with no resolved IP (so it can't pollute the graph/pivot)", () => {
    const base = makeOutput();
    const out = makeOutput({ summary: { ...base.summary, domain_threats: [{ host: "noip.example", flows: 1, bytes: 1 }] } });
    const { output } = matchIocs(out, parseIocs("noip.example"));
    expect(output.summary.findings!.find((x) => x.kind === "ioc_match")!.src_ip).toBe("");
  });

  it("does not mutate the input output", () => {
    const out = withExtras();
    const before = out.summary.findings!.length;
    matchIocs(out, parseIocs("45.77.13.37"));
    expect(out.summary.findings!.length).toBe(before);
  });
});
