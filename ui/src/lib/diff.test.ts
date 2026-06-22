import { describe, it, expect } from "vitest";
import { diffByKey, diffSummaries } from "./diff";
import type { IpThreat, Incident, Summary, SeverityCounts, ReputationVerdict } from "../types";

const sev = (o: Partial<SeverityCounts> = {}): SeverityCounts => ({ critical: 0, high: 0, medium: 0, low: 0, info: 0, ...o });
const summary = (over: Partial<Summary>): Summary =>
  ({ ip_threats: [], incidents: [], severity_counts: sev(), ...over } as Summary);
const threat = (o: Partial<IpThreat>): IpThreat =>
  ({ ip: "1.1.1.1", ip_class: "public", severity: "low", score: 10, flows: 1, bytes: 1,
     ioc: false, tags: [], attack: [], evidence: [], ...o } as IpThreat);
const incident = (o: Partial<Incident>): Incident =>
  ({ host: "10.0.0.1", severity: "low", score: 10, title: "t", narrative: "n",
     stages: [], attack: [], findings: [], ...o } as Incident);
const verdict = (status: ReputationVerdict["status"]): ReputationVerdict =>
  ({ source: "abuseipdb", status, malicious: status === "malicious", score: 0,
     tags: [], link: null, fetched_at: 0 } as ReputationVerdict);

describe("diffByKey", () => {
  it("splits into added / removed / changed and sorts changed by key", () => {
    const r = diffByKey(
      [{ k: "a", v: 1 }, { k: "b", v: 2 }],
      [{ k: "b", v: 9 }, { k: "c", v: 3 }],
      (x) => x.k,
      (a, b) => (a.v !== b.v ? [{ field: "v", before: a.v, after: b.v }] : []),
    );
    expect(r.added.map((x) => x.k)).toEqual(["c"]);
    expect(r.removed.map((x) => x.k)).toEqual(["a"]);
    expect(r.changed).toHaveLength(1);
    expect(r.changed[0]).toMatchObject({ key: "b", deltas: [{ field: "v", before: 2, after: 9 }] });
  });
});

describe("diffSummaries", () => {
  it("diffs threats by ip with field deltas, incidents by host, and severity bands", () => {
    const before = summary({
      ip_threats: [threat({ ip: "1.1.1.1", score: 40, severity: "medium" }), threat({ ip: "2.2.2.2" })],
      incidents: [incident({ host: "h1", stages: ["Discovery"] })],
      severity_counts: sev({ critical: 1, low: 5 }),
    });
    const after = summary({
      ip_threats: [threat({ ip: "1.1.1.1", score: 85, severity: "critical", ioc: true }), threat({ ip: "9.9.9.9" })],
      incidents: [incident({ host: "h1", stages: ["Discovery", "Command & Control"] })],
      severity_counts: sev({ critical: 3, low: 0 }),
    });
    const d = diffSummaries(before, after);
    expect(d.threats.added.map((t) => t.ip)).toEqual(["9.9.9.9"]);
    expect(d.threats.removed.map((t) => t.ip)).toEqual(["2.2.2.2"]);
    expect(d.threats.changed[0].key).toBe("1.1.1.1");
    expect(d.threats.changed[0].deltas).toEqual(expect.arrayContaining([
      { field: "score", before: 40, after: 85 },
      { field: "severity", before: "medium", after: "critical" },
      { field: "ioc", before: "no", after: "yes" },
    ]));
    expect(d.incidents.changed[0].deltas).toEqual(expect.arrayContaining([
      { field: "stages", before: "Discovery", after: "Command & Control,Discovery" },
    ]));
    expect(d.severity.find((s) => s.band === "critical")).toMatchObject({ before: 1, after: 3, delta: 2 });
    expect(d.shared).toBe(2); // ip 1.1.1.1 + host h1 present in both
  });

  it("returns an empty diff for identical inputs", () => {
    const s = summary({ ip_threats: [threat({ ip: "1.1.1.1" })], incidents: [incident({ host: "h1" })] });
    const d = diffSummaries(s, s);
    expect(d.threats.added).toHaveLength(0);
    expect(d.threats.removed).toHaveLength(0);
    expect(d.threats.changed).toHaveLength(0);
    expect(d.severity.every((b) => b.delta === 0)).toBe(true);
  });

  it("detects reputation status change (worstRep: with reputation vs empty)", () => {
    const before = summary({
      ip_threats: [threat({ ip: "1.1.1.1", reputation: [] })],
    });
    const after = summary({
      ip_threats: [threat({ ip: "1.1.1.1", reputation: [verdict("malicious"), verdict("clean")] })],
    });
    const d = diffSummaries(before, after);
    expect(d.threats.changed[0].deltas).toEqual(
      expect.arrayContaining([{ field: "reputation", before: "(none)", after: "malicious" }]),
    );
  });

  it("detects tag removal as a setDelta with (none) on the after side", () => {
    const before = summary({
      ip_threats: [threat({ ip: "1.1.1.1", tags: ["scanner"] })],
    });
    const after = summary({
      ip_threats: [threat({ ip: "1.1.1.1", tags: [] })],
    });
    const d = diffSummaries(before, after);
    expect(d.threats.changed[0].deltas).toEqual(
      expect.arrayContaining([{ field: "tags", before: "scanner", after: "(none)" }]),
    );
  });

  it("shared counts only entities present in both captures", () => {
    const before = summary({
      ip_threats: [threat({ ip: "1.1.1.1" }), threat({ ip: "2.2.2.2" })],
      incidents: [incident({ host: "h1" })],
    });
    const after = summary({
      ip_threats: [threat({ ip: "1.1.1.1" }), threat({ ip: "3.3.3.3" })],
      incidents: [incident({ host: "h2" })],
    });
    const d = diffSummaries(before, after);
    expect(d.shared).toBe(1); // only ip 1.1.1.1 is shared; h1/h2 are different; 2.2.2.2 removed
  });

  it("handles summaries with missing optional fields (nullish fallbacks)", () => {
    // Exercise the ?? [] and ?? 0 branches in diffSummaries
    const bare = { ip_threats: undefined, incidents: undefined, severity_counts: undefined } as unknown as Summary;
    const d = diffSummaries(bare, bare);
    expect(d.threats.added).toHaveLength(0);
    expect(d.threats.removed).toHaveLength(0);
    expect(d.incidents.added).toHaveLength(0);
    expect(d.severity.every((b) => b.before === 0 && b.after === 0 && b.delta === 0)).toBe(true);
    expect(d.shared).toBe(0);
  });
});
