import { describe, it, expect } from "vitest";
import { diffByKey, diffSummaries } from "./diff";
import type { Alert, IpThreat, Incident, Finding, Summary, SeverityCounts, ReputationVerdict } from "../types";

const sev = (o: Partial<SeverityCounts> = {}): SeverityCounts => ({ critical: 0, high: 0, medium: 0, low: 0, info: 0, ...o });
const summary = (over: Partial<Summary>): Summary =>
  ({ ip_threats: [], incidents: [], severity_counts: sev(), ...over } as Summary);
const threat = (o: Partial<IpThreat>): IpThreat =>
  ({ ip: "1.1.1.1", ip_class: "public", severity: "low", score: 10, flows: 1, bytes: 1,
     ioc: false, tags: [], attack: [], evidence: [], ...o } as IpThreat);
const incident = (o: Partial<Incident>): Incident =>
  ({ host: "10.0.0.1", severity: "low", score: 10, title: "t", narrative: "n",
     stages: [], attack: [], findings: [], ...o } as Incident);
const finding = (o: Partial<Finding>): Finding =>
  ({ kind: "port_scan", severity: "low", score: 10, title: "t", src_ip: "10.0.0.1",
     dst_ip: null, dst_port: null, attack: [], evidence: [],
     interval_ns: null, jitter_cv: null, contacts: null, ...o } as Finding);
const alert = (o: Partial<Alert>): Alert =>
  ({ id: "alert:0000000000000000", source: "rollup", band: "review", priority: 40, confidence: 50,
     severity: "medium", title: "t", narrative: "n", action: "a", actor: "10.0.0.1",
     hosts: ["10.0.0.1"], host_count: 1, peer: null, attack: [], stage: "Collection", stage_ordinal: 2,
     next_stage: null, priority_terms: [], context: { actor: { ip: "10.0.0.1", internal: true } },
     finding_indices: [0], finding_count: 1, chain_id: null, incident_hosts: [],
     first_seen_ns: null, last_seen_ns: null, ...o } as Alert);
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

  it("diffs behavioral findings as new / resolved / changed by kind + endpoints", () => {
    const before = summary({
      findings: [
        finding({ kind: "port_scan", src_ip: "10.0.0.1", score: 50, severity: "medium" }),
        finding({ kind: "beacon", src_ip: "10.0.0.2", dst_ip: "5.5.5.5" }),
      ],
    });
    const after = summary({
      findings: [
        finding({ kind: "port_scan", src_ip: "10.0.0.1", score: 80, severity: "high" }), // changed
        finding({ kind: "dga", src_ip: "10.0.0.3" }), // new
      ],
    });
    const d = diffSummaries(before, after);
    expect(d.findings.added.map((f) => f.kind)).toEqual(["dga"]);
    expect(d.findings.removed.map((f) => f.kind)).toEqual(["beacon"]);
    expect(d.findings.changed[0].key).toBe("port_scan|10.0.0.1||");
    expect(d.findings.changed[0].deltas).toEqual(expect.arrayContaining([
      { field: "score", before: 50, after: 80 },
      { field: "severity", before: "medium", after: "high" },
    ]));
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

  it("diffs alerts by stable id into new / resolved / changed", () => {
    const before = summary({
      alerts: [
        alert({ id: "alert:aaaaaaaaaaaaaaaa", title: "Cleartext credentials: 10.0.0.51" }),
        alert({ id: "alert:bbbbbbbbbbbbbbbb", priority: 56, band: "review" }),
      ],
    });
    const after = summary({
      alerts: [
        alert({ id: "alert:bbbbbbbbbbbbbbbb", priority: 90, band: "act_now" }),
        alert({ id: "alert:cccccccccccccccc", title: "SYN flood: 45.77.13.37:443" }),
      ],
    });
    const d = diffSummaries(before, after);
    expect(d.alerts.added.map((a) => a.id)).toEqual(["alert:cccccccccccccccc"]);
    expect(d.alerts.removed.map((a) => a.id)).toEqual(["alert:aaaaaaaaaaaaaaaa"]);
    expect(d.alerts.changed).toHaveLength(1);
    expect(d.alerts.changed[0].key).toBe("alert:bbbbbbbbbbbbbbbb");
    expect(d.alerts.changed[0].deltas).toEqual(expect.arrayContaining([
      { field: "priority", before: 56, after: 90 },
      { field: "band", before: "review", after: "act_now" },
    ]));
  });

  it("detects alert severity / finding_count / action moves and skips identical alerts", () => {
    const before = summary({
      alerts: [
        alert({ id: "alert:1111111111111111", severity: "medium", finding_count: 2, action: "watch the host" }),
        alert({ id: "alert:2222222222222222" }),
      ],
    });
    const after = summary({
      alerts: [
        alert({ id: "alert:1111111111111111", severity: "high", finding_count: 5, action: "isolate the host" }),
        alert({ id: "alert:2222222222222222" }),
      ],
    });
    const d = diffSummaries(before, after);
    expect(d.alerts.changed).toHaveLength(1);
    expect(d.alerts.changed[0].deltas).toEqual(expect.arrayContaining([
      { field: "severity", before: "medium", after: "high" },
      { field: "finding_count", before: 2, after: 5 },
      { field: "action", before: "watch the host", after: "isolate the host" },
    ]));
  });

  it("treats summaries without alerts arrays (pre-SAC) as empty queues", () => {
    const without = summary({}); // helper never sets `alerts`
    const withAlerts = summary({ alerts: [alert({ id: "alert:ffffffffffffffff" })] });
    const d1 = diffSummaries(without, withAlerts);
    expect(d1.alerts.added.map((a) => a.id)).toEqual(["alert:ffffffffffffffff"]);
    expect(d1.alerts.removed).toHaveLength(0);
    expect(d1.alerts.changed).toHaveLength(0);
    const d2 = diffSummaries(without, without);
    expect(d2.alerts.added).toHaveLength(0);
    expect(d2.alerts.removed).toHaveLength(0);
    expect(d2.alerts.changed).toHaveLength(0);
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
