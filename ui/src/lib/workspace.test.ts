import { describe, it, expect } from "vitest";
import { captureVerdict, workspaceRollup, TREND_WINDOW } from "./workspace";
import { makeOutput } from "../test/fixtures";
import type {
  AnalysisOutput,
  Finding,
  FindingKind,
  Incident,
  RecentEntry,
  Severity,
} from "../types";

const mkFinding = (kind: FindingKind, severity: Severity): Finding => ({
  kind,
  severity,
  score: 50,
  title: `${kind} finding`,
  src_ip: "10.0.0.1",
  dst_ip: null,
  dst_port: null,
  attack: [],
  evidence: [],
  interval_ns: null,
  jitter_cv: null,
  contacts: null,
});

const mkIncident = (severity: Severity): Incident => ({
  host: "10.0.0.1",
  severity,
  score: 80,
  title: "incident",
  narrative: "",
  stages: [],
  attack: [],
  findings: [],
});

function outputWith(findings: Finding[], incidents: Incident[] = []): AnalysisOutput {
  const base = makeOutput();
  return { ...base, summary: { ...base.summary, findings, incidents } };
}

function entry(
  id: string,
  opts: { analyzedAt?: number; flowCount?: number; summary?: AnalysisOutput } = {},
): RecentEntry {
  return {
    id,
    name: `${id}.pcap`,
    sizeBytes: 1000,
    analyzedAt: opts.analyzedAt ?? 1000,
    engineVersion: "0.1.0",
    origin: "wasm",
    flowCount: opts.flowCount ?? 0,
    flowsCached: false,
    summary: opts.summary ?? outputWith([]),
  };
}

describe("captureVerdict", () => {
  it("reports a clean verdict when there are no findings or incidents", () => {
    const v = captureVerdict(outputWith([]));
    expect(v).toEqual({ worst: "none", worstCount: 0, findings: 0, threatScore: 0 });
  });

  it("derives worst severity and count from findings when no incidents exist", () => {
    const v = captureVerdict(
      outputWith([
        mkFinding("port_scan", "high"),
        mkFinding("dga", "medium"),
        mkFinding("syn_flood", "high"),
      ]),
    );
    expect(v.worst).toBe("high");
    expect(v.worstCount).toBe(2); // two high findings
    expect(v.findings).toBe(3);
    expect(v.threatScore).toBe(4 + 3 + 4); // high + medium + high
  });

  it("prefers correlated incidents over raw findings for the verdict", () => {
    const v = captureVerdict(
      outputWith([mkFinding("beacon", "high")], [mkIncident("critical")]),
    );
    expect(v.worst).toBe("critical"); // from the incident, not the high finding
    expect(v.worstCount).toBe(1);
    expect(v.findings).toBe(1); // findings count is unaffected
    expect(v.threatScore).toBe(4); // threatScore still weights raw findings (one high)
  });

  it("tolerates summaries missing the findings/incidents arrays", () => {
    expect(captureVerdict(makeOutput({})).findings).toBeGreaterThanOrEqual(0);
  });
});

describe("workspaceRollup", () => {
  // Newest-first, as recordRecent stores them.
  const eC = entry("c", {
    analyzedAt: 3000,
    flowCount: 30,
    summary: outputWith([mkFinding("beacon", "critical"), mkFinding("port_scan", "high")]),
  });
  const eB = entry("b", {
    analyzedAt: 2000,
    flowCount: 20,
    summary: outputWith([mkFinding("port_scan", "high")]),
  });
  const eA = entry("a", {
    analyzedAt: 1000,
    flowCount: 10,
    summary: outputWith([mkFinding("port_scan", "high"), mkFinding("dga", "medium")]),
  });
  const recent = [eC, eB, eA];

  it("sums captures, flows, findings, and critical/high across the workspace", () => {
    const r = workspaceRollup(recent);
    expect(r.captures).toBe(3);
    expect(r.totalFlows).toBe(60);
    expect(r.totalFindings).toBe(5);
    expect(r.criticalHigh).toBe(4); // eA:1 high, eB:1 high, eC:1 critical + 1 high
  });

  it("ranks recurring kinds by how many captures they appear in", () => {
    const r = workspaceRollup(recent);
    expect(r.recurring[0]).toEqual({ kind: "port_scan", label: "Port Scan", captures: 3 });
    // beacon and dga each appear once; tie broken alphabetically by label.
    expect(r.recurring.map((x) => x.kind)).toEqual(["port_scan", "beacon", "dga"]);
  });

  it("orders the trend oldest -> newest and flags a rising workspace", () => {
    const r = workspaceRollup(recent);
    // threatScore: eA = 4+3, eB = 4, eC = 5+4 ; chronological = [eA, eB, eC]
    expect(r.trend).toEqual([7, 4, 9]);
    expect(r.trendRising).toBe(true);
  });

  it("caps the trend window to the most recent captures", () => {
    const many = Array.from({ length: TREND_WINDOW + 4 }, (_, i) =>
      entry(`e${i}`, { analyzedAt: i, summary: outputWith([mkFinding("port_scan", "low")]) }),
    ).reverse(); // newest-first
    expect(workspaceRollup(many).trend).toHaveLength(TREND_WINDOW);
  });

  it("returns zeroed stats for an empty workspace", () => {
    const r = workspaceRollup([]);
    expect(r).toMatchObject({ captures: 0, totalFlows: 0, totalFindings: 0, criticalHigh: 0 });
    expect(r.trend).toEqual([]);
    expect(r.trendRising).toBe(false);
    expect(r.recurring).toEqual([]);
  });
});
