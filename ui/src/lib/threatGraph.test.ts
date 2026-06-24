import { describe, it, expect } from "vitest";
import { buildThreatGraph } from "./threatGraph";
import type { Finding, IpThreat } from "../types";

const f = (
  over: Partial<Finding> & Pick<Finding, "kind" | "severity" | "score" | "src_ip">,
): Finding => ({
  dst_ip: null, dst_port: null, attack: [], evidence: [],
  interval_ns: null, jitter_cv: null, contacts: null, title: "", ...over,
});

describe("buildThreatGraph", () => {
  it("builds nodes for involved hosts and edges for src->dst findings, deterministically", () => {
    const findings = [
      f({ kind: "beacon", severity: "high", score: 70, src_ip: "10.0.0.5", dst_ip: "45.77.13.37" }),
      f({ kind: "data_exfil", severity: "high", score: 72, src_ip: "10.0.0.5", dst_ip: "185.220.101.5" }),
    ];
    const m = buildThreatGraph(findings, []);
    expect(m.nodes.map((n) => n.ip).sort()).toEqual(["10.0.0.5", "185.220.101.5", "45.77.13.37"]);
    expect(m.edges).toHaveLength(2);
    expect(m.edges.every((e) => e.from === "10.0.0.5")).toBe(true);
    expect(m.edges.every((e) => e.path.startsWith("M"))).toBe(true);
    for (const n of m.nodes) {
      expect(Number.isFinite(n.x) && Number.isFinite(n.y)).toBe(true);
      expect(n.x).toBeGreaterThanOrEqual(0);
      expect(n.x).toBeLessThanOrEqual(m.width);
    }
    expect(buildThreatGraph(findings, [])).toEqual(m);
  });

  it("skips findings with no destination and dedupes edges keeping the worst severity", () => {
    const findings = [
      f({ kind: "host_sweep", severity: "high", score: 65, src_ip: "10.0.0.5" }), // no dst -> no edge
      f({ kind: "beacon", severity: "medium", score: 50, src_ip: "10.0.0.5", dst_ip: "8.8.8.8" }),
      f({ kind: "beacon", severity: "critical", score: 90, src_ip: "10.0.0.5", dst_ip: "8.8.8.8" }),
    ];
    const m = buildThreatGraph(findings, []);
    expect(m.edges).toHaveLength(1);
    expect(m.edges[0].severity).toBe("critical");
  });

  it("caps nodes at maxNodes and reports the remainder as truncated", () => {
    const findings = Array.from({ length: 20 }, (_, i) =>
      f({ kind: "beacon", severity: "high", score: 100 - i, src_ip: "10.0.0.1", dst_ip: `203.0.0.${i + 1}` }),
    );
    const m = buildThreatGraph(findings, [], { maxNodes: 6 });
    expect(m.nodes).toHaveLength(6);
    expect(m.truncated).toBe(15); // 21 distinct hosts - 6 kept
    expect(m.edges.every((e) => m.nodes.some((n) => n.ip === e.to))).toBe(true);
  });

  it("folds the authoritative per-IP threat severity/score into involved nodes", () => {
    const findings = [f({ kind: "beacon", severity: "low", score: 30, src_ip: "10.0.0.5", dst_ip: "9.9.9.9" })];
    const threats: IpThreat[] = [
      { ip: "9.9.9.9", ip_class: "public", severity: "critical", score: 95, flows: 1, bytes: 1, ioc: true, tags: [], attack: [], evidence: [] },
    ];
    const node = buildThreatGraph(findings, threats).nodes.find((n) => n.ip === "9.9.9.9")!;
    expect(node.severity).toBe("critical");
    expect(node.score).toBe(95);
  });
});
