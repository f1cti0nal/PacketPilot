import { describe, it, expect } from "vitest";
import { attackCoverage, attackUrl } from "./attack";
import type { Finding, Severity } from "../types";

const f = (severity: Severity, attack: string[]): Finding => ({
  kind: "port_scan",
  severity,
  score: 50,
  title: "t",
  src_ip: "10.0.0.1",
  dst_ip: null,
  dst_port: null,
  attack,
  evidence: [],
  interval_ns: null,
  jitter_cv: null,
  contacts: null,
});

describe("attackCoverage", () => {
  it("groups techniques by tactic in kill-chain order", () => {
    const cov = attackCoverage([
      f("high", ["T1046"]), // Discovery
      f("critical", ["T1071"]), // Command & Control
      f("medium", ["T1595"]), // Reconnaissance
    ]);
    expect(cov.tacticCount).toBe(3);
    expect(cov.techniqueCount).toBe(3);
    expect(cov.tactics.map((t) => t.tactic)).toEqual([
      "Reconnaissance",
      "Discovery",
      "Command & Control",
    ]);
  });

  it("tracks the worst severity and the finding count per technique", () => {
    const cov = attackCoverage([f("medium", ["T1046"]), f("critical", ["T1046"]), f("low", ["T1046"])]);
    const disc = cov.tactics.find((t) => t.tactic === "Discovery")!;
    expect(disc.techniques[0]).toMatchObject({ id: "T1046", severity: "critical", count: 3 });
  });

  it("names known techniques, including sub-techniques", () => {
    const all = attackCoverage([f("high", ["T1071.004", "T1557.002"])]).tactics.flatMap((t) => t.techniques);
    expect(all.find((t) => t.id === "T1071.004")?.name).toBe("DNS");
    expect(all.find((t) => t.id === "T1557.002")?.name).toBe("ARP Cache Poisoning");
  });

  it("maps an unknown technique id to the Other tactic with the raw id as its name", () => {
    const other = attackCoverage([f("high", ["T9999"])]).tactics.find((t) => t.tactic === "Other")!;
    expect(other.techniques[0]).toMatchObject({ id: "T9999", name: "T9999", tactic: "Other" });
  });

  it("returns empty coverage when no finding carries a technique", () => {
    expect(attackCoverage([f("high", []), f("low", [])])).toEqual({
      tactics: [],
      techniqueCount: 0,
      tacticCount: 0,
    });
    expect(attackCoverage([]).tacticCount).toBe(0);
  });

  it("builds the MITRE url (sub-techniques use a slash path)", () => {
    expect(attackUrl("T1133")).toBe("https://attack.mitre.org/techniques/T1133/");
    expect(attackUrl("T1071.004")).toBe("https://attack.mitre.org/techniques/T1071/004/");
  });
});
