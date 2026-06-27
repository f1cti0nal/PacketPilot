// MITRE ATT&CK coverage: aggregate the technique ids cited across a capture's behavioral findings
// into a tactic-grouped matrix. Pure and dependency-light so it stays unit-testable.
import type { Finding, Severity } from "../types";

/** ATT&CK enterprise tactics, in kill-chain order — restricted to those the engine's detectors map
 *  to, plus an "Other" bucket for ids from imported rules that aren't in the curated table. */
export type Tactic =
  | "Reconnaissance"
  | "Initial Access"
  | "Defense Evasion"
  | "Credential Access"
  | "Discovery"
  | "Lateral Movement"
  | "Collection"
  | "Command & Control"
  | "Exfiltration"
  | "Impact"
  | "Other";

export const TACTIC_ORDER: Tactic[] = [
  "Reconnaissance",
  "Initial Access",
  "Defense Evasion",
  "Credential Access",
  "Discovery",
  "Lateral Movement",
  "Collection",
  "Command & Control",
  "Exfiltration",
  "Impact",
  "Other",
];

interface TechniqueMeta {
  name: string;
  tactic: Tactic;
}

/** Curated technique → {name, tactic} for every ATT&CK id the engine emits (detect / score / rules).
 *  Unknown ids (e.g. arbitrary technique tags on imported Suricata rules) fall back to the raw id
 *  under the "Other" tactic, so the matrix degrades gracefully rather than dropping coverage. */
const TECHNIQUES: Record<string, TechniqueMeta> = {
  T1595: { name: "Active Scanning", tactic: "Reconnaissance" },
  T1133: { name: "External Remote Services", tactic: "Initial Access" },
  T1036: { name: "Masquerading", tactic: "Defense Evasion" },
  T1110: { name: "Brute Force", tactic: "Credential Access" },
  T1552: { name: "Unsecured Credentials", tactic: "Credential Access" },
  T1040: { name: "Network Sniffing", tactic: "Credential Access" },
  T1557: { name: "Adversary-in-the-Middle", tactic: "Credential Access" },
  "T1557.002": { name: "ARP Cache Poisoning", tactic: "Credential Access" },
  T1046: { name: "Network Service Discovery", tactic: "Discovery" },
  T1021: { name: "Remote Services", tactic: "Lateral Movement" },
  T1071: { name: "Application Layer Protocol", tactic: "Command & Control" },
  "T1071.004": { name: "DNS", tactic: "Command & Control" },
  T1095: { name: "Non-Application Layer Protocol", tactic: "Command & Control" },
  "T1568.002": { name: "Domain Generation Algorithms", tactic: "Command & Control" },
  T1573: { name: "Encrypted Channel", tactic: "Command & Control" },
  T1105: { name: "Ingress Tool Transfer", tactic: "Command & Control" },
  T1048: { name: "Exfil Over Alternative Protocol", tactic: "Exfiltration" },
  "T1048.003": { name: "Exfil Over Unencrypted Protocol", tactic: "Exfiltration" },
  "T1499.001": { name: "Endpoint DoS", tactic: "Impact" },
  T1496: { name: "Resource Hijacking", tactic: "Impact" },
};

/** The canonical MITRE ATT&CK page for a technique id (sub-techniques use a slash path). */
export function attackUrl(id: string): string {
  return `https://attack.mitre.org/techniques/${id.replace(".", "/")}/`;
}

export interface CoveredTechnique {
  id: string;
  name: string;
  tactic: Tactic;
  /** Worst severity among the findings citing this technique. */
  severity: Severity;
  /** Number of findings citing it. */
  count: number;
}
export interface CoveredTactic {
  tactic: Tactic;
  techniques: CoveredTechnique[];
}
export interface AttackCoverage {
  /** Covered tactics in kill-chain order (empty tactics omitted). */
  tactics: CoveredTactic[];
  techniqueCount: number;
  tacticCount: number;
}

const SEV_RANK: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
  none: 0,
};

/**
 * Aggregate the ATT&CK techniques cited across the capture's behavioral findings into a
 * tactic-grouped matrix. Each technique tracks the worst severity + how many findings cite it.
 */
export function attackCoverage(findings: Finding[]): AttackCoverage {
  const byId = new Map<string, CoveredTechnique>();
  for (const f of findings) {
    for (const id of f.attack) {
      const ex = byId.get(id);
      if (ex) {
        ex.count += 1;
        if (SEV_RANK[f.severity] > SEV_RANK[ex.severity]) ex.severity = f.severity;
      } else {
        const meta = TECHNIQUES[id];
        byId.set(id, {
          id,
          name: meta?.name ?? id,
          tactic: meta?.tactic ?? "Other",
          severity: f.severity,
          count: 1,
        });
      }
    }
  }
  const tactics: CoveredTactic[] = TACTIC_ORDER.map((tactic) => ({
    tactic,
    techniques: [...byId.values()]
      .filter((t) => t.tactic === tactic)
      .sort((a, b) => SEV_RANK[b.severity] - SEV_RANK[a.severity] || a.id.localeCompare(b.id)),
  })).filter((t) => t.techniques.length > 0);
  return { tactics, techniqueCount: byId.size, tacticCount: tactics.length };
}
