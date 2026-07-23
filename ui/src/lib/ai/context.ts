import type { Alert, AnalysisOutput, AttackChain, DomainThreat, Incident, IpThreat } from "../../types";
import { bandLabel } from "../alerts";

const TOP_INCIDENTS = 10, TOP_THREATS = 20, TOP_N = 10, TOP_CHAINS = 3, TOP_ALERTS = 5;

function fmtBytes(n: number): string {
  if (n >= 1e9) return `${(n / 1e9).toFixed(1)} GB`;
  if (n >= 1e6) return `${(n / 1e6).toFixed(1)} MB`;
  if (n >= 1e3) return `${(n / 1e3).toFixed(1)} KB`;
  return `${n} B`;
}

function incidentLine(i: Incident): string {
  const atk = i.attack.length ? ` [${i.attack.join(",")}]` : "";
  const stages = i.stages.length ? ` (stages: ${i.stages.join(" → ")})` : "";
  return `- **${i.host}** — ${i.severity} ${i.score}/100 — ${i.title}${stages}${atk}\n  ${i.narrative}`;
}

/** One-line incident reference for a host already detailed in a section above. */
function incidentLineBrief(i: Incident, ref = "see attack chains above"): string {
  return `- **${i.host}** — ${i.severity} ${i.score}/100 — ${i.title} (${ref})`;
}

/** Render one ranked alert as a single self-sufficient triage line (engine rollups only). */
function alertLine(a: Alert): string {
  const hostname = a.context?.actor?.hostname;
  const actor = hostname ? `${a.actor} (${hostname})` : a.actor;
  const why = a.priority_terms.map((t) => t.label).join(", ");
  return `- [${bandLabel(a.band).toUpperCase()} p=${a.priority} conf ${a.confidence}%] ${a.title} — actor ${actor} — why: ${why} — do: ${a.action}`;
}

/** Render one reconstructed attack chain as a compact, labeled block (engine rollups only). */
function chainSection(c: AttackChain): string[] {
  const out: string[] = [];
  const camp = c.campaign_id ? ` [campaign ${c.campaign_id}]` : "";
  out.push(`- **${c.title}** — ${c.severity} ${c.score}/100 (conf ${c.confidence})${camp}`);
  out.push(`  spine: ${c.tactics.map((t) => t.tactic).join(" → ")}`);
  const pivotTargets = new Set(c.edges.filter((e) => e.kind === "pivot").map((e) => e.to));
  for (const step of c.steps) {
    // '↦' marks the arrival of a cross-host pivot so the model narrates the movement.
    const arrow = pivotTargets.has(step.order) ? "↦" : "→";
    const peer = step.peer ? ` ${arrow} ${step.peer}` : "";
    const tech = step.techniques[0] ? ` — ${step.techniques[0].id} ${step.techniques[0].name}` : "";
    const ev = step.evidence ? ` — ${step.evidence}` : "";
    out.push(`  - [${step.tactic}] ${step.actor}${peer}${tech}${ev}`);
  }
  const pivots = c.edges.filter((e) => e.kind === "pivot");
  if (pivots.length) {
    const pivotStr = pivots
      .map((e) => {
        const from = c.steps.find((s) => s.order === e.from);
        const to = c.steps.find((s) => s.order === e.to);
        return `${from?.actor ?? "?"} → ${to?.actor ?? "?"}${e.via_kind ? ` (via ${e.via_kind})` : ""}`;
      })
      .join("; ");
    out.push(`  pivots: ${pivotStr}`);
  }
  out.push(`  ${c.narrative}`);
  return out;
}

function domainLine(d: DomainThreat): string {
  const verdicts = d.reputation ?? [];
  const malSources = verdicts.filter((r) => r.status === "malicious").map((r) => r.source);
  if (malSources.length) {
    return `- ${d.host} — ${fmtBytes(d.bytes)}, ${d.flows} flows — MALICIOUS (${malSources.join(", ")})`;
  }
  const rep = verdicts.length
    ? ` — reputation: ${verdicts.map((r) => `${r.source}:${r.status}`).join(", ")}`
    : "";
  return `- ${d.host} — ${fmtBytes(d.bytes)}, ${d.flows} flows${rep}`;
}

function threatLine(t: IpThreat): string {
  const tags = t.tags.length ? ` tags:[${t.tags.join(",")}]` : "";
  const ev = t.evidence.length ? ` — ${t.evidence.slice(0, 3).join("; ")}` : "";
  const rep = t.reputation?.length
    ? ` — reputation: ${t.reputation.map((r) => `${r.source}:${r.status}`).join(", ")}`
    : "";
  const fp = t.fingerprints?.length
    ? ` — fingerprint: ${t.fingerprints.map((f) => f.label).join(", ")}`
    : "";
  return `- ${t.ip} (${t.ip_class}) — ${t.severity} ${t.score}/100${t.ioc ? " IOC" : ""}${tags}${ev}${rep}${fp}`;
}

/** Curate the derived analysis summary into a compact, labeled context for the LLM.
 * Only rollups the engine already computed — never raw packets/payloads/flows. */
export function buildContext(output: AnalysisOutput): string {
  const s = output.summary;
  const lines: string[] = ["# PacketPilot analysis summary", ""];

  const durSec = Math.round((s.duration_ns ?? 0) / 1e9);
  lines.push(
    `Capture: ${s.total_packets} packets, ${fmtBytes(s.total_bytes)}, ${s.total_flows} flows, ` +
      `${s.unique_hosts} hosts, ~${durSec}s.`,
    "",
  );

  // The ranked queue leads the brief — it is the engine's own triage order, so the model
  // narrates from the same priorities the analyst sees.
  const alerts = s.alerts ?? [];
  const alertCovered = new Set<string>();
  if (alerts.length) {
    lines.push("## Alert queue (ranked, deduplicated — triage in this order)");
    for (const a of alerts.slice(0, TOP_ALERTS)) {
      lines.push(alertLine(a));
      (a.incident_hosts ?? []).forEach((h) => alertCovered.add(h));
    }
    if (alerts.length > TOP_ALERTS) lines.push(`…and ${alerts.length - TOP_ALERTS} more.`);
    lines.push("");
  }

  const sc = s.severity_counts;
  if (sc) {
    lines.push(
      `## Severity\ncritical ${sc.critical}, high ${sc.high}, medium ${sc.medium}, low ${sc.low}, info ${sc.info}`,
      "",
    );
  }

  const chains = s.attack_chains ?? [];
  const coveredHosts = new Set<string>();
  if (chains.length) {
    lines.push("## Reconstructed attack chains (multi-host, temporally ordered)");
    for (const c of chains.slice(0, TOP_CHAINS)) {
      lines.push(...chainSection(c));
      c.hosts.forEach((h) => coveredHosts.add(h));
    }
    if (chains.length > TOP_CHAINS) lines.push(`…and ${chains.length - TOP_CHAINS} more.`);
    lines.push("");
  }

  const incidents = s.incidents ?? [];
  if (incidents.length) {
    lines.push("## Incidents (correlated, kill-chain ordered)");
    for (const i of incidents.slice(0, TOP_INCIDENTS)) {
      // A host already detailed in a chain or covered by an alert above is demoted to a
      // one-liner so the narrative budget is not double-spent.
      lines.push(
        coveredHosts.has(i.host)
          ? incidentLineBrief(i)
          : alertCovered.has(i.host)
            ? incidentLineBrief(i, "see alert queue above")
            : incidentLine(i),
      );
    }
    if (incidents.length > TOP_INCIDENTS) lines.push(`…and ${incidents.length - TOP_INCIDENTS} more.`);
    lines.push("");
  }

  const threats = s.ip_threats ?? [];
  if (threats.length) {
    lines.push("## Top threat IPs");
    for (const t of threats.slice(0, TOP_THREATS)) lines.push(threatLine(t));
    lines.push("");
  }

  const domains = s.domain_threats ?? [];
  if (domains.length) {
    const isMal = (d: DomainThreat) => (d.reputation ?? []).some((r) => r.status === "malicious");
    const malicious = domains.filter(isMal);
    const rest = domains.filter((d) => !isMal(d)).slice(0, TOP_N);
    const shown = [...malicious, ...rest];
    lines.push("## Notable domains (SNI)");
    for (const d of shown) lines.push(domainLine(d));
    lines.push("");
  }

  if (s.category_breakdown?.length) {
    lines.push("## Traffic categories");
    for (const c of s.category_breakdown.slice(0, TOP_N)) {
      lines.push(`- ${c.category}: ${c.flows} flows, ${fmtBytes(c.bytes)}`);
    }
    lines.push("");
  }

  if (s.top_talkers?.length) {
    lines.push("## Top talkers (by bytes)");
    for (const t of s.top_talkers.slice(0, TOP_N)) lines.push(`- ${t.ip}: ${fmtBytes(t.bytes)}, ${t.flows} flows`);
    lines.push("");
  }

  return lines.join("\n");
}
