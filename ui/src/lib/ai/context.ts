import type { AnalysisOutput, Incident, IpThreat } from "../../types";

const TOP_INCIDENTS = 10, TOP_THREATS = 20, TOP_N = 10;

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

function threatLine(t: IpThreat): string {
  const tags = t.tags.length ? ` tags:[${t.tags.join(",")}]` : "";
  const ev = t.evidence.length ? ` — ${t.evidence.slice(0, 3).join("; ")}` : "";
  const rep = t.reputation?.length
    ? ` — reputation: ${t.reputation.map((r) => `${r.source}:${r.status}`).join(", ")}`
    : "";
  return `- ${t.ip} (${t.ip_class}) — ${t.severity} ${t.score}/100${t.ioc ? " IOC" : ""}${tags}${ev}${rep}`;
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

  const sc = s.severity_counts;
  if (sc) {
    lines.push(
      `## Severity\ncritical ${sc.critical}, high ${sc.high}, medium ${sc.medium}, low ${sc.low}, info ${sc.info}`,
      "",
    );
  }

  const incidents = s.incidents ?? [];
  if (incidents.length) {
    lines.push("## Incidents (correlated, kill-chain ordered)");
    for (const i of incidents.slice(0, TOP_INCIDENTS)) lines.push(incidentLine(i));
    if (incidents.length > TOP_INCIDENTS) lines.push(`…and ${incidents.length - TOP_INCIDENTS} more.`);
    lines.push("");
  }

  const threats = s.ip_threats ?? [];
  if (threats.length) {
    lines.push("## Top threat IPs");
    for (const t of threats.slice(0, TOP_THREATS)) lines.push(threatLine(t));
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
