// Client-side capture diffing for the Compare tab. The alert-diff semantics mirror the engine's
// `diff_alerts` (`engine/crates/ppcap-core/src/detect/alerts.rs`) — the house lib-port convention
// (see `lib/forecast.ts`): stories match by their stable alert id, added = new, removed = resolved,
// changed = in both with a rank/shape move.
import type { Alert, IpThreat, Incident, Finding, Summary, SeverityCounts, RepStatus } from "../types";

export interface FieldDelta { field: string; before: string | number; after: string | number; }
export interface Changed<T> { key: string; before: T; after: T; deltas: FieldDelta[]; }
export interface DiffResult<T> { added: T[]; removed: T[]; changed: Changed<T>[]; }
export interface SeverityDelta { band: keyof SeverityCounts; before: number; after: number; delta: number; }
export interface SummaryDiff {
  /** Alert-queue stories keyed by their stable alert id: added = new stories, removed = resolved. */
  alerts: DiffResult<Alert>;
  threats: DiffResult<IpThreat>;
  incidents: DiffResult<Incident>;
  /** Behavioral findings, keyed by kind + endpoints: added = new in `after`, removed = resolved. */
  findings: DiffResult<Finding>;
  severity: SeverityDelta[];
  /** Count of entities (threat IPs + incident hosts) present in BOTH captures. */
  shared: number;
}

/** Generic keyed diff: added = key only in `after`, removed = key only in `before`, changed = key in both with deltas. */
export function diffByKey<T>(
  before: T[],
  after: T[],
  keyOf: (t: T) => string,
  deltasOf: (before: T, after: T) => FieldDelta[],
): DiffResult<T> {
  const beforeMap = new Map(before.map((t) => [keyOf(t), t]));
  const afterMap = new Map(after.map((t) => [keyOf(t), t]));
  const added = after.filter((t) => !beforeMap.has(keyOf(t)));
  const removed = before.filter((t) => !afterMap.has(keyOf(t)));
  const changed: Changed<T>[] = [];
  for (const [key, b] of beforeMap) {
    const a = afterMap.get(key);
    if (!a) continue;
    const deltas = deltasOf(b, a);
    if (deltas.length > 0) changed.push({ key, before: b, after: a, deltas });
  }
  changed.sort((x, y) => (x.key < y.key ? -1 : x.key > y.key ? 1 : 0));
  return { added, removed, changed };
}

/** A field delta for a sorted set comparison, or null when the sets are equal. */
function setDelta(field: string, before: string[], after: string[]): FieldDelta | null {
  const b = [...before].sort().join(",");
  const a = [...after].sort().join(",");
  if (b === a) return null;
  return { field, before: b || "(none)", after: a || "(none)" };
}

const REP_RANK: Record<RepStatus, number> = { malicious: 5, benign: 4, unknown: 3, clean: 2, notfound: 1, unavailable: 0 };
function worstRep(t: IpThreat): string {
  if (!t.reputation || t.reputation.length === 0) return "";
  return [...t.reputation].sort((x, y) => REP_RANK[y.status] - REP_RANK[x.status])[0].status;
}

function threatDeltas(before: IpThreat, after: IpThreat): FieldDelta[] {
  const d: FieldDelta[] = [];
  if (before.score !== after.score) d.push({ field: "score", before: before.score, after: after.score });
  if (before.severity !== after.severity) d.push({ field: "severity", before: before.severity, after: after.severity });
  if (before.ioc !== after.ioc) d.push({ field: "ioc", before: before.ioc ? "yes" : "no", after: after.ioc ? "yes" : "no" });
  const tags = setDelta("tags", before.tags, after.tags); if (tags) d.push(tags);
  const attack = setDelta("attack", before.attack, after.attack); if (attack) d.push(attack);
  const rb = worstRep(before), ra = worstRep(after);
  if (rb !== ra) d.push({ field: "reputation", before: rb || "(none)", after: ra || "(none)" });
  return d;
}

function incidentDeltas(before: Incident, after: Incident): FieldDelta[] {
  const d: FieldDelta[] = [];
  if (before.score !== after.score) d.push({ field: "score", before: before.score, after: after.score });
  if (before.severity !== after.severity) d.push({ field: "severity", before: before.severity, after: after.severity });
  const stages = setDelta("stages", before.stages, after.stages); if (stages) d.push(stages);
  if (before.findings.length !== after.findings.length)
    d.push({ field: "findings", before: before.findings.length, after: after.findings.length });
  return d;
}

/** Stable identity for a behavioral finding across captures: its kind plus the endpoints it names. */
const findingKey = (f: Finding): string =>
  `${f.kind}|${f.src_ip}|${f.dst_ip ?? ""}|${f.dst_port ?? ""}`;

function findingDeltas(before: Finding, after: Finding): FieldDelta[] {
  const d: FieldDelta[] = [];
  if (before.score !== after.score) d.push({ field: "score", before: before.score, after: after.score });
  if (before.severity !== after.severity) d.push({ field: "severity", before: before.severity, after: after.severity });
  return d;
}

function alertDeltas(before: Alert, after: Alert): FieldDelta[] {
  const d: FieldDelta[] = [];
  if (before.priority !== after.priority) d.push({ field: "priority", before: before.priority, after: after.priority });
  if (before.band !== after.band) d.push({ field: "band", before: before.band, after: after.band });
  if (before.severity !== after.severity) d.push({ field: "severity", before: before.severity, after: after.severity });
  if (before.finding_count !== after.finding_count)
    d.push({ field: "finding_count", before: before.finding_count, after: after.finding_count });
  if (before.action !== after.action) d.push({ field: "action", before: before.action, after: after.action });
  return d;
}

const SEV_BANDS: (keyof SeverityCounts)[] = ["critical", "high", "medium", "low", "info"];

export function diffSummaries(before: Summary, after: Summary): SummaryDiff {
  const alerts = diffByKey(before.alerts ?? [], after.alerts ?? [], (a) => a.id, alertDeltas);
  const threats = diffByKey(before.ip_threats ?? [], after.ip_threats ?? [], (t) => t.ip, threatDeltas);
  const incidents = diffByKey(before.incidents ?? [], after.incidents ?? [], (i) => i.host, incidentDeltas);
  const findings = diffByKey(before.findings ?? [], after.findings ?? [], findingKey, findingDeltas);
  const severity: SeverityDelta[] = SEV_BANDS.map((band) => {
    const b = before.severity_counts?.[band] ?? 0;
    const a = after.severity_counts?.[band] ?? 0;
    return { band, before: b, after: a, delta: a - b };
  });
  const beforeKeys = new Set<string>([
    ...(before.ip_threats ?? []).map((t) => `ip:${t.ip}`),
    ...(before.incidents ?? []).map((i) => `host:${i.host}`),
  ]);
  let shared = 0;
  for (const t of after.ip_threats ?? []) if (beforeKeys.has(`ip:${t.ip}`)) shared++;
  for (const i of after.incidents ?? []) if (beforeKeys.has(`host:${i.host}`)) shared++;
  return { alerts, threats, incidents, findings, severity, shared };
}
