// Shared kill-chain / attack-chain helpers: stage labels, the load-bearing per-finding metric,
// stage colours, MITRE technique names, and the swimlane layout used by the AttackChain views.
// NB: KIND_STAGE / metric / stageColor are mirrored verbatim from cockpit/IncidentHero.tsx; a
// follow-up should have IncidentHero import them from here so the two can never drift.
import type { AttackChain, ChainStep, EdgeKind, Finding, FindingKind } from "../types";
import { durationHumanNs, humanNumber } from "./format";

/** Kill-chain stage label per finding kind (mirrors the engine's `stage_label`). */
export const KIND_STAGE: Record<FindingKind, string> = {
  host_sweep: "Discovery",
  brute_force: "Credential Access",
  cleartext_creds: "Credential Access",
  pii_exposure: "Collection",
  lateral_movement: "Lateral Movement",
  beacon: "Command & Control",
  dns_tunnel: "Command & Control",
  data_exfil: "Exfiltration",
  rule_match: "Detection",
  tls_cert_health: "Command & Control",
  weak_tls: "Collection",
  icmp_tunnel: "Exfiltration",
  dga: "Command & Control",
  port_scan: "Discovery",
  arp_spoof: "Collection",
  syn_flood: "Impact",
  suspicious_ua: "Discovery",
  disguised_download: "Command & Control",
  cryptomining: "Impact",
  malware_download: "Command & Control",
  malware_signature: "Command & Control",
  exposed_remote_access: "Lateral Movement",
  ioc_match: "Detection",
};

/** The noun for a finding kind's contributing count (e.g. "contacts", "hosts"). */
export const CONTACT_NOUN: Partial<Record<FindingKind, string>> = {
  beacon: "contacts",
  host_sweep: "hosts",
  brute_force: "attempts",
  lateral_movement: "hosts",
  dns_tunnel: "queries",
  dga: "domains",
  port_scan: "ports",
  arp_spoof: "MACs",
  syn_flood: "half-open conns",
  suspicious_ua: "requests",
  cleartext_creds: "exposures",
  disguised_download: "downloads",
  cryptomining: "messages",
  malware_download: "files",
  exposed_remote_access: "sessions",
};

/** The load-bearing metric for a finding (what makes it real). */
export function metric(f: Finding): string {
  const parts: string[] = [];
  if (f.interval_ns != null) parts.push(`every ${durationHumanNs(f.interval_ns)}`);
  if (f.jitter_cv != null) parts.push(`CV ${f.jitter_cv.toFixed(3)}`);
  if (f.contacts != null) parts.push(`${humanNumber(f.contacts)} ${CONTACT_NOUN[f.kind] ?? ""}`.trim());
  if (parts.length === 0 && f.dst_ip) parts.push(`${f.dst_ip}${f.dst_port ? `:${f.dst_port}` : ""}`);
  return parts.join(" · ");
}

/** Interpolate a stage node colour along cyan → violet → critical-red for step `i` of `n`. */
export function stageColor(i: number, n: number): string {
  const t = n <= 1 ? 1 : i / (n - 1);
  if (t <= 0.5)
    return `color-mix(in srgb, var(--color-spine-violet) ${Math.round((t / 0.5) * 100)}%, var(--color-accent))`;
  return `color-mix(in srgb, var(--color-sev-critical) ${Math.round(((t - 0.5) / 0.5) * 100)}%, var(--color-spine-violet))`;
}

/** MITRE ATT&CK technique id → human name (mirrors the engine's `technique_name`). */
const TECHNIQUE_NAME: Record<string, string> = {
  T1046: "Network Service Discovery",
  T1595: "Active Scanning",
  T1110: "Brute Force",
  T1552: "Unsecured Credentials",
  T1021: "Remote Services",
  T1133: "External Remote Services",
  T1071: "Application Layer Protocol",
  "T1071.004": "Application Layer Protocol: DNS",
  T1048: "Exfiltration Over Alternative Protocol",
  T1095: "Non-Application Layer Protocol",
  "T1568.002": "Dynamic Resolution: DGA",
  T1557: "Adversary-in-the-Middle",
  "T1557.002": "AiTM: ARP Cache Poisoning",
  "T1499.001": "Endpoint DoS: Flood",
  T1036: "Masquerading",
  T1105: "Ingress Tool Transfer",
  T1496: "Resource Hijacking",
  T1040: "Network Sniffing",
  T1573: "Encrypted Channel",
  T1027: "Obfuscated Files or Information",
};

/** Resolve a technique id to its name; unknown ids return the id itself (never throws). */
export function techniqueName(id: string): string {
  return TECHNIQUE_NAME[id] ?? id;
}

// ---- Swimlane layout -------------------------------------------------------------------------

export interface LanePos {
  host: string;
  y: number;
}
export interface NodePos {
  order: number;
  x: number;
  y: number;
  step: ChainStep;
}
export interface ArrowPos {
  fromOrder: number;
  toOrder: number;
  kind: EdgeKind;
  x1: number;
  y1: number;
  x2: number;
  y2: number;
}
export interface ChainLayout {
  width: number;
  height: number;
  laneHeight: number;
  padX: number;
  lanes: LanePos[];
  nodes: NodePos[];
  arrows: ArrowPos[];
}

export interface LayoutOpts {
  width?: number;
  laneHeight?: number;
  padX?: number;
}

/**
 * Deterministic horizontal-swimlane layout for an attack chain: one lane per host (in the chain's
 * first-seen host order), each step placed on its actor's lane with x scaled by `first_seen_ns`
 * (falling back to even order-spacing when timestamps are missing or all-equal). Pure — no DOM.
 */
export function computeChainLayout(chain: AttackChain, opts: LayoutOpts = {}): ChainLayout {
  const width = opts.width ?? 720;
  const laneHeight = opts.laneHeight ?? 64;
  const padX = opts.padX ?? 44;

  const laneY = new Map<string, number>();
  const lanes: LanePos[] = chain.hosts.map((host, i) => {
    const y = i * laneHeight + laneHeight / 2;
    laneY.set(host, y);
    return { host, y };
  });
  const height = Math.max(laneHeight, chain.hosts.length * laneHeight);

  const times = chain.steps
    .map((s) => s.first_seen_ns)
    .filter((t): t is number => t != null);
  const tMin = times.length ? Math.min(...times) : 0;
  const tMax = times.length ? Math.max(...times) : 0;
  const span = tMax - tMin;
  const innerW = Math.max(1, width - padX * 2);
  const n = chain.steps.length;

  const nodes: NodePos[] = chain.steps.map((step, i) => {
    let frac: number;
    if (span > 0 && step.first_seen_ns != null) {
      frac = (step.first_seen_ns - tMin) / span;
    } else {
      frac = n > 1 ? i / (n - 1) : 0;
    }
    const x = padX + frac * innerW;
    const y = laneY.get(step.actor) ?? laneHeight / 2;
    return { order: step.order, x, y, step };
  });

  const posByOrder = new Map(nodes.map((nd) => [nd.order, nd]));
  const arrows: ArrowPos[] = chain.edges.map((e) => {
    const a = posByOrder.get(e.from);
    const b = posByOrder.get(e.to);
    return {
      fromOrder: e.from,
      toOrder: e.to,
      kind: e.kind,
      x1: a?.x ?? 0,
      y1: a?.y ?? 0,
      x2: b?.x ?? 0,
      y2: b?.y ?? 0,
    };
  });

  return { width, height, laneHeight, padX, lanes, nodes, arrows };
}
