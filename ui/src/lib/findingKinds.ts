import {
  Activity,
  ArrowUpFromLine,
  Bug,
  Globe,
  KeyRound,
  Network,
  Radio,
  Radar,
  ScreenShare,
  Unlock,
  Crosshair,
  Factory,
  Fingerprint,
  FileWarning,
  FileSearch,
  Gauge,
  Pickaxe,
  VenetianMask,
  ScanSearch,
  ShieldAlert,
  ShieldOff,
  Shuffle,
  Split,
  Waves,
  Waypoints,
  type LucideIcon,
} from "lucide-react";
import type { FindingKind } from "../types";

export interface KindMeta {
  label: string;
  Icon: LucideIcon;
}

/**
 * Canonical FindingKind → {label, Icon}. Single source of truth — IncidentHero,
 * DetailFlyout (and any future incident surface) import from here so the labels can
 * never drift apart (they previously diverged across three independent copies).
 */
export const KIND_META: Record<FindingKind, KindMeta> = {
  beacon: { label: "C2 Beacon", Icon: Radio },
  host_sweep: { label: "Host Sweep", Icon: Radar },
  brute_force: { label: "Brute Force", Icon: KeyRound },
  cleartext_creds: { label: "Cleartext Creds", Icon: Unlock },
  pii_exposure: { label: "PII Exposure", Icon: FileWarning },
  lateral_movement: { label: "Lateral Movement", Icon: Network },
  data_exfil: { label: "Data Exfiltration", Icon: ArrowUpFromLine },
  dns_tunnel: { label: "DNS Tunnel", Icon: Globe },
  rule_match: { label: "Signature Match", Icon: Crosshair },
  tls_cert_health: { label: "TLS Cert", Icon: ShieldAlert },
  weak_tls: { label: "Weak TLS", Icon: ShieldOff },
  icmp_tunnel: { label: "ICMP Tunnel", Icon: Waypoints },
  dga: { label: "DGA Domains", Icon: Shuffle },
  port_scan: { label: "Port Scan", Icon: ScanSearch },
  arp_spoof: { label: "ARP Spoofing", Icon: Split },
  syn_flood: { label: "SYN Flood", Icon: Waves },
  suspicious_ua: { label: "Attack Tool", Icon: Bug },
  disguised_download: { label: "Disguised Download", Icon: VenetianMask },
  cryptomining: { label: "Cryptomining", Icon: Pickaxe },
  malware_download: { label: "Malware Download", Icon: FileWarning },
  malware_signature: { label: "Malware Signature", Icon: FileSearch },
  exposed_remote_access: { label: "Exposed Remote Access", Icon: ScreenShare },
  ics_control_command: { label: "ICS Control", Icon: Factory },
  baseline_deviation: { label: "Baseline Deviation", Icon: Gauge },
  ioc_match: { label: "IOC Match", Icon: Fingerprint },
};

/** Title-case a raw kind token, e.g. "pii_exposure" → "Pii Exposure" (fallback only). */
function titleCase(token: string): string {
  return token
    .split("_")
    .map((w) => (w ? w[0].toUpperCase() + w.slice(1) : w))
    .join(" ");
}

/**
 * Safe lookup. `kind` originates from runtime engine/cache JSON, not a typechecked
 * union, so a version-skew kind not in the bundled map must degrade (generic chip)
 * rather than crash a `KIND_META[kind].Icon` dereference.
 */
export function kindMeta(kind: FindingKind | string): KindMeta {
  return KIND_META[kind as FindingKind] ?? { label: titleCase(String(kind)), Icon: Activity };
}

/** Canonical human label for a kind, with a title-cased fallback for unknown tokens. */
export function kindLabel(kind: FindingKind | string): string {
  return KIND_META[kind as FindingKind]?.label ?? titleCase(String(kind));
}
