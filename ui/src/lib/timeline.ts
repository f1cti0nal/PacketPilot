import type { AlertTimeline, CarveQuery, PacketScope, TimelineEvent, TimelineEventKind } from "../types";

/** Short human label per row kind (mirrors the engine's `TimelineEventKind::label`). */
export const KIND_LABEL: Record<TimelineEventKind, string> = {
  first_contact: "First contact",
  dns_answer: "DNS answer",
  pivot: "Lateral hop",
  file_download: "Download",
  detection: "Detection",
};

export function kindLabel(kind: TimelineEventKind): string {
  return KIND_LABEL[kind] ?? kind;
}

/** A row's packet scope as the carve request the wasm / Tauri carve accepts. */
export function carveQueryFor(scope: PacketScope): CarveQuery {
  const q: CarveQuery = { host: scope.host, start_ns: scope.start_ns, end_ns: scope.end_ns };
  if (scope.peer) q.peer = scope.peer;
  if (scope.port != null) q.port = scope.port;
  return q;
}

/** The scope as a tcpdump / Wireshark capture filter (mirrors the engine's `PacketScope::bpf`). */
export function bpfFor(scope: PacketScope): string {
  let f = `host ${scope.host}`;
  if (scope.peer) f += ` and host ${scope.peer}`;
  if (scope.port != null) f += ` and port ${scope.port}`;
  return f;
}

/** File name for a row's carved pcap: kind, host(s), port and start second — filesystem-safe. */
export function carveFileName(e: TimelineEvent): string {
  const s = e.packets;
  if (!s) return "timeline.pcap";
  const parts = [e.kind, s.host, s.peer, s.port != null ? `p${s.port}` : null, String(Math.floor(s.start_ns / 1e9))];
  return `${parts.filter(Boolean).join("_").replace(/[^A-Za-z0-9._-]/g, "-")}.pcap`;
}

/** "+1m 2.5s"-style offset of `ts` from the timeline start; "" when either is unknown. */
export function offsetLabel(ts: number | null | undefined, start: number | null | undefined): string {
  if (ts == null || start == null) return "";
  const ms = Math.max(0, (ts - start) / 1e6);
  if (ms < 1000) return `+${Math.round(ms)}ms`;
  const sec = ms / 1000;
  if (sec < 60) return `+${sec.toFixed(sec < 10 ? 2 : 1)}s`;
  const m = Math.floor(sec / 60);
  if (m < 60) return `+${m}m ${Math.floor(sec - m * 60)}s`;
  const h = Math.floor(m / 60);
  return `+${h}h ${m - h * 60}m`;
}

/** Rows touching any of `hosts` (as the row's host or its peer); every row when `hosts` is empty. */
export function filterByHosts(events: TimelineEvent[], hosts: ReadonlySet<string>): TimelineEvent[] {
  if (hosts.size === 0) return events;
  return events.filter((e) => hosts.has(e.host) || (e.peer != null && hosts.has(e.peer)));
}

/** The timeline for `alertId`, else the first one (the queue's top alert); null when none. */
export function pickTimeline(timelines: AlertTimeline[], alertId: string | null | undefined): AlertTimeline | null {
  return timelines.find((t) => t.alert_id === alertId) ?? timelines[0] ?? null;
}

/** Stable lane colour per host (index into a small categorical set; cycles past 6 hosts). */
const LANE_COLORS = ["#0ea5e9", "#8b5cf6", "#ec4899", "#10b981", "#d97706", "#64748b"];
export function laneColor(hosts: string[], host: string): string {
  const i = hosts.indexOf(host);
  return LANE_COLORS[(i < 0 ? 0 : i) % LANE_COLORS.length];
}
