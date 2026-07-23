import type { Finding } from "../types";

/**
 * The destination a finding is attributed to, as a compact display string:
 *
 * - `ip:port` / `ip` when a peer host is named (beacons, exfil, per-peer traffic anomalies, …),
 * - `port N` when only a **service port** is named — the case per-port traffic anomalies,
 *   sweeps, and floods produce (`dst_ip` null, `dst_port` set); the older `dst_ip ? … : "—"`
 *   idiom dropped these to "—", hiding the attribution,
 * - `—` for pure fan-out findings that carry neither (read `victims` instead).
 */
export function dstLabel(f: Pick<Finding, "dst_ip" | "dst_port">): string {
  if (f.dst_ip) {
    return f.dst_port != null ? `${f.dst_ip}:${f.dst_port}` : f.dst_ip;
  }
  return f.dst_port != null ? `port ${f.dst_port}` : "—";
}

/** Whether a finding names any destination at all (a peer host or a service port). */
export function hasTarget(f: Pick<Finding, "dst_ip" | "dst_port">): boolean {
  return f.dst_ip != null || f.dst_port != null;
}
