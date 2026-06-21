/** Per-provider daily budget; mirrors the Rust default quotas (spec §6.3, §8). */
export function makeBudget(): Record<string, number> {
  return { greynoise: 9, virustotal: 480, abuseipdb: 950 };
}
export function trySpend(budget: Record<string, number>, source: string): boolean {
  if ((budget[source] ?? 0) > 0) { budget[source] -= 1; return true; }
  return false;
}
