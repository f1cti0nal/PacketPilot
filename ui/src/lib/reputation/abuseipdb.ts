import type { ReputationVerdict, RepStatus } from "../../types";
import { type HttpGet, unavailable } from "./http";

export async function abuseipdbVerdict(http: HttpGet, ip: string, now: number): Promise<ReputationVerdict> {
  const url = `https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}&maxAgeInDays=90`;
  const res = await http(url, { Accept: "application/json" });
  if (res.status !== 200) return unavailable("abuseipdb", now);
  let d: any;
  try { d = JSON.parse(res.body).data; } catch { return unavailable("abuseipdb", now); }
  const score: number = d?.abuseConfidenceScore ?? 0;
  const total: number = d?.totalReports ?? 0;
  const status: RepStatus = score >= 75 ? "malicious" : score >= 25 ? "unknown" : total === 0 ? "clean" : "unknown";
  const tags: string[] = [];
  if (d?.usageType) tags.push(d.usageType);
  if (d?.isTor) tags.push("tor");
  if (d?.countryCode) tags.push(d.countryCode);
  return { source: "abuseipdb", status, malicious: status === "malicious", score, tags,
    link: `https://www.abuseipdb.com/check/${ip}`, fetched_at: now };
}
