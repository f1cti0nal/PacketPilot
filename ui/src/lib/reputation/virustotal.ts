import type { ReputationVerdict, RepStatus } from "../../types";
import { type HttpGet, unavailable } from "./http";

function parse(body: string, status: number, link: string, now: number): ReputationVerdict {
  if (status === 404) return { source: "virustotal", status: "notfound", malicious: false, score: null, tags: [], link, fetched_at: now };
  if (status !== 200) return unavailable("virustotal", now);
  let a: any;
  try { a = JSON.parse(body).data.attributes; } catch { return unavailable("virustotal", now); }
  const st = a?.last_analysis_stats;
  if (!st) return { source: "virustotal", status: "unknown", malicious: false, score: null, tags: [], link, fetched_at: now };
  const total = Math.max(1, (st.malicious ?? 0) + (st.suspicious ?? 0) + (st.harmless ?? 0) + (st.undetected ?? 0));
  const score = Math.round((100 * (st.malicious ?? 0)) / total);
  let s: RepStatus;
  if ((st.malicious ?? 0) > 0) s = "malicious";
  else if ((st.suspicious ?? 0) === 0 && (st.harmless ?? 0) > 0) s = "clean";
  else s = "unknown";
  const tags: string[] = Array.isArray(a.tags) ? [...a.tags] : [];
  if (a.as_owner) tags.push(a.as_owner);
  if (a.country) tags.push(a.country);
  return { source: "virustotal", status: s, malicious: s === "malicious", score, tags, link, fetched_at: now };
}

export async function virustotalVerdictIp(http: HttpGet, key: string, ip: string, now: number): Promise<ReputationVerdict> {
  const res = await http(`https://www.virustotal.com/api/v3/ip_addresses/${ip}`, { "x-apikey": key });
  return parse(res.body, res.status, `https://www.virustotal.com/gui/ip-address/${ip}`, now);
}

export async function virustotalVerdictDomain(http: HttpGet, key: string, domain: string, now: number): Promise<ReputationVerdict> {
  const res = await http(`https://www.virustotal.com/api/v3/domains/${domain}`, { "x-apikey": key });
  return parse(res.body, res.status, `https://www.virustotal.com/gui/domain/${domain}`, now);
}
