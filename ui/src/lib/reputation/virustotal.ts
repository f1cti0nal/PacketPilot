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

export async function virustotalVerdictIp(http: HttpGet, ip: string, now: number): Promise<ReputationVerdict> {
  const res = await http(`https://www.virustotal.com/api/v3/ip_addresses/${ip}`, {});
  return parse(res.body, res.status, `https://www.virustotal.com/gui/ip-address/${ip}`, now);
}

export async function virustotalVerdictDomain(http: HttpGet, domain: string, now: number): Promise<ReputationVerdict> {
  const res = await http(`https://www.virustotal.com/api/v3/domains/${domain}`, {});
  return parse(res.body, res.status, `https://www.virustotal.com/gui/domain/${domain}`, now);
}

/** File-hash reputation. Same /api/v3 shape as IP/domain (last_analysis_stats), so parse() is
 *  reused; file-only attributes (threat label, friendly name) are folded into tags when present. */
export async function virustotalVerdictFile(http: HttpGet, sha256: string, now: number): Promise<ReputationVerdict> {
  const res = await http(`https://www.virustotal.com/api/v3/files/${sha256}`, {});
  const v = parse(res.body, res.status, `https://www.virustotal.com/gui/file/${sha256}`, now);
  if (res.status === 200) {
    try {
      const a = JSON.parse(res.body).data.attributes;
      const label = a?.popular_threat_classification?.suggested_threat_label;
      if (typeof label === "string" && label && !v.tags.includes(label)) v.tags.unshift(label);
      const name = a?.meaningful_name;
      if (typeof name === "string" && name && !v.tags.includes(name)) v.tags.push(name);
    } catch { /* tags are best-effort */ }
  }
  return v;
}
