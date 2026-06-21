import type { ReputationVerdict, RepStatus } from "../../types";
import { type HttpGet, unavailable } from "./http";

export async function greynoiseVerdict(http: HttpGet, key: string, ip: string, now: number): Promise<ReputationVerdict> {
  const url = `https://api.greynoise.io/v3/community/${ip}`;
  const res = await http(url, { key });
  if (res.status === 404) {
    return { source: "greynoise", status: "notfound", malicious: false, score: 0, tags: [], link: `https://viz.greynoise.io/ip/${ip}`, fetched_at: now };
  }
  if (res.status !== 200) return unavailable("greynoise", now);
  let r: any;
  try { r = JSON.parse(res.body); } catch { return unavailable("greynoise", now); }
  let status: RepStatus; let score: number;
  if (r.classification === "malicious") { status = "malicious"; score = 95; }
  else if (r.classification === "benign" || r.riot === true) { status = "benign"; score = 5; }
  else { status = "unknown"; score = r.noise ? 50 : 0; }
  const tags: string[] = [];
  if (r.name && r.name !== "unknown") tags.push(r.name);
  if (r.riot) tags.push("business-service");
  if (r.noise) tags.push("internet-scanner");
  return { source: "greynoise", status, malicious: status === "malicious", score, tags,
    link: r.link ?? `https://viz.greynoise.io/ip/${ip}`, fetched_at: now };
}
