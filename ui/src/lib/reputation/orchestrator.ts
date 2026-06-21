import type { ReputationVerdict } from "../../types";
import { isPublicIp } from "../data"; // see note below
import type { HttpGet } from "./http";
import { abuseipdbVerdict } from "./abuseipdb";
import { greynoiseVerdict } from "./greynoise";
import { virustotalVerdictIp } from "./virustotal";
import { getReputation, putReputation } from "../recent";
import { makeBudget, trySpend } from "./budget";

export interface RepKeys { abuseipdb?: string; greynoise?: string; virustotal?: string; }
const TTL = { abuseipdb: 18 * 3600, greynoise: 24 * 3600, virustotal: 12 * 3600 };

function quotaUnavailable(source: string, now: number): ReputationVerdict {
  return { source, status: "unavailable", malicious: false, score: null, tags: ["quota"], link: null, fetched_at: now };
}

/** `ips` should be priority-ordered (most-suspicious first). Cache-first, budget-bounded. */
export async function lookupReputation(http: HttpGet, ips: string[], keys: RepKeys, now: number): Promise<Record<string, ReputationVerdict[]>> {
  const out: Record<string, ReputationVerdict[]> = {};
  const budget = makeBudget();
  const providers: Array<[string, number, (h: HttpGet, k: string, ip: string, n: number) => Promise<ReputationVerdict>]> = [];
  if (keys.abuseipdb) providers.push(["abuseipdb", TTL.abuseipdb, abuseipdbVerdict]);
  if (keys.greynoise) providers.push(["greynoise", TTL.greynoise, greynoiseVerdict]);
  if (keys.virustotal) providers.push(["virustotal", TTL.virustotal, virustotalVerdictIp]);

  for (const ip of ips) {
    if (!isPublicIp(ip)) continue;
    const verdicts: ReputationVerdict[] = [];
    for (const [source, ttl, fetchFn] of providers) {
      const cached = await getReputation(source, ip, now, ttl);
      if (cached) { verdicts.push(cached); continue; }
      if (trySpend(budget, source)) {
        const v = await fetchFn(http, (keys as any)[source], ip, now);
        await putReputation(source, ip, v);
        verdicts.push(v);
      } else {
        verdicts.push(quotaUnavailable(source, now));
      }
    }
    if (verdicts.length) out[ip] = verdicts;
  }
  return out;
}
