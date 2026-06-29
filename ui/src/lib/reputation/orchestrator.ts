import type { ReputationVerdict } from "../../types";
import { isPublicIp } from "../data"; // see note below
import type { HttpGet } from "./http";
import { abuseipdbVerdict } from "./abuseipdb";
import { greynoiseVerdict } from "./greynoise";
import { virustotalVerdictIp, virustotalVerdictDomain, virustotalVerdictFile } from "./virustotal";
import { getReputation, putReputation } from "../recent";
import { makeBudget, trySpend } from "./budget";

const VALID_PROVIDERS = ["abuseipdb", "greynoise", "virustotal"] as const;
type ProviderName = (typeof VALID_PROVIDERS)[number];

const TTL: Record<ProviderName, number> = { abuseipdb: 18 * 3600, greynoise: 24 * 3600, virustotal: 12 * 3600 };

function quotaUnavailable(source: string, now: number): ReputationVerdict {
  return { source, status: "unavailable", malicious: false, score: null, tags: ["quota"], link: null, fetched_at: now };
}

/** Only genuinely public domains may be sent to a third-party reputation service —
 *  the IP path already does this via isPublicIp. Skip single-label hosts and internal/
 *  reserved TLDs so intranet SNI (vault.internal, printer.lan, gitlab.corp) never leaks. */
export function isPublicDomain(host: string): boolean {
  const h = host.trim().toLowerCase();
  if (!h.includes(".")) return false;
  return !/\.(local|lan|internal|intranet|corp|home|test|localhost|localdomain)$/.test(h);
}

/** Domain reputation — VirusTotal only. `hosts` should already be capped/ordered by the caller. */
export async function lookupDomainReputation(
  http: HttpGet,
  hosts: string[],
  now: number,
): Promise<Record<string, ReputationVerdict[]>> {
  const out: Record<string, ReputationVerdict[]> = {};
  const budget = makeBudget();
  for (const host of hosts) {
    if (!isPublicDomain(host)) continue; // never query internal/intranet SNI against VT
    const cached = await getReputation("virustotal", host, now, TTL.virustotal);
    let v: ReputationVerdict;
    if (cached) {
      v = cached;
    } else if (trySpend(budget, "virustotal")) {
      v = await virustotalVerdictDomain(http, host, now);
      await putReputation("virustotal", host, v);
    } else {
      v = quotaUnavailable("virustotal", now);
    }
    out[host] = [v];
  }
  return out;
}

/** File-hash reputation — VirusTotal only, keyed on the SHA-256. `hashes` should already be
 *  capped/deduped by the caller (e.g. summary.carved_files[].sha256). Cache-first under the
 *  "virustotal-file" source so file hashes never collide with IP/domain cache entries; budget-bounded.
 *  A SHA-256 leaks nothing about the capture, so there's no privacy guard — only a format check. */
export async function lookupFileReputation(
  http: HttpGet,
  hashes: string[],
  now: number,
): Promise<Record<string, ReputationVerdict[]>> {
  const out: Record<string, ReputationVerdict[]> = {};
  const budget = makeBudget();
  for (const hash of hashes) {
    const h = hash.trim().toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(h)) continue; // only well-formed SHA-256 hits VT
    const cached = await getReputation("virustotal-file", h, now, TTL.virustotal);
    let v: ReputationVerdict;
    if (cached) {
      v = cached;
    } else if (trySpend(budget, "virustotal")) {
      v = await virustotalVerdictFile(http, h, now);
      await putReputation("virustotal-file", h, v);
    } else {
      v = quotaUnavailable("virustotal", now);
    }
    out[h] = [v];
  }
  return out;
}

/** `ips` should be priority-ordered (most-suspicious first). Cache-first, budget-bounded.
 *  `providers` is the operator-configured list (from rep_config); intersected against VALID_PROVIDERS. */
export async function lookupReputation(
  http: HttpGet,
  ips: string[],
  providers: string[],
  now: number,
): Promise<Record<string, ReputationVerdict[]>> {
  const out: Record<string, ReputationVerdict[]> = {};
  const budget = makeBudget();

  type FetchFn = (h: HttpGet, ip: string, n: number) => Promise<ReputationVerdict>;
  const active: Array<[ProviderName, number, FetchFn]> = [];
  const activeSet = new Set(providers);
  if (activeSet.has("abuseipdb")) active.push(["abuseipdb", TTL.abuseipdb, abuseipdbVerdict]);
  if (activeSet.has("greynoise")) active.push(["greynoise", TTL.greynoise, greynoiseVerdict]);
  if (activeSet.has("virustotal")) active.push(["virustotal", TTL.virustotal, virustotalVerdictIp]);

  for (const ip of ips) {
    if (!isPublicIp(ip)) continue;
    const verdicts: ReputationVerdict[] = [];
    for (const [source, ttl, fetchFn] of active) {
      const cached = await getReputation(source, ip, now, ttl);
      if (cached) { verdicts.push(cached); continue; }
      if (trySpend(budget, source)) {
        const v = await fetchFn(http, ip, now);
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
