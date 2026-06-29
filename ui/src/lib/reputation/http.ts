import type { ReputationVerdict } from "../../types";

export interface HttpResult { status: number; body: string }
/** A GET that returns status + raw body. The concrete impl (edgeRepHttp) relays through
 *  the reputation-proxy Edge Function which injects the provider key server-side. */
export type HttpGet = (url: string, headers: Record<string, string>) => Promise<HttpResult>;

export function unavailable(source: string, now: number): ReputationVerdict {
  return { source, status: "unavailable", malicious: false, score: null, tags: [], link: null, fetched_at: now };
}
