import type { ReputationVerdict } from "../../types";

export interface HttpResult { status: number; body: string }
/** A GET that returns status + raw body. Real impl relays through the user's proxy. */
export type HttpGet = (url: string, headers: Record<string, string>) => Promise<HttpResult>;

/**
 * Relay through a user-supplied proxy. Contract: `POST {proxyUrl}` with JSON body
 * `{ url, headers }`; the proxy forwards server-side and responds `{ status, body }` (body a string).
 * This is the only way the browser can reach providers that block CORS (spec §7.4).
 */
export function proxyHttp(proxyUrl: string): HttpGet {
  return async (url, headers) => {
    try {
      const resp = await fetch(proxyUrl, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ url, headers }),
      });
      if (!resp.ok) return { status: resp.status, body: "" };
      const data = await resp.json();
      return { status: Number(data.status) || 0, body: typeof data.body === "string" ? data.body : JSON.stringify(data.body ?? "") };
    } catch {
      return { status: 0, body: "" };
    }
  };
}

export function unavailable(source: string, now: number): ReputationVerdict {
  return { source, status: "unavailable", malicious: false, score: null, tags: [], link: null, fetched_at: now };
}
