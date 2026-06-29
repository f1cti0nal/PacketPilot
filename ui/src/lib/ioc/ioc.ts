// Local IOC matching — match the capture's already-extracted indicators (host IPs, SNI/resolved
// domains, carved-file SHA-256 hashes) against an IOC list the user provides. Runs ENTIRELY
// client-side over the computed summary (no packets, no network) so a user can check a capture
// against their own threat intel without anything leaving the browser — the privacy-aligned
// answer to "does this traffic touch a known-bad indicator?" that cloud tools can't offer.
import type { AnalysisOutput, Finding, Severity } from "../../types";

/** A normalized, de-duplicated set of indicators parsed from a user-supplied IOC list. */
export interface ParsedIocs {
  /** IPv4 (canonical) and IPv6 (lowercased) literals. */
  ips: Set<string>;
  /** Hostnames, lowercased. */
  domains: Set<string>;
  /** MD5 / SHA-1 / SHA-256 hex digests, lowercased. */
  hashes: Set<string>;
  /** Total distinct indicators across all three buckets. */
  count: number;
}

const HEX_HASH = /^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/; // md5 / sha1 / sha256
const DOMAIN = /^(?:[a-z0-9_](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i;

/** Refang a defanged indicator: `hxxp`→`http`, `[.]`/`(.)`/`{.}`→`.`, `[:]`→`:`, `[at]`→`@`. */
function refang(s: string): string {
  return s
    .replace(/\[\.\]|\(\.\)|\{\.\}/g, ".")
    .replace(/\[:\]/g, ":")
    .replace(/\[at\]/gi, "@")
    .replace(/hxxp/gi, "http");
}

/** Classify a single token into one indicator kind (or null if unrecognized). */
function classify(rawTok: string): { kind: "ip" | "domain" | "hash"; value: string } | null {
  let v = refang(rawTok.trim());
  if (!v) return null;

  // Bracketed IPv6 with optional port: [2001:db8::1]:443
  const br = v.match(/^\[([0-9a-fA-F:]+)\](?::\d+)?$/);
  if (br) return { kind: "ip", value: br[1].toLowerCase() };

  v = v.replace(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//, ""); // strip URL scheme
  v = v.split(/[/?#\\]/)[0]; // drop path/query/fragment
  if (!v) return null;

  const low = v.toLowerCase();
  if (HEX_HASH.test(low)) return { kind: "hash", value: low };

  // IPv4 with optional :port — octets must be 0-255 (reject 256.x / 999.x typos so they don't
  // inflate the indicator tally or masquerade as a valid IOC).
  const v4 = v.match(/^((?:\d{1,3}\.){3}\d{1,3})(?::\d+)?$/);
  if (v4) return v4[1].split(".").every((o) => Number(o) <= 255) ? { kind: "ip", value: v4[1] } : null;

  // Bare IPv6 (≥2 colons, hex/colon only)
  if ((v.match(/:/g)?.length ?? 0) >= 2 && /^[0-9a-fA-F:]+$/.test(v)) {
    return { kind: "ip", value: low };
  }

  // Hostname, optionally with a trailing :port
  const host = low.replace(/:\d+$/, "");
  if (DOMAIN.test(host)) return { kind: "domain", value: host };

  return null;
}

/**
 * Parse a free-form IOC list into normalized indicator sets. Accepts one-per-line or
 * whitespace/comma/semicolon-separated tokens, `#`/`//` comments (to end of line), defanged
 * indicators, and URLs (reduced to host). Unrecognized tokens are silently ignored.
 */
export function parseIocs(text: string): ParsedIocs {
  const ips = new Set<string>();
  const domains = new Set<string>();
  const hashes = new Set<string>();
  for (const line of text.split(/\r?\n/)) {
    for (const tok of line.split(/[\s,;]+/)) {
      if (!tok) continue;
      if (tok.startsWith("#") || tok.startsWith("//")) break; // rest of line is a comment
      const hit = classify(tok);
      if (!hit) continue;
      if (hit.kind === "ip") ips.add(hit.value);
      else if (hit.kind === "domain") domains.add(hit.value);
      else hashes.add(hit.value);
    }
  }
  return { ips, domains, hashes, count: ips.size + domains.size + hashes.size };
}

function iocFinding(opts: {
  indicator: string;
  type: "ip" | "domain" | "hash";
  srcIp: string;
  dstIp: string | null;
  severity: Severity;
  score: number;
  extra: string[];
}): Finding {
  return {
    kind: "ioc_match",
    severity: opts.severity,
    score: opts.score,
    title: `IOC match: ${opts.indicator}`,
    src_ip: opts.srcIp,
    dst_ip: opts.dstIp,
    dst_port: null,
    attack: [],
    evidence: [`Matches your imported IOC list (${opts.type})`, ...opts.extra],
    interval_ns: null,
    jitter_cv: null,
    contacts: null,
  };
}

/**
 * Match `iocs` against the capture's FULL indicator inventory — every host IP seen (threats, top
 * talkers, passive-DNS answers, ARP), every domain seen (SNI threats, HTTP Host headers, passive
 * DNS), and carved-file SHA-256 hashes — not just the subset the behavioral engine elevated to
 * threats. (A known-bad IP that's just an ordinary talker is exactly what an IOC sweep must catch.)
 * Returns a new output whose `summary.findings` carries one `ioc_match` finding per distinct hit
 * (hash matches are Critical; IP/domain hits are High). Domain hits are attributed to their resolved
 * IP from passive DNS when known (so the threat graph + flow pivot work), else carry no src IP.
 * Any prior `ioc_match` findings are replaced so re-running a list never stacks. Pure — does not
 * mutate `output`.
 */
export function matchIocs(
  output: AnalysisOutput,
  iocs: ParsedIocs,
): { output: AnalysisOutput; matches: number } {
  const s = output.summary;
  const fresh: Finding[] = [];
  const seen = new Set<string>();
  const push = (key: string, f: Finding) => {
    if (!seen.has(key)) {
      seen.add(key);
      fresh.push(f);
    }
  };

  // --- IPs: every host the capture saw, deduped (lowercased). ---
  const ipSet = new Set<string>();
  const addIp = (ip: string | undefined) => { if (ip) ipSet.add(ip.toLowerCase()); };
  for (const t of s.ip_threats ?? []) addIp(t.ip);
  for (const t of s.top_talkers ?? []) addIp(t.ip);
  for (const r of s.resolved_ips ?? []) addIp(r.ip);
  for (const a of s.arp_hosts ?? []) addIp(a.ip);
  for (const c of s.carved_files ?? []) { addIp(c.client); addIp(c.server); }

  // --- Domains: every host seen + a domain→IP map (passive DNS) for attribution. ---
  const domainSet = new Set<string>();
  const domainToIp = new Map<string, string>();
  const addDomain = (host: string | undefined, ip?: string) => {
    if (!host) return;
    const h = host.toLowerCase();
    domainSet.add(h);
    if (ip && !domainToIp.has(h)) domainToIp.set(h, ip);
  };
  for (const d of s.domain_threats ?? []) addDomain(d.host);
  for (const h of s.http_hosts ?? []) addDomain(h.host);
  for (const r of s.resolved_ips ?? []) addDomain(r.domain, r.ip);

  for (const ip of ipSet) {
    if (iocs.ips.has(ip)) {
      push(`ip:${ip}`, iocFinding({
        indicator: ip, type: "ip", srcIp: ip, dstIp: null,
        severity: "high", score: 90, extra: [`Host ${ip} is present in the capture`],
      }));
    }
  }
  for (const host of domainSet) {
    if (iocs.domains.has(host)) {
      const ip = domainToIp.get(host) ?? ""; // attribute to the resolved IP when passive DNS knows it
      push(`domain:${host}`, iocFinding({
        indicator: host, type: "domain", srcIp: ip, dstIp: null,
        severity: "high", score: 90,
        extra: [ip ? `Domain ${host} resolved to ${ip}` : `Domain ${host} was seen in the capture`],
      }));
    }
  }
  for (const c of s.carved_files ?? []) {
    const low = c.sha256.toLowerCase();
    if (iocs.hashes.has(low)) {
      push(`hash:${low}`, iocFinding({
        indicator: `${c.sha256.slice(0, 12)}…`, type: "hash", srcIp: c.client, dstIp: c.server,
        severity: "critical", score: 100,
        extra: [`File SHA-256 ${c.sha256}`, `Carried ${c.client} → ${c.server}`],
      }));
    }
  }

  const kept = (s.findings ?? []).filter((f) => f.kind !== "ioc_match");
  return {
    output: { ...output, summary: { ...s, findings: [...fresh, ...kept] } },
    matches: fresh.length,
  };
}
