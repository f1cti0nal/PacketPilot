import { Card } from "./primitives";
import { humanNumber } from "../lib/format";
import type { TlsServerPosture } from "../types";

/**
 * TLS server posture: what the servers in this capture actually negotiated — protocol version,
 * cipher suite, and the JA4S/JA3S server fingerprint — rolled up per endpoint.
 *
 * The per-flow columns carried these already, but nothing aggregated them, so "what TLS do my
 * servers speak?" meant querying the flow table. Everything here is keyless: it comes from the
 * cleartext ServerHello (and, for QUIC, from the version-public Initial). Display-only; hidden
 * when no server handshake was observed.
 */
export function TlsServersCard({
  servers,
  onJump,
}: {
  servers: TlsServerPosture[];
  onJump?: (ip: string) => void;
}) {
  const rows = servers ?? [];
  if (rows.length === 0) return null;

  return (
    <Card
      label="TLS POSTURE"
      title="TLS servers"
      right={
        <span className="font-mono-num t-tag text-[var(--color-text-dim)]">
          {humanNumber(rows.length)} servers
        </span>
      }
    >
      <ul className="flex flex-col divide-y divide-[var(--color-border)]">
        {rows.slice(0, 12).map((s) => {
          const fingerprint = s.ja4s ?? s.ja3s ?? null;
          return (
            <li key={`${s.server}-${s.port}`} className="flex flex-col gap-0.5 py-1.5 text-xs">
              <div className="flex items-baseline gap-2">
                <button
                  type="button"
                  className="font-mono-num shrink-0 truncate text-left text-[var(--color-text)] hover:underline"
                  title={s.sni ? `${s.server}:${s.port} — ${s.sni}` : `${s.server}:${s.port}`}
                  onClick={() => onJump?.(s.server)}
                >
                  {s.server}:{s.port}
                </button>
                {s.tls_version && (
                  <span
                    className="t-tag shrink-0 rounded-[var(--r-micro)] border border-[var(--color-border)] px-1 text-[var(--color-text-faint)]"
                    title={s.tls_cipher ?? undefined}
                  >
                    {s.tls_version}
                  </span>
                )}
                <span className="font-mono-num ml-auto shrink-0 t-tag text-[var(--color-text-faint)]">
                  {humanNumber(s.flows)} flows
                </span>
              </div>
              {fingerprint && (
                <span
                  className="font-mono-num truncate text-[var(--color-text-faint)]"
                  title={[s.ja4s && `JA4S: ${s.ja4s}`, s.ja3s && `JA3S: ${s.ja3s}`]
                    .filter(Boolean)
                    .join("\n")}
                >
                  {s.ja4s ? "JA4S" : "JA3S"} {fingerprint.slice(0, 24)}
                  {fingerprint.length > 24 ? "…" : ""}
                </span>
              )}
            </li>
          );
        })}
      </ul>
    </Card>
  );
}
