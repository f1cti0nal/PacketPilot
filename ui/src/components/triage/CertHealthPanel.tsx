import { ShieldAlert } from "lucide-react";
import type { Finding } from "../../types";
import { humanNumber } from "../../lib/format";
import { SeverityChip, MitreTag } from "../../cockpit/primitives";
import { EvidenceList } from "../transparency/EvidenceList";

function CertCard({ f, onJump }: { f: Finding; onJump?: (ip: string) => void }) {
  const dst = f.dst_ip ? `${f.dst_ip}${f.dst_port != null ? `:${f.dst_port}` : ""}` : "—";
  const pivot = f.dst_ip ?? f.src_ip;

  const content = (
    <>
      <div className="flex flex-wrap items-center gap-2">
        <span
          className="min-w-0 flex-1 truncate text-sm font-semibold text-[var(--color-text)]"
          title={f.title}
        >
          {f.title}
        </span>
        <SeverityChip severity={f.severity} />
      </div>
      <div className="font-mono-num flex items-center gap-1.5 text-xs text-[var(--color-text-dim)]">
        <span className="truncate">{f.src_ip}</span>
        <span className="text-[var(--color-text-faint)]">→</span>
        <span className="truncate">{dst}</span>
      </div>
      <EvidenceList evidence={f.evidence} />
      {f.attack.length > 0 && (
        <div className="flex flex-wrap items-center gap-1.5">
          {f.attack.map((a) => (
            <MitreTag key={a} id={a} />
          ))}
        </div>
      )}
    </>
  );

  if (onJump) {
    return (
      <li>
        <button
          type="button"
          onClick={() => onJump(pivot)}
          aria-label={`View flows for ${pivot}`}
          className="flex w-full flex-col gap-2 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-2)] p-3 text-left transition-colors hover:border-[var(--color-border-strong)]"
        >
          {content}
        </button>
      </li>
    );
  }

  return (
    <li className="flex flex-col gap-2 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-2)] p-3">
      {content}
    </li>
  );
}

/**
 * Consolidated read-only list of suspicious-server-certificate (`tls_cert_health`) findings —
 * self-signed / expired / hostname-mismatched TLS certs surfaced by the engine. Hidden when none.
 */
export function CertHealthPanel({
  findings,
  onJump,
}: {
  findings: Finding[];
  onJump?: (ip: string) => void;
}) {
  const certs = (findings ?? []).filter((f) => f.kind === "tls_cert_health");
  if (certs.length === 0) return null;
  return (
    <section
      data-component="CertHealthPanel"
      aria-label="TLS certificate issues"
      className="rounded-lg border border-border bg-surface p-4 shadow-sm"
    >
      <div className="mb-3 flex items-baseline justify-between gap-2">
        <h2 className="flex items-center gap-2 text-sm font-semibold uppercase tracking-wide text-[var(--color-text-dim)]">
          <ShieldAlert size={15} className="text-[var(--color-sev-high)]" /> TLS certificate issues
        </h2>
        <span className="font-mono-num text-xs text-[var(--color-text-faint)]">
          {humanNumber(certs.length)} flagged
        </span>
      </div>
      <ul className="grid grid-cols-1 gap-2 md:grid-cols-2 xl:grid-cols-3">
        {certs.slice(0, 50).map((f, i) => (
          <CertCard key={`${f.src_ip}-${f.dst_ip ?? "nodst"}-${i}`} f={f} onJump={onJump} />
        ))}
      </ul>
    </section>
  );
}

export default CertHealthPanel;
