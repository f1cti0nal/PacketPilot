import { ShieldAlert } from "lucide-react";
import type { Finding } from "../../types";
import { humanNumber } from "../../lib/format";
import { dstLabel } from "../../lib/findingTarget";
import { SeverityChip, MitreTag, Panel } from "../../cockpit/primitives";
import { EvidenceList } from "../transparency/EvidenceList";

function CertCard({ f, onJump }: { f: Finding; onJump?: (ip: string) => void }) {
  const dst = dstLabel(f);
  const pivot = f.dst_ip ?? f.src_ip;

  const content = (
    <>
      <div className="flex flex-wrap items-center gap-2">
        <span
          className="min-w-0 flex-1 truncate text-sm font-medium text-[var(--color-text)]"
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
          className="flex w-full flex-col gap-2 rounded-[var(--r-tile)] border border-[var(--color-border)] bg-[var(--color-surface-2)] p-3 text-left transition-colors hover:border-[var(--color-border-strong)]"
        >
          {content}
        </button>
      </li>
    );
  }

  return (
    <li className="flex flex-col gap-2 rounded-[var(--r-tile)] border border-[var(--color-border)] bg-[var(--color-surface-2)] p-3">
      {content}
    </li>
  );
}

/**
 * Consolidated read-only list of *handshake posture* findings — everything an analyst can learn
 * about a channel's crypto from the cleartext negotiation, with no decryption: suspicious
 * certificates (`tls_cert_health`), weak/deprecated TLS (`weak_tls`), a client that named no
 * server (`missing_sni`), a protocol/port disagreement (`port_protocol_mismatch`), and a broken
 * SSH configuration (`ssh_posture`). Hidden when none.
 *
 * The component keeps its original name for import stability; its scope is the panel's labels.
 */
export function CertHealthPanel({
  findings,
  onJump,
}: {
  findings: Finding[];
  onJump?: (ip: string) => void;
}) {
  const tls = (findings ?? []).filter(
    (f) => f.kind === "tls_cert_health" ||
        f.kind === "weak_tls" ||
        f.kind === "missing_sni" ||
        f.kind === "port_protocol_mismatch" ||
        f.kind === "ssh_posture",
  );
  if (tls.length === 0) return null;
  return (
    <Panel
      label="HANDSHAKE POSTURE"
      title="Handshake issues"
      count={`${humanNumber(tls.length)} flagged`}
      icon={<ShieldAlert size={14} style={{ color: "var(--color-sev-high)" }} />}
      accent="high"
      bodyClassName="p-3"
    >
      <ul className="grid grid-cols-1 gap-2 md:grid-cols-2 xl:grid-cols-3">
        {tls.slice(0, 50).map((f, i) => (
          <CertCard key={`${f.kind}-${f.src_ip}-${f.dst_ip ?? "nodst"}-${i}`} f={f} onJump={onJump} />
        ))}
      </ul>
    </Panel>
  );
}

export default CertHealthPanel;
