// Right-side glass flyout: full incident narrative, ordered findings with the
// evidence[] rendered as a mono log, and a deep-link back to the flows table.
import { useEffect, useRef } from "react";
import { ArrowRight, X } from "lucide-react";
import type { Incident, ScoreTerm } from "../types";
import { sevColor } from "./viz";
import { SeverityChip, SeverityDot, MitreTag, SectionLabel } from "./primitives";
import { EvidenceList } from "../components/transparency/EvidenceList";
import { FindingMetrics } from "../components/transparency/FindingMetrics";
import { ScoreWaterfall } from "../components/transparency/ScoreWaterfall";
import { TriageAnnotation } from "./TriageAnnotation";
import { vendorForMac } from "../lib/oui";

const humanizeKind = (k: string) =>
  k.split("_").map((w) => (w ? w[0].toUpperCase() + w.slice(1) : w)).join(" ");

export function DetailFlyout({
  incident,
  onClose,
  onJumpToFlows,
  scoreEvidence,
  hostScore,
  scoreTerms,
  resolvedDomain,
  mac,
  captureKey,
}: {
  incident: Incident | null;
  onClose: () => void;
  onJumpToFlows?: (host: string) => void;
  scoreEvidence?: string[];
  hostScore?: number;
  scoreTerms?: ScoreTerm[];
  /** Passive-DNS domain this host's IP resolved from, if known. */
  resolvedDomain?: string;
  /** L2 MAC address claimed by this host's IP via ARP, if known. */
  mac?: string;
  captureKey?: string;
}) {
  const panelRef = useRef<HTMLDivElement>(null);
  const closeBtnRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    if (!incident) return;
    const opener = document.activeElement as HTMLElement | null;
    const id = window.setTimeout(() => closeBtnRef.current?.focus(), 0);
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        onClose();
        return;
      }
      if (e.key === "Tab" && panelRef.current) {
        const focusable = panelRef.current.querySelectorAll<HTMLElement>(
          'button, [href], [tabindex]:not([tabindex="-1"])',
        );
        if (focusable.length === 0) return;
        const first = focusable[0];
        const last = focusable[focusable.length - 1];
        if (e.shiftKey && document.activeElement === first) {
          e.preventDefault();
          last.focus();
        } else if (!e.shiftKey && document.activeElement === last) {
          e.preventDefault();
          first.focus();
        }
      }
    };
    window.addEventListener("keydown", onKey);
    return () => {
      window.clearTimeout(id);
      window.removeEventListener("keydown", onKey);
      opener?.focus?.();
    };
  }, [incident, onClose]);

  if (!incident) return null;
  const color = sevColor(incident.severity);

  return (
    <div className="fixed inset-0 z-50 flex justify-end" role="dialog" aria-modal="true" aria-label={`Incident detail for ${incident.host}`}>
      <div className="absolute inset-0 bg-black/40" onClick={onClose} />
      <div ref={panelRef} className="glass-panel relative flex h-full w-[480px] max-w-full flex-col border-l" style={{ boxShadow: "var(--sh-float)" }}>
        {/* Header */}
        <header className="flex items-start justify-between gap-3 border-b border-[var(--color-border)] px-5 py-4">
          <div className="min-w-0">
            <SeverityChip severity={incident.severity} />
            <h2 className="font-mono-num t-host mt-2 truncate text-[var(--color-text)]">{incident.host}</h2>
            <div className="font-mono-num mt-0.5 text-sm" style={{ color }}>
              {incident.score}
              <span className="text-[var(--color-text-faint)]">/100</span>
            </div>
          </div>
          <button ref={closeBtnRef} type="button" onClick={onClose} aria-label="Close" className="rounded-[var(--r-tile)] p-1.5 text-[var(--color-text-dim)] transition-colors hover:bg-[var(--color-surface-2)] hover:text-[var(--color-text)]">
            <X size={16} />
          </button>
        </header>

        {/* Body */}
        <div className="min-h-0 flex-1 overflow-y-auto px-5 py-4">
          <p className="t-body text-[var(--color-text-dim)]">{incident.narrative}</p>

          {(resolvedDomain || mac) && (
            <>
              <SectionLabel className="mb-2 mt-5">Identity</SectionLabel>
              <dl className="flex flex-col gap-1 text-xs">
                {resolvedDomain && (
                  <div className="flex items-baseline gap-2">
                    <dt className="shrink-0 text-[var(--color-text-faint)]">Resolved from</dt>
                    <dd
                      className="font-mono-num truncate text-[var(--color-text-dim)]"
                      title={resolvedDomain}
                    >
                      {resolvedDomain}
                    </dd>
                  </div>
                )}
                {mac && (
                  <div className="flex items-baseline gap-2">
                    <dt className="shrink-0 text-[var(--color-text-faint)]">MAC</dt>
                    <dd className="font-mono-num text-[var(--color-text-dim)]">
                      {mac}
                      {vendorForMac(mac) && (
                        <span className="ml-1.5 text-[var(--color-text-faint)]">
                          ({vendorForMac(mac)})
                        </span>
                      )}
                    </dd>
                  </div>
                )}
              </dl>
            </>
          )}

          {captureKey && (
            <>
              <SectionLabel className="mb-2 mt-5">Triage</SectionLabel>
              <TriageAnnotation captureKey={captureKey} ip={incident.host} />
            </>
          )}

          <SectionLabel className="mb-2 mt-5">Kill-chain stages</SectionLabel>
          <div className="flex flex-wrap items-center gap-1.5">
            {incident.stages.map((stage, i) => (
              <span key={stage} className="inline-flex items-center gap-1.5">
                {i > 0 && <ArrowRight size={12} className="text-[var(--color-text-faint)]" />}
                <span className="rounded-[var(--r-chip)] border border-[var(--color-border)] bg-[var(--color-surface-2)] px-2 py-0.5 t-tag text-[var(--color-text-dim)]">{stage}</span>
              </span>
            ))}
          </div>

          <div className="mt-3 flex flex-wrap gap-1">
            {incident.attack.map((t) => (
              <MitreTag key={t} id={t} />
            ))}
          </div>

          {scoreEvidence && scoreEvidence.length > 0 && (
            <ScoreWaterfall
              evidence={scoreEvidence}
              score={hostScore ?? incident.score}
              severity={incident.severity}
              scoreTerms={scoreTerms}
            />
          )}

          <SectionLabel className="mb-2 mt-5">Findings · {incident.findings.length}</SectionLabel>
          <ul className="flex flex-col gap-2.5">
            {incident.findings.map((f, i) => (
              <li key={`${f.kind}-${i}`} className="rounded-[var(--r-tile)] border border-[var(--color-border)] bg-[var(--color-surface-1)] p-3">
                <div className="flex items-center gap-2">
                  <SeverityDot severity={f.severity} />
                  <span className="text-[13px] font-medium text-[var(--color-text)]">{humanizeKind(f.kind)}</span>
                </div>
                <div className="font-mono-num mt-1 text-xs text-[var(--color-text-dim)]">{f.title}</div>
                <div className="mt-2">
                  <FindingMetrics finding={f} />
                </div>
                {f.evidence.length > 0 && (
                  <div className="mt-2 border-l border-[var(--color-border)] pl-2.5">
                    <EvidenceList evidence={f.evidence} />
                  </div>
                )}
              </li>
            ))}
          </ul>
        </div>

        {/* Footer */}
        {onJumpToFlows && (
          <footer className="border-t border-[var(--color-border)] p-4">
            <button
              type="button"
              onClick={() => onJumpToFlows(incident.host)}
              className="glow-live flex w-full items-center justify-center gap-2 rounded-[var(--r-tile)] border border-[color:color-mix(in_srgb,var(--color-accent)_45%,transparent)] bg-[color:color-mix(in_srgb,var(--color-accent)_12%,transparent)] px-3 py-2 text-sm font-semibold text-[var(--color-accent)] transition-colors hover:bg-[color:color-mix(in_srgb,var(--color-accent)_18%,transparent)]"
            >
              View flows for {incident.host}
              <ArrowRight size={15} />
            </button>
          </footer>
        )}
      </div>
    </div>
  );
}

export default DetailFlyout;
