import { useCallback, useState, type ReactNode } from "react";
import clsx from "clsx";
import {
  FileText,
  Fingerprint,
  HardDrive,
  Cable,
  Clock,
  Hourglass,
  Boxes,
  Network,
  ArrowDownUp,
  Copy,
  Check,
  AlertTriangle,
  EthernetPort,
} from "lucide-react";
import type { Summary, AnalysisOutput } from "../../types";
import {
  basename,
  shortHash,
  humanBytes,
  humanNumber,
  compactNumber,
  nsToDateTime,
  durationHumanNs,
} from "../../lib/format";

export interface SummaryCardProps {
  summary: Summary;
  source: Pick<AnalysisOutput, "source_path" | "source_bytes" | "link_type">;
}

const txt = "text-[color:var(--color-text)]";
const dim = "text-[color:var(--color-text-dim)]";
const faint = "text-[color:var(--color-text-faint)]";

/** A single stat cell in the card grid. */
function Stat({
  icon,
  label,
  value,
  sub,
  children,
}: {
  icon: ReactNode;
  label: string;
  value?: ReactNode;
  sub?: ReactNode;
  children?: ReactNode;
}) {
  return (
    <div className="flex flex-col gap-1 rounded-lg border border-[color:var(--color-border)] bg-[color:var(--color-surface-2)] p-3">
      <div className={clsx("flex items-center gap-1.5 text-[11px] font-medium uppercase tracking-wide", faint)}>
        <span className="shrink-0 text-[color:var(--color-accent)]">{icon}</span>
        <span>{label}</span>
      </div>
      {value !== undefined && (
        <div className={clsx("font-mono-num text-sm leading-tight", txt)}>{value}</div>
      )}
      {children}
      {sub !== undefined && <div className={clsx("text-[11px] leading-tight", dim)}>{sub}</div>}
    </div>
  );
}

/** Small warning/info badge for decode errors and non-IP frames. */
function CountBadge({
  label,
  count,
  warn,
}: {
  label: string;
  count: number;
  warn: boolean;
}) {
  const active = warn && count > 0;
  return (
    <span
      className={clsx(
        "inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-[11px] font-medium",
        active
          ? "border-[color:var(--color-sev-high)]/40 bg-[color:var(--color-sev-high)]/10 text-[color:var(--color-sev-high)]"
          : "border-[color:var(--color-border)] bg-[color:var(--color-surface-2)] " + dim,
      )}
    >
      {active && <AlertTriangle size={12} className="shrink-0" />}
      <span>{label}</span>
      <span className="font-mono-num">{humanNumber(count)}</span>
    </span>
  );
}

export function SummaryCard({ summary, source }: SummaryCardProps) {
  const [copied, setCopied] = useState(false);

  // sha256 is not part of the stable prop contract, but the real AnalysisOutput
  // carries it on the source object — surface it when present without widening
  // the declared interface.
  const sha256 = (source as { source_sha256?: string }).source_sha256;

  const handleCopy = useCallback(() => {
    if (!sha256) return;
    void navigator.clipboard?.writeText(sha256).then(() => {
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1200);
    });
  }, [sha256]);

  const fileName = basename(source.source_path);
  const first = nsToDateTime(summary.first_ts_ns);
  const last = nsToDateTime(summary.last_ts_ns);

  return (
    <div
      data-component="SummaryCard"
      className="rounded-xl border border-[color:var(--color-border)] bg-[color:var(--color-surface)] p-4"
    >
      {/* Header: filename + link type */}
      <div className="mb-3 flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className={clsx("mb-0.5 text-[11px] font-medium uppercase tracking-wide", faint)}>
            Capture
          </div>
          <div className="flex items-center gap-2">
            <FileText size={16} className="shrink-0 text-[color:var(--color-accent)]" />
            <span
              className={clsx("truncate font-mono-num text-sm font-semibold", txt)}
              title={source.source_path}
            >
              {fileName}
            </span>
          </div>
        </div>
        <span
          className={clsx(
            "inline-flex shrink-0 items-center gap-1 rounded-md border border-[color:var(--color-border)] bg-[color:var(--color-surface-2)] px-2 py-0.5 text-[11px] font-medium",
            dim,
          )}
          title="Link-layer type"
        >
          <Cable size={12} />
          {source.link_type}
        </span>
      </div>

      {/* Stat grid */}
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
        <Stat
          icon={<Boxes size={13} />}
          label="Packets"
          value={humanNumber(summary.total_packets)}
          sub={`${compactNumber(summary.total_packets)} frames`}
        />
        <Stat
          icon={<Network size={13} />}
          label="Flows"
          value={humanNumber(summary.total_flows)}
          sub={`${humanNumber(summary.unique_hosts)} hosts`}
        />
        <Stat
          icon={<ArrowDownUp size={13} />}
          label="Total Bytes"
          value={humanBytes(summary.total_bytes)}
          sub={`${humanBytes(summary.captured_bytes)} captured`}
        />
        <Stat
          icon={<HardDrive size={13} />}
          label="File Size"
          value={humanBytes(source.source_bytes)}
        />
        <Stat
          icon={<Hourglass size={13} />}
          label="Duration"
          value={durationHumanNs(summary.duration_ns)}
        />
        <Stat icon={<EthernetPort size={13} />} label="Link Type" value={source.link_type} />
      </div>

      {/* Capture time range */}
      <div className="mt-2">
        <Stat icon={<Clock size={13} />} label="Capture Window">
          <div className={clsx("font-mono-num text-xs leading-relaxed", txt)}>
            <div>
              <span className={faint}>first&nbsp;</span>
              {first}
            </div>
            <div>
              <span className={faint}>last&nbsp;&nbsp;</span>
              {last}
            </div>
          </div>
        </Stat>
      </div>

      {/* SHA-256 (copyable) — rendered only when available */}
      {sha256 && (
        <div className="mt-2">
          <Stat icon={<Fingerprint size={13} />} label="SHA-256">
            <button
              type="button"
              onClick={handleCopy}
              title={`${sha256}\nClick to copy`}
              className={clsx(
                "group inline-flex items-center gap-2 rounded-md border border-[color:var(--color-border)] bg-[color:var(--color-surface)] px-2 py-1 text-left transition-colors hover:border-[color:var(--color-accent)]/50",
              )}
            >
              <span className={clsx("font-mono-num text-xs", txt)}>{shortHash(sha256, 10, 8)}</span>
              {copied ? (
                <Check size={13} className="shrink-0 text-[color:var(--color-sev-info)]" />
              ) : (
                <Copy size={13} className={clsx("shrink-0", faint)} />
              )}
            </button>
          </Stat>
        </div>
      )}

      {/* Integrity badges */}
      <div className="mt-3 flex flex-wrap items-center gap-2">
        <span className={clsx("text-[11px] font-medium uppercase tracking-wide", faint)}>
          Integrity
        </span>
        <CountBadge label="Decode errors" count={summary.decode_errors} warn />
        <CountBadge label="Non-IP frames" count={summary.non_ip_frames} warn={false} />
      </div>
    </div>
  );
}

export default SummaryCard;
