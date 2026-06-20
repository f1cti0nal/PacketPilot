// CaptureIntegrity — evidence-quality trust card. Surfaces the forensic
// provenance signals (decode losses, coverage, link layer, source digest) that
// tell an analyst whether the capture can be trusted as evidence.
import { useMemo } from "react";
import { AlertTriangle, Clock, Fingerprint, ShieldCheck } from "lucide-react";
import { cn } from "../lib/cn";
import { humanBytes, nsToDateTime, percent, shortHash } from "../lib/format";
import { Card } from "./primitives";
import type { AnalysisOutput } from "../types";

const TEAL = "var(--color-sev-low)";
const HIGH = "var(--color-sev-high)";

function Tile({
  caption,
  value,
  valueColor,
  note,
}: {
  caption: string;
  value: string;
  valueColor?: string;
  note?: string;
}) {
  return (
    <div className="rounded-[var(--r-tile)] bg-[var(--color-surface-2)] p-3">
      <div className="t-label">{caption}</div>
      <div className="font-mono-num mt-1 text-sm text-[var(--color-text)]" style={valueColor ? { color: valueColor } : undefined}>
        {value}
      </div>
      {note && (
        <div className="font-mono-num mt-0.5 t-tag" style={{ color: TEAL }}>
          {note}
        </div>
      )}
    </div>
  );
}

export function CaptureIntegrity({ output }: { output: AnalysisOutput }): JSX.Element {
  const s = output.summary;

  const { coveragePct, complete, anyErrors } = useMemo(() => {
    const total = s.total_bytes || 0;
    const cap = s.captured_bytes || 0;
    const isComplete = total > 0 && cap >= total;
    return {
      coveragePct: percent(cap, total),
      complete: isComplete,
      anyErrors: s.decode_errors > 0 || s.non_ip_frames > 0,
    };
  }, [s.total_bytes, s.captured_bytes, s.decode_errors, s.non_ip_frames]);

  const bucketSecs = s.time_bucket_secs ?? 1;

  return (
    <Card
      label="EVIDENCE"
      title="Capture integrity"
      right={
        anyErrors ? (
          <AlertTriangle size={14} aria-hidden style={{ color: HIGH }} />
        ) : (
          <ShieldCheck size={14} aria-hidden style={{ color: TEAL }} />
        )
      }
    >
      <div className="grid grid-cols-2 gap-2">
        <Tile
          caption="Decode errors"
          value={String(s.decode_errors)}
          valueColor={s.decode_errors > 0 ? HIGH : TEAL}
        />
        <Tile
          caption="Non-IP frames"
          value={String(s.non_ip_frames)}
          valueColor={s.non_ip_frames > 0 ? HIGH : TEAL}
        />
        <Tile
          caption="Captured"
          value={`${humanBytes(s.captured_bytes)} · ${coveragePct} of wire`}
          note={complete ? "complete" : undefined}
        />
        <Tile caption="Link type" value={output.link_type} />
        <Tile caption="Bucket width" value={`${bucketSecs}s`} />
        <Tile caption="File size" value={humanBytes(output.source_bytes)} />
      </div>

      <div className="mt-3 space-y-2 border-t border-[var(--color-border)] pt-3">
        <div className="flex items-start gap-2">
          <Clock size={13} aria-hidden className="mt-0.5 shrink-0" style={{ color: "var(--color-accent)" }} />
          <div className="font-mono-num min-w-0 text-xs leading-relaxed text-[var(--color-text-dim)]">
            <span className="text-[var(--color-text-faint)]">first </span>
            {nsToDateTime(s.first_ts_ns)}
            <br />
            <span className="text-[var(--color-text-faint)]">last </span>
            {nsToDateTime(s.last_ts_ns)}
          </div>
        </div>
        {output.source_sha256 && (
          <div className="flex items-center gap-2">
            <Fingerprint size={13} aria-hidden className="shrink-0" style={{ color: "var(--color-accent)" }} />
            <span
              className={cn(
                "font-mono-num truncate rounded-[var(--r-micro)] bg-[var(--color-surface-2)] px-2 py-0.5 text-xs text-[var(--color-text-dim)]",
              )}
              title={output.source_sha256}
            >
              {shortHash(output.source_sha256, 10, 8)}
            </span>
          </div>
        )}
      </div>
    </Card>
  );
}

export default CaptureIntegrity;
