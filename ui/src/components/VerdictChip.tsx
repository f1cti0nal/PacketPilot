import { ShieldCheck } from "lucide-react";
import type { CaptureVerdict } from "../lib/workspace";
import { SEVERITY_META } from "../lib/severity";
import { sevColor } from "../cockpit/viz";

/**
 * A capture's worst-severity verdict as a compact chip — "{n} {Severity}" in the severity colour,
 * or a calm "Clean" when nothing was detected. Shared by the Home overview and the Recent tab so
 * the two recent surfaces read the same.
 */
export function VerdictChip({ verdict }: { verdict: CaptureVerdict }) {
  if (verdict.worst === "none") {
    // The calm variant keeps SeverityChip's exact shape and type, in neutral grays.
    return (
      <span className="inline-flex shrink-0 items-center gap-1.5 rounded-[var(--r-chip)] border border-[var(--color-border)] bg-[var(--color-surface-2)] px-2 py-0.5 t-tag font-medium uppercase text-[var(--color-text-dim)]">
        <ShieldCheck className="h-3 w-3" aria-hidden />
        Clean
      </span>
    );
  }
  const color = sevColor(verdict.worst);
  const label = SEVERITY_META[verdict.worst]?.label ?? verdict.worst;
  return (
    <span
      className="inline-flex shrink-0 items-center gap-1.5 rounded-[var(--r-chip)] border px-2 py-0.5 t-tag font-medium uppercase"
      style={{ color, borderColor: color, backgroundColor: "var(--color-surface-2)" }}
    >
      <span aria-hidden className="h-1.5 w-1.5 rounded-full" style={{ backgroundColor: color }} />
      {verdict.worstCount} {label}
    </span>
  );
}

export default VerdictChip;
