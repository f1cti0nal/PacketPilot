import clsx from "clsx";
import type { Finding } from "../../types";
import { dstLabel, hasTarget } from "../../lib/findingTarget";

/**
 * The `src → dst` attribution row for a finding, where `dst` is the peer host (`ip:port`) or the
 * service port (`port N`) the finding names — see {@link dstLabel}. Renders nothing when the finding
 * carries no destination at all (a pure fan-out finding), so callers can drop it in unconditionally
 * without printing a bare "src → —".
 *
 * Mirrors the mono `src → dst` row already used by the signature-match and TLS-posture triage panels,
 * so a predictive `traffic_anomaly` shows the peer/port it was attributed to in the same shape.
 */
export function FindingTarget({
  finding,
  className,
}: {
  finding: Pick<Finding, "src_ip" | "dst_ip" | "dst_port">;
  className?: string;
}) {
  if (!hasTarget(finding)) return null;
  return (
    <div
      className={clsx(
        "font-mono-num flex items-center gap-1.5 text-xs text-[var(--color-text-dim)]",
        className,
      )}
    >
      <span className="truncate">{finding.src_ip}</span>
      <span className="text-[var(--color-text-faint)]" aria-hidden>
        →
      </span>
      <span className="truncate">{dstLabel(finding)}</span>
    </div>
  );
}
