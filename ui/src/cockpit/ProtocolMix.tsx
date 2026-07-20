// ProtocolMix — a single segmented stacked bar of L4/L7 protocol composition.
// When TLS dominates, a caption notes it; the C2-beacon framing only appears
// when the parent confirms a beacon incident exists (beaconIncident prop).
import { useMemo } from "react";
import { humanNumber, percent } from "../lib/format";
import { protoSegments } from "./viz";
import { Card } from "./primitives";
import type { ProtoCounts } from "../types";

/** Segment keys whose token cleanly filters the Flows view (matches a flow's appProto). The
 *  "other_tcp" / "other_udp" / "non_ipv4" segments have no clean flow-filter token, so stay static. */
const FILTERABLE = new Set(["dns", "http", "tls"]);

export function ProtocolMix({
  proto,
  onSelect,
  beaconIncident = false,
}: {
  proto: ProtoCounts;
  /** Drill into Flows filtered on the clicked protocol token. Legend is static when omitted. */
  onSelect?: (key: string) => void;
  /** True when the capture actually carries a beacon incident; gates the C2-profile caption
   *  so a TLS-heavy mix alone never claims a beacon that was not detected. */
  beaconIncident?: boolean;
}): JSX.Element {
  const segs = useMemo(() => protoSegments(proto), [proto]);
  const total = useMemo(() => segs.reduce((sum, s) => sum + s.value, 0), [segs]);
  const tlsHeavy = useMemo(
    () => segs.length > 0 && segs[0].key === "tls" && segs[0].value === Math.max(...segs.map((s) => s.value)),
    [segs],
  );

  return (
    <Card label="PROTOCOLS" title="Protocol mix">
      {total === 0 ? (
        <div className="py-6 text-center t-body text-[var(--color-text-faint)]">No protocol traffic</div>
      ) : (
        <div className="flex flex-col gap-3">
          <div className="flex h-3 w-full overflow-hidden rounded-[var(--r-tile)] bg-[var(--color-surface-3)]">
            {segs.map((s) => (
              <div
                key={s.key}
                className="h-full border-r border-[var(--color-surface-1)] last:border-r-0"
                style={{
                  width: `${(s.value / total) * 100}%`,
                  minWidth: 2,
                  backgroundColor: s.color,
                }}
                title={`${s.label}: ${humanNumber(s.value)} (${percent(s.value, total)})`}
              />
            ))}
          </div>

          <div className="flex flex-wrap gap-x-3 gap-y-1.5">
            {segs.map((s) => {
              const clickable = !!onSelect && FILTERABLE.has(s.key);
              const inner = (
                <>
                  <span
                    aria-hidden
                    className="inline-block h-2 w-2 shrink-0 rounded-[var(--r-micro)]"
                    style={{ backgroundColor: s.color }}
                  />
                  <span className="text-xs text-[var(--color-text-dim)]">{s.label}</span>
                  <span className="font-mono-num text-xs text-[var(--color-text-faint)]">
                    {percent(s.value, total)}
                  </span>
                </>
              );
              return clickable ? (
                <button
                  key={s.key}
                  type="button"
                  onClick={() => onSelect!(s.key)}
                  title={`Show ${s.label} flows`}
                  className="flex items-center gap-1.5 rounded-[var(--r-micro)] px-0.5 transition-colors hover:bg-[var(--color-surface-2)]"
                >
                  {inner}
                </button>
              ) : (
                <div key={s.key} className="flex items-center gap-1.5">
                  {inner}
                </div>
              );
            })}
          </div>

          {tlsHeavy && (
            <div className="t-label">
              {beaconIncident
                ? "TLS-heavy, consistent with the C2 beacon profile"
                : "TLS-heavy traffic mix"}
            </div>
          )}
        </div>
      )}
    </Card>
  );
}

export default ProtocolMix;
