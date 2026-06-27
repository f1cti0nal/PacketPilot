import { useCallback, useEffect, useState } from "react";
import {
  getAnnotation,
  setAnnotation,
  ANNOTATIONS_EVENT,
  STATUS_META,
  TRIAGE_STATUSES,
  type HostAnnotation,
  type TriageStatus,
} from "../lib/annotations";

/**
 * Read + write the triage annotation for `(captureKey, ip)`, kept in sync across every mounted
 * instance via the `ANNOTATIONS_EVENT` window event (and cross-tab `storage` events).
 */
export function useAnnotation(
  captureKey: string,
  ip: string,
): readonly [HostAnnotation | null, (patch: Partial<Pick<HostAnnotation, "status" | "note">>) => void] {
  const [ann, setAnn] = useState<HostAnnotation | null>(() => getAnnotation(captureKey, ip));

  useEffect(() => {
    const sync = () => setAnn(getAnnotation(captureKey, ip));
    sync();
    window.addEventListener(ANNOTATIONS_EVENT, sync);
    window.addEventListener("storage", sync);
    return () => {
      window.removeEventListener(ANNOTATIONS_EVENT, sync);
      window.removeEventListener("storage", sync);
    };
  }, [captureKey, ip]);

  const update = useCallback(
    (patch: Partial<Pick<HostAnnotation, "status" | "note">>) => {
      setAnnotation(captureKey, ip, patch);
    },
    [captureKey, ip],
  );

  return [ann, update] as const;
}

/** A read-only status pill; renders nothing for an untriaged host. */
export function TriageBadge({ captureKey, ip }: { captureKey: string; ip: string }) {
  const [ann] = useAnnotation(captureKey, ip);
  if (!ann || ann.status === "new") return null;
  const meta = STATUS_META[ann.status];
  return (
    <span
      data-component="TriageBadge"
      aria-label={`Triage: ${meta.label}`}
      title={ann.note || meta.label}
      className="inline-flex shrink-0 items-center gap-1 rounded-full border px-1.5 py-0.5 t-tag font-medium uppercase"
      style={{
        color: `var(${meta.cssVar})`,
        borderColor: `var(${meta.cssVar})`,
        backgroundColor: "var(--color-surface-2)",
      }}
    >
      {meta.label}
    </span>
  );
}

/** The editable triage control: a status selector + a free-text note, persisted per capture. */
export function TriageAnnotation({ captureKey, ip }: { captureKey: string; ip: string }) {
  const [ann, update] = useAnnotation(captureKey, ip);
  const status: TriageStatus = ann?.status ?? "new";

  return (
    <div data-component="TriageAnnotation" className="flex flex-col gap-2">
      <div role="group" aria-label="Triage status" className="flex flex-wrap gap-1">
        {TRIAGE_STATUSES.map((s) => {
          const meta = STATUS_META[s];
          const active = status === s;
          return (
            <button
              key={s}
              type="button"
              aria-pressed={active}
              onClick={() => update({ status: s })}
              className="rounded-[var(--r-chip)] border px-2 py-0.5 t-tag font-medium transition-colors"
              style={
                active
                  ? {
                      color: `var(${meta.cssVar})`,
                      borderColor: `var(${meta.cssVar})`,
                      backgroundColor: "var(--color-surface-2)",
                    }
                  : {
                      color: "var(--color-text-dim)",
                      borderColor: "var(--color-border)",
                    }
              }
            >
              {meta.label}
            </button>
          );
        })}
      </div>
      <textarea
        aria-label="Triage note"
        value={ann?.note ?? ""}
        placeholder="Add a triage note…"
        rows={2}
        onChange={(e) => update({ note: e.target.value })}
        className="w-full resize-y rounded-[var(--r-tile)] border border-[var(--color-border)] bg-[var(--color-surface-1)] px-2 py-1.5 text-xs text-[var(--color-text)] placeholder:text-[var(--color-text-faint)] focus:border-[var(--color-accent)] focus:outline-none"
      />
    </div>
  );
}
