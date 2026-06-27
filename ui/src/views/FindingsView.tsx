import { useMemo, useState } from "react";
import { Search, X, ArrowRight } from "lucide-react";
import type { Finding, FindingKind, Severity } from "../types";
import { kindLabel, kindMeta } from "../lib/findingKinds";
import { SEVERITY_META, SEVERITY_ORDER } from "../lib/severity";
import { humanNumber } from "../lib/format";
import { sevColor } from "../cockpit/viz";
import { MitreTag, Panel, Toolbar } from "../cockpit/primitives";
import { EmptyState } from "../components/state/EmptyState";
import { cn } from "../lib/cn";

export interface FindingsViewProps {
  findings: Finding[];
  /** Drill into Flows filtered by a finding's source host. */
  onJumpToFlows?: (filter: { ip?: string }) => void;
}

type SortKey = "severity" | "kind" | "source" | "score";
type SortDir = "asc" | "desc";

const SEV_RANK: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
  none: 0,
};

const ALL = "__all__";

/** Ascending base comparator; the active direction is applied by the caller. */
function baseCompare(a: Finding, b: Finding, key: SortKey): number {
  switch (key) {
    case "severity":
      return SEV_RANK[a.severity] - SEV_RANK[b.severity] || a.score - b.score;
    case "score":
      return a.score - b.score;
    case "kind":
      return kindLabel(a.kind).localeCompare(kindLabel(b.kind));
    case "source":
      return a.src_ip.localeCompare(b.src_ip);
  }
}

/**
 * Findings triage view: every behavioral finding in the active capture as a filterable, sortable
 * table — the finding-centric companion to the incident-centric dashboard. Free-text + severity +
 * kind filters; click a column header to sort; click a row to pivot into the host's flows.
 */
export function FindingsView({ findings, onJumpToFlows }: FindingsViewProps) {
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState<string>(ALL);
  const [kind, setKind] = useState<string>(ALL);
  const [sort, setSort] = useState<{ key: SortKey; dir: SortDir }>({ key: "severity", dir: "desc" });

  // Distinct kinds actually present, for the dropdown.
  const kinds = useMemo(() => {
    const set = new Set<FindingKind>();
    for (const f of findings) set.add(f.kind);
    return [...set].sort((a, b) => kindLabel(a).localeCompare(kindLabel(b)));
  }, [findings]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    const rows = findings.filter((f) => {
      if (severity !== ALL && f.severity !== severity) return false;
      if (kind !== ALL && f.kind !== kind) return false;
      if (q) {
        const hay = `${f.src_ip} ${f.dst_ip ?? ""} ${f.dst_port ?? ""} ${kindLabel(f.kind)} ${f.title} ${f.attack.join(" ")}`;
        if (!hay.toLowerCase().includes(q)) return false;
      }
      return true;
    });
    rows.sort((a, b) => {
      const c = baseCompare(a, b, sort.key);
      return sort.dir === "asc" ? c : -c;
    });
    return rows;
  }, [findings, query, severity, kind, sort]);

  const hasFilters = query.trim() !== "" || severity !== ALL || kind !== ALL;
  const clear = () => {
    setQuery("");
    setSeverity(ALL);
    setKind(ALL);
  };
  const toggleSort = (key: SortKey) =>
    setSort((s) =>
      s.key === key
        ? { key, dir: s.dir === "asc" ? "desc" : "asc" }
        : { key, dir: key === "kind" || key === "source" ? "asc" : "desc" },
    );

  if (findings.length === 0) {
    return (
      <EmptyState
        title="No behavioral findings"
        hint="This capture has no cross-flow findings, or no capture is loaded yet."
      />
    );
  }

  const inputBase =
    "rounded border border-[var(--color-border)] bg-[var(--color-surface-2)] " +
    "text-[length:var(--fs-body)] text-[var(--color-text)] placeholder:text-[var(--color-text-faint)] " +
    "focus:outline-none focus:ring-1 focus:ring-[var(--color-accent)] focus:border-[var(--color-accent)]";

  const SortHead = ({ label, k, className }: { label: string; k: SortKey; className?: string }) => (
    <th
      className={cn(
        "cursor-pointer select-none px-3 py-2 text-left text-[10px] font-medium uppercase tracking-wider text-[var(--color-text-faint)] hover:text-[var(--color-text-dim)]",
        className,
      )}
      aria-sort={sort.key === k ? (sort.dir === "asc" ? "ascending" : "descending") : "none"}
      onClick={() => toggleSort(k)}
    >
      {label}
      <span className="ml-1 font-mono-num">{sort.key === k ? (sort.dir === "asc" ? "↑" : "↓") : ""}</span>
    </th>
  );

  return (
    <div data-component="FindingsView" className="flex h-full min-h-0 flex-col gap-3">
      <Toolbar className="gap-2">
        <div className="relative min-w-[16rem] flex-1">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-[var(--color-text-faint)]" aria-hidden />
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Filter by host, kind, title, or technique…"
            aria-label="Filter findings"
            className={cn(inputBase, "w-full py-1.5 pl-8 pr-8")}
          />
          {query && (
            <button
              type="button"
              onClick={() => setQuery("")}
              aria-label="Clear text filter"
              className="absolute right-2 top-1/2 -translate-y-1/2 text-[var(--color-text-faint)] hover:text-[var(--color-text)]"
            >
              <X className="h-4 w-4" />
            </button>
          )}
        </div>

        <label className="flex items-center gap-2 text-[length:var(--fs-body)] text-[var(--color-text-dim)]">
          <span>Severity</span>
          <select
            value={severity}
            onChange={(e) => setSeverity(e.target.value)}
            aria-label="Filter by severity"
            className={cn(inputBase, "py-1.5 pl-2.5 pr-7")}
          >
            <option value={ALL}>All</option>
            {SEVERITY_ORDER.map((s) => (
              <option key={s} value={s}>
                {SEVERITY_META[s].label}
              </option>
            ))}
          </select>
        </label>

        <label className="flex items-center gap-2 text-[length:var(--fs-body)] text-[var(--color-text-dim)]">
          <span>Kind</span>
          <select
            value={kind}
            onChange={(e) => setKind(e.target.value)}
            aria-label="Filter by kind"
            className={cn(inputBase, "py-1.5 pl-2.5 pr-7")}
          >
            <option value={ALL}>All</option>
            {kinds.map((k) => (
              <option key={k} value={k}>
                {kindLabel(k)}
              </option>
            ))}
          </select>
        </label>

        <div className="ml-auto flex items-center gap-2 text-[length:var(--fs-body)] text-[var(--color-text-dim)]">
          <span>
            <span className="font-mono-num text-[var(--color-text)]">{humanNumber(filtered.length)}</span>
            {" / "}
            <span className="font-mono-num">{humanNumber(findings.length)}</span>
            {" findings"}
          </span>
          {hasFilters && (
            <button
              type="button"
              onClick={clear}
              className="rounded border border-[var(--color-border)] bg-[var(--color-surface-2)] px-2.5 py-1 text-[length:var(--fs-label)] text-[var(--color-text-dim)] hover:border-[var(--color-accent)] hover:text-[var(--color-text)]"
            >
              Clear filters
            </button>
          )}
        </div>
      </Toolbar>

      <Panel className="min-h-0 flex-1 overflow-auto">
        {filtered.length === 0 ? (
          <EmptyState title="No findings match the current filters" hint="Try clearing the text filter or a dropdown." />
        ) : (
          <table className="pp-table">
            <thead>
              <tr>
                <SortHead label="Severity" k="severity" className="w-28" />
                <SortHead label="Finding" k="kind" />
                <SortHead label="Source" k="source" className="hidden md:table-cell" />
                <th className="hidden px-3 py-2 text-left text-[10px] font-medium uppercase tracking-wider text-[var(--color-text-faint)] lg:table-cell">Target</th>
                <SortHead label="Score" k="score" className="w-16" />
                <th className="hidden px-3 py-2 text-left text-[10px] font-medium uppercase tracking-wider text-[var(--color-text-faint)] xl:table-cell">ATT&CK</th>
                <th className="w-8 px-3 py-2" />
              </tr>
            </thead>
            <tbody>
              {filtered.map((f, i) => {
                const color = sevColor(f.severity);
                const { Icon } = kindMeta(f.kind);
                const target = f.dst_ip ? `${f.dst_ip}${f.dst_port ? `:${f.dst_port}` : ""}` : "—";
                const clickable = !!onJumpToFlows;
                return (
                  <tr
                    key={`${f.kind}-${f.src_ip}-${i}`}
                    onClick={clickable ? () => onJumpToFlows!({ ip: f.src_ip }) : undefined}
                    className={cn(
                      "border-t border-[var(--color-border)] transition-colors",
                      clickable && "cursor-pointer hover:bg-[var(--color-surface-2)]",
                    )}
                    style={{ borderLeft: `2px solid ${color}` }}
                  >
                    <td className="px-3 py-2.5">
                      <span
                        className="inline-flex items-center gap-1.5 rounded-[var(--r-chip)] border px-2 py-0.5 t-tag font-medium"
                        style={{ color, borderColor: color, backgroundColor: "var(--color-surface-2)" }}
                      >
                        <span aria-hidden className="h-1.5 w-1.5 rounded-full" style={{ backgroundColor: color }} />
                        {SEVERITY_META[f.severity]?.label ?? f.severity}
                      </span>
                    </td>
                    <td className="min-w-0 px-3 py-2.5">
                      <div className="flex items-center gap-2">
                        <Icon className="h-3.5 w-3.5 shrink-0 text-[var(--color-text-faint)]" aria-hidden />
                        <span className="text-sm font-medium text-[var(--color-text)]">{kindLabel(f.kind)}</span>
                      </div>
                      <div className="font-mono-num mt-0.5 truncate text-xs text-[var(--color-text-dim)]" title={f.title}>
                        {f.title}
                      </div>
                    </td>
                    <td className="hidden px-3 py-2.5 md:table-cell">
                      <span className="font-mono-num text-xs text-[var(--color-text-dim)]">{f.src_ip}</span>
                    </td>
                    <td className="hidden px-3 py-2.5 lg:table-cell">
                      <span className="font-mono-num text-xs text-[var(--color-text-faint)]">{target}</span>
                    </td>
                    <td className="px-3 py-2.5">
                      <span className="font-mono-num text-xs font-medium tabular-nums" style={{ color }}>
                        {f.score}
                      </span>
                    </td>
                    <td className="hidden px-3 py-2.5 xl:table-cell">
                      <div className="flex flex-wrap gap-1">
                        {f.attack.slice(0, 3).map((t) => (
                          <MitreTag key={t} id={t} />
                        ))}
                      </div>
                    </td>
                    <td className="px-3 py-2.5">
                      {clickable && (
                        <ArrowRight className="h-3.5 w-3.5 text-[var(--color-text-faint)]" aria-hidden />
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </Panel>
    </div>
  );
}

export default FindingsView;
