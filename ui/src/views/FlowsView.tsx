import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { FilterProfiles } from "../components/flows/FilterProfiles";
import type { FlowFilter } from "../lib/filterProfiles";
import type { SortingState } from "@tanstack/react-table";
import { Download, Search, X } from "lucide-react";
import type {
  ActiveSource,
  FlowsState,
  FlowRow,
  FlowPackets,
  Severity,
  FlowCategory,
} from "../types";
import { normCategory } from "../lib/severity";
import { compactNumber, humanBytes, humanNumber } from "../lib/format";
import { flowStats } from "../lib/flowStats";
import { flowsToCsv } from "../lib/flowsCsv";
import { downloadText } from "../lib/platform";
import { extractFlowPackets, carveSubPcap } from "../lib/packets";
import { cn } from "../lib/cn";
import { LoadingState } from "../components/state/LoadingState";
import { ErrorState } from "../components/state/ErrorState";
import { EmptyState } from "../components/state/EmptyState";
import { FlowsTable } from "../components/flows/FlowsTable";
import { FlowDetail } from "../components/FlowDetail";
import { PacketInspector } from "../cockpit/PacketInspector";
import { Panel, Toolbar } from "../cockpit/primitives";

export interface FlowsViewProps {
  state: FlowsState;
  initialFilter?: { severity?: Severity; category?: string; proto?: number; ip?: string };
  /** The active capture source — enables per-flow packet drill-down when non-null. */
  activeSource: ActiveSource;
}

const ALL_CATEGORIES = "__all__";

/** Human label for a snake_case category token. */
function categoryLabel(token: string): string {
  return token
    .split("_")
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(" ");
}

/**
 * Flows view: composes a filter bar (free-text across ip/port/category plus a
 * category dropdown) above the virtualized FlowsTable, opening FlowDetailPanel
 * when a row is selected. Owns the selected-row, free-text, category, severity
 * and proto filter state, and feeds the already-filtered rows to FlowsTable.
 */
export function FlowsView({ state, initialFilter, activeSource }: FlowsViewProps) {
  const [query, setQuery] = useState("");
  const [category, setCategory] = useState<string>(ALL_CATEGORIES);
  const [severity, setSeverity] = useState<Severity | undefined>(undefined);
  const [proto, setProto] = useState<number | undefined>(undefined);
  const [selected, setSelected] = useState<FlowRow | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  // Packet inspector: which flow is being inspected, its extracted packets, and the
  // async load status. `inspecting` non-null mounts the PacketInspector overlay.
  const [inspecting, setInspecting] = useState<FlowRow | null>(null);
  const [packets, setPackets] = useState<FlowPackets | null>(null);
  const [pktLoading, setPktLoading] = useState(false);
  const [pktError, setPktError] = useState<string | null>(null);

  // Generation counter: each openInspector call bumps it; async callbacks check
  // the generation still matches before committing state, preventing a slow
  // extractFlowPackets for flow A from overwriting a faster result for flow B.
  const inspectGen = useRef(0);

  const openInspector = useCallback(
    (flow: FlowRow) => {
      const gen = ++inspectGen.current;
      setInspecting(flow);
      setPackets(null);
      setPktError(null);
      setPktLoading(true);
      extractFlowPackets(activeSource, flow)
        .then((fp) => { if (gen === inspectGen.current) setPackets(fp); })
        .catch((e) => { if (gen === inspectGen.current) setPktError(String((e as Error)?.message ?? e)); })
        .finally(() => { if (gen === inspectGen.current) setPktLoading(false); });
    },
    [activeSource],
  );

  // Stable identity so PacketInspector's focus/Esc effect doesn't re-fire on every render.
  // Also bumps the generation so any in-flight extraction for the closed flow is discarded.
  const closeInspector = useCallback(() => { inspectGen.current++; setInspecting(null); }, []);

  // Carve a sub-pcap for the given flow and surface success/failure via pktError.
  const carveFlow = useCallback(
    async (flow: FlowRow) => {
      const query = {
        src_ip: flow.srcIp,
        dst_ip: flow.dstIp,
        src_port: flow.srcPort,
        dst_port: flow.dstPort,
        proto: flow.proto,
        start_ns: Math.round(flow.startMs * 1e6),
        end_ns: Math.round(flow.endMs * 1e6),
      };
      const name = `${flow.srcIp}-${flow.dstIp}-${flow.srcPort}-${flow.dstPort}.pcap`;
      const res = await carveSubPcap(query, activeSource, name);
      if (res.ok) {
        setPktError(null);
      } else if (res.message) {
        setPktError(res.message);
      }
    },
    [activeSource],
  );

  // Default "busiest flows first". Must reference the column's id ("bytes"),
  // not the accessorKey ("bytesTotal") — the explicit column id wins, and a
  // mismatch makes TanStack drop the sort and warn "Column ... does not exist".
  const [sorting, setSorting] = useState<SortingState>([
    { id: "bytes", desc: true },
  ]);

  // Apply an inbound deep-link filter (e.g. "show me scan flows" from the
  // dashboard). Resets the free-text box so the targeted facet is unambiguous.
  useEffect(() => {
    if (!initialFilter) return;
    setSeverity(initialFilter.severity);
    setProto(initialFilter.proto);
    setCategory(
      initialFilter.category
        ? normCategory(initialFilter.category)
        : ALL_CATEGORIES,
    );
    setQuery(initialFilter.ip ?? "");
    setSelected(null);
  }, [initialFilter]);

  const rows = state.rows;

  // Distinct categories actually present in the data, for the dropdown.
  const categories = useMemo(() => {
    const set = new Set<FlowCategory>();
    for (const r of rows) set.add(r.category);
    return Array.from(set).sort();
  }, [rows]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return rows.filter((r) => {
      if (category !== ALL_CATEGORIES && r.category !== category) return false;
      if (severity !== undefined && r.severity !== severity) return false;
      if (proto !== undefined && r.proto !== proto) return false;
      if (q) {
        // Free-text across endpoints, ports and category token.
        const hay =
          r.srcIp +
          " " +
          r.dstIp +
          " " +
          r.srcPort +
          " " +
          r.dstPort +
          " " +
          r.category +
          " " +
          (r.appProto ?? "") +
          " " +
          (r.sni ?? "") +
          " " +
          (r.httpHost ?? "") +
          " " +
          (r.httpUa ?? "") +
          " " +
          (r.ja3 ?? "") +
          " " +
          (r.ja4 ?? "") +
          " " +
          (r.ja3s ?? "") +
          " " +
          (r.hassh ?? "") +
          " " +
          (r.hasshServer ?? "") +
          " " +
          r.protoLabel +
          " " +
          r.severity +
          " " +
          (r.ioc ? "ioc" : "");
        if (!hay.toLowerCase().includes(q)) return false;
      }
      return true;
    });
  }, [rows, query, category, severity, proto]);

  // If the selected row falls out of the filtered set, drop the detail panel.
  useEffect(() => {
    if (!selected) return;
    if (!filtered.some((r) => r.flowIdBig === selected.flowIdBig)) {
      setSelected(null);
    }
  }, [filtered, selected]);

  // Live aggregate over the current filter — bytes / packets / IOCs / top categories.
  const stats = useMemo(() => flowStats(filtered), [filtered]);

  const hasActiveFilters =
    query.trim() !== "" ||
    category !== ALL_CATEGORIES ||
    severity !== undefined ||
    proto !== undefined;

  // Export exactly what's on screen (the filtered set) as CSV.
  const exportCsv = useCallback(() => {
    if (filtered.length === 0) return;
    const name = hasActiveFilters ? "packetpilot-flows-filtered.csv" : "packetpilot-flows.csv";
    downloadText(flowsToCsv(filtered), name, "text/csv");
  }, [filtered, hasActiveFilters]);

  const clearFilters = () => {
    setQuery("");
    setCategory(ALL_CATEGORIES);
    setSeverity(undefined);
    setProto(undefined);
  };

  const applyProfile = useCallback((f: FlowFilter) => {
    setQuery(f.query);
    setCategory(f.category);
    setSeverity(f.severity);
    setProto(f.proto);
  }, []);

  if (state.status === "idle" || state.status === "loading") {
    return <LoadingState label="Loading flows…" />;
  }
  if (state.status === "error") {
    return <ErrorState message={state.error ?? "Failed to load flows"} />;
  }
  if (rows.length === 0) {
    return (
      <EmptyState
        title="No flows in this capture"
        hint="The capture contained no flow records."
      />
    );
  }

  const inputBase =
    "rounded border border-[var(--color-border)] bg-[var(--color-surface-2)] " +
    "text-[length:var(--fs-body)] text-[var(--color-text)] placeholder:text-[var(--color-text-faint)] " +
    "focus:outline-none focus:ring-1 focus:ring-[var(--color-accent)] " +
    "focus:border-[var(--color-accent)]";

  return (
    <div
      data-component="FlowsView"
      className="flex h-full min-h-0 flex-col gap-3"
    >
      {/* Filter toolbar */}
      <Toolbar className="gap-2">
        <div className="relative min-w-[16rem] flex-1">
          <Search
            className="pointer-events-none absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-[var(--color-text-faint)]"
            aria-hidden
          />
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Filter by IP, port, category, or SNI…"
            aria-label="Filter flows"
            className={cn(inputBase, "w-full py-1.5 pl-8 pr-8 font-mono-num")}
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
          <span>Category</span>
          <select
            value={category}
            onChange={(e) => setCategory(e.target.value)}
            aria-label="Filter by category"
            className={cn(inputBase, "py-1.5 pl-2.5 pr-7")}
          >
            <option value={ALL_CATEGORIES}>All categories</option>
            {categories.map((c) => (
              <option key={c} value={c}>
                {categoryLabel(c)}
              </option>
            ))}
          </select>
        </label>

        <div className="ml-auto flex items-center gap-2 text-[length:var(--fs-body)] text-[var(--color-text-dim)]">
          <span>
            <span className="font-mono-num text-[var(--color-text)]">
              {humanNumber(filtered.length)}
            </span>
            {" / "}
            <span className="font-mono-num">{humanNumber(rows.length)}</span>
            {" flows"}
          </span>
          {hasActiveFilters && (
            <button
              type="button"
              onClick={clearFilters}
              className="rounded border border-[var(--color-border)] bg-[var(--color-surface-2)] px-2.5 py-1 text-[length:var(--fs-label)] text-[var(--color-text-dim)] hover:text-[var(--color-text)] hover:border-[var(--color-accent)]"
            >
              Clear filters
            </button>
          )}
          <button
            type="button"
            onClick={exportCsv}
            disabled={filtered.length === 0}
            title="Export the filtered flows to CSV"
            className="inline-flex items-center gap-1.5 rounded border border-[var(--color-border)] bg-[var(--color-surface-2)] px-2.5 py-1 text-[length:var(--fs-label)] text-[var(--color-text-dim)] hover:text-[var(--color-text)] hover:border-[var(--color-accent)] disabled:opacity-50"
          >
            <Download className="h-3.5 w-3.5" aria-hidden />
            Export CSV
          </button>
          <FilterProfiles
            current={{ query, category, severity, proto }}
            hasActiveFilters={hasActiveFilters}
            onApply={applyProfile}
            onNotice={setNotice}
          />
        </div>
      </Toolbar>

      {/* Live stats for the current filter — bytes / packets / IOCs / top categories. */}
      <div
        data-component="FlowsStats"
        className="flex flex-wrap items-center gap-x-4 gap-y-1 text-[length:var(--fs-label)] text-[var(--color-text-dim)]"
      >
        <span>
          <span className="font-mono-num text-[var(--color-text)]">{humanBytes(stats.bytes)}</span>
        </span>
        <span>
          <span className="font-mono-num text-[var(--color-text)]">{compactNumber(stats.packets)}</span>{" "}
          packets
        </span>
        {stats.iocs > 0 && (
          <span>
            <span className="font-mono-num" style={{ color: "var(--color-sev-critical)" }}>
              {humanNumber(stats.iocs)}
            </span>{" "}
            IOC{stats.iocs === 1 ? "" : "s"}
          </span>
        )}
        {stats.topCategories.length > 0 && (
          <span className="flex flex-wrap items-center gap-2">
            <span className="text-[var(--color-text-faint)]">Top:</span>
            {stats.topCategories.map((c) => (
              <span key={c.category} className="inline-flex items-center gap-1">
                {categoryLabel(c.category)}
                <span className="font-mono-num text-[var(--color-text-faint)]">
                  {compactNumber(c.flows)}
                </span>
              </span>
            ))}
          </span>
        )}
      </div>

      {notice && (
        <p className="text-[length:var(--fs-label)] text-[var(--color-text-dim)]" role="status">
          {notice}
        </p>
      )}

      {/* Table + detail */}
      <div className="flex min-h-0 flex-1 gap-3">
        <Panel className="min-h-0 min-w-0 flex-1" bodyClassName="min-h-0 flex-1 flex flex-col">
          {filtered.length === 0 ? (
            <EmptyState
              title="No flows match the current filters"
              hint="Try clearing the text filter or selecting a different category."
            />
          ) : (
            <FlowsTable
              rows={filtered}
              sorting={sorting}
              onSortingChange={setSorting}
              onRowClick={setSelected}
              selectedFlowId={selected?.flowId ?? null}
            />
          )}
        </Panel>

        {selected && (
          // Mobile: full-screen overlay (an inline 352px column would crush the
          // flows table to a sliver and overflow the narrowest phones). Desktop:
          // the inline side-by-side detail column.
          <aside className="fixed inset-0 z-40 min-h-0 w-full overflow-auto bg-[var(--color-bg)] md:static md:z-auto md:w-[22rem] md:shrink-0 md:bg-transparent">
            <FlowDetail
              flow={selected}
              onClose={() => setSelected(null)}
              activeSource={activeSource}
              onInspectPackets={() => openInspector(selected)}
              onCarvePcap={() => carveFlow(selected)}
            />
          </aside>
        )}
      </div>

      {inspecting && (
        <PacketInspector
          flow={inspecting}
          packets={packets}
          loading={pktLoading}
          error={pktError}
          onClose={closeInspector}
        />
      )}
    </div>
  );
}

export default FlowsView;
