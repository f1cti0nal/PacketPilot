import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Download, ExternalLink, Play, Save } from "lucide-react";
import type { FlowsState, FlowRow } from "../types";
import type { QueryEngine, QueryResult } from "../lib/query/engine";
import { SAMPLE_QUERIES } from "../lib/query/samples";
import {
  listSavedQueries,
  removeSavedQuery,
  saveQuery,
  type SavedQuery,
} from "../lib/query/savedQueries";
import { resultsToCsv } from "../lib/query/results";
import { downloadText } from "../lib/platform";
import { humanNumber } from "../lib/format";
import { cn } from "../lib/cn";
import { LoadingState } from "../components/state/LoadingState";
import { ErrorState } from "../components/state/ErrorState";
import { EmptyState } from "../components/state/EmptyState";
import { ResultsGrid } from "../components/query/ResultsGrid";
import { BTN_OUTLINE, BTN_PRIMARY, INPUT_BASE, Panel, Toolbar } from "../cockpit/primitives";

export interface QueryViewProps {
  state: FlowsState;
  /** Lift a flow_id result set into the Flows tab as a cross-filter. */
  onOpenInFlows: (flowIds: Set<number>) => void;
}

/**
 * Identity key for a loaded rows array, so the engine reloads the `flow` table
 * exactly when the dataset object changes (capture switch, out-of-band flows
 * replace) and never re-ingests on mere re-renders.
 */
const rowsKeys = new WeakMap<object, string>();
let rowsKeyCounter = 0;
function rowsIdentityKey(rows: FlowRow[]): string {
  let key = rowsKeys.get(rows);
  if (!key) {
    key = `rows-${++rowsKeyCounter}`;
    rowsKeys.set(rows, key);
  }
  return key;
}

type EngineStatus = "booting" | "ready" | "error";

/**
 * Query console: run read-only DuckDB SQL against the loaded capture's flows,
 * entirely in-browser (the engine is a lazy-loaded wasm worker — nothing ever
 * leaves the device). Phase 2 of the NLQ plan; the natural-language input
 * lands on top of this in Phase 3.
 */
export function QueryView({ state, onOpenInFlows }: QueryViewProps) {
  const rows = state.rows;

  const [engineStatus, setEngineStatus] = useState<EngineStatus>("booting");
  const [engineError, setEngineError] = useState<string | null>(null);
  const engineRef = useRef<QueryEngine | null>(null);

  const [sql, setSql] = useState<string>(SAMPLE_QUERIES[0].sql);
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<QueryResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  // Discards a stale in-flight run when a newer one starts or the view unmounts.
  const runGen = useRef(0);

  const [saved, setSaved] = useState<SavedQuery[]>(() => listSavedQueries());
  const [saveName, setSaveName] = useState("");
  const [notice, setNotice] = useState<string | null>(null);

  // Boot the engine and (re)load the flow table whenever the dataset changes.
  useEffect(() => {
    if (state.status !== "ready" || rows.length === 0) return;
    let alive = true;
    setEngineStatus((s) => (s === "ready" ? s : "booting"));
    void (async () => {
      try {
        // Dynamic import keeps duckdb-wasm out of the main bundle (see engine.ts).
        const { getQueryEngine } = await import("../lib/query/engine");
        const engine = await getQueryEngine();
        await engine.loadFlows(rows, rowsIdentityKey(rows));
        if (!alive) return;
        engineRef.current = engine;
        setEngineStatus("ready");
        setEngineError(null);
      } catch (err: unknown) {
        if (!alive) return;
        setEngineStatus("error");
        setEngineError(String((err as Error)?.message ?? err));
      }
    })();
    return () => {
      alive = false;
    };
  }, [state.status, rows]);

  // Auto-dismiss transient notices (save/delete confirmations).
  useEffect(() => {
    if (!notice) return;
    const t = window.setTimeout(() => setNotice(null), 2500);
    return () => window.clearTimeout(t);
  }, [notice]);

  const runQuery = useCallback(async () => {
    const engine = engineRef.current;
    if (!engine || engineStatus !== "ready") return;
    const gen = ++runGen.current;
    setRunning(true);
    setError(null);
    try {
      const res = await engine.run(sql);
      if (gen === runGen.current) setResult(res);
    } catch (err: unknown) {
      if (gen === runGen.current) {
        setResult(null);
        setError(String((err as Error)?.message ?? err));
      }
    } finally {
      if (gen === runGen.current) setRunning(false);
    }
  }, [engineStatus, sql]);

  const onEditorKeyDown = useCallback(
    (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
      if ((e.metaKey || e.ctrlKey) && e.key === "Enter") {
        e.preventDefault();
        void runQuery();
      }
    },
    [runQuery],
  );

  const applySample = useCallback((id: string) => {
    const sample = SAMPLE_QUERIES.find((s) => s.id === id);
    if (sample) setSql(sample.sql);
  }, []);

  const applySaved = useCallback(
    (id: string) => {
      const q = saved.find((s) => s.id === id);
      if (q) setSql(q.sql);
    },
    [saved],
  );

  const handleSave = useCallback(() => {
    const name = saveName.trim();
    if (!name) return;
    setSaved(saveQuery(name, sql));
    setSaveName("");
    setNotice(`Saved "${name}"`);
  }, [saveName, sql]);

  const handleDeleteSaved = useCallback((id: string) => {
    const q = listSavedQueries().find((s) => s.id === id);
    setSaved(removeSavedQuery(id));
    if (q) setNotice(`Deleted "${q.name}"`);
  }, []);

  const exportCsv = useCallback(() => {
    if (!result || result.rows.length === 0) return;
    downloadText(resultsToCsv(result), "packetpilot-query.csv", "text/csv");
  }, [result]);

  // "Open in Flows" needs a flow_id column in the result.
  const flowIdIndex = useMemo(
    () => result?.columns.findIndex((c) => c.name === "flow_id") ?? -1,
    [result],
  );
  const flowIds = useMemo(() => {
    if (!result || flowIdIndex < 0) return null;
    const ids = new Set<number>();
    for (const row of result.rows) {
      const v = row[flowIdIndex];
      const n = typeof v === "bigint" ? Number(v) : typeof v === "number" ? v : NaN;
      if (Number.isFinite(n)) ids.add(n);
    }
    return ids.size > 0 ? ids : null;
  }, [result, flowIdIndex]);

  if (state.status === "idle") {
    return (
      <EmptyState
        title="No capture loaded"
        hint="Load a capture (or open the sample) to query its flows with SQL."
      />
    );
  }
  if (state.status === "loading") {
    return <LoadingState label="Loading flows…" />;
  }
  if (state.status === "error") {
    return <ErrorState message={state.error ?? "Failed to load flows"} />;
  }
  if (rows.length === 0) {
    return (
      <EmptyState
        title="No flows in this capture"
        hint="The capture contained no flow records to query."
      />
    );
  }

  const engineReady = engineStatus === "ready";

  return (
    <div data-component="QueryView" className="flex h-full min-h-0 flex-col gap-3">
      <Toolbar className="gap-2">
        <label className="flex items-center gap-2 text-[length:var(--fs-body)] text-[var(--color-text-dim)]">
          <span>Bundled</span>
          <select
            value=""
            onChange={(e) => {
              if (e.target.value) applySample(e.target.value);
              e.target.value = "";
            }}
            aria-label="Insert a bundled query"
            className={cn(INPUT_BASE, "py-1.5 pl-2.5 pr-7")}
          >
            <option value="">Insert query…</option>
            {SAMPLE_QUERIES.map((s) => (
              <option key={s.id} value={s.id}>
                {s.label}
              </option>
            ))}
          </select>
        </label>

        {saved.length > 0 && (
          <label className="flex items-center gap-2 text-[length:var(--fs-body)] text-[var(--color-text-dim)]">
            <span>Saved</span>
            <select
              value=""
              onChange={(e) => {
                if (e.target.value) applySaved(e.target.value);
                e.target.value = "";
              }}
              aria-label="Insert a saved query"
              className={cn(INPUT_BASE, "py-1.5 pl-2.5 pr-7")}
            >
              <option value="">Insert saved…</option>
              {saved.map((q) => (
                <option key={q.id} value={q.id}>
                  {q.name}
                </option>
              ))}
            </select>
          </label>
        )}
        {saved.length > 0 && (
          <select
            value=""
            onChange={(e) => {
              if (e.target.value) handleDeleteSaved(e.target.value);
              e.target.value = "";
            }}
            aria-label="Delete a saved query"
            title="Delete a saved query"
            className={cn(INPUT_BASE, "py-1.5 pl-2.5 pr-7")}
          >
            <option value="">Delete saved…</option>
            {saved.map((q) => (
              <option key={q.id} value={q.id}>
                {q.name}
              </option>
            ))}
          </select>
        )}

        <div className="ml-auto flex items-center gap-2">
          <input
            type="text"
            value={saveName}
            onChange={(e) => setSaveName(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") handleSave();
            }}
            placeholder="Save as…"
            aria-label="Name for the saved query"
            className={cn(INPUT_BASE, "w-36 px-2.5 py-1.5")}
          />
          <button
            type="button"
            onClick={handleSave}
            disabled={saveName.trim() === ""}
            title="Save the current SQL under this name"
            className={BTN_OUTLINE}
          >
            <Save className="h-3.5 w-3.5" aria-hidden />
            Save
          </button>
        </div>
      </Toolbar>

      {notice && (
        <p className="text-[length:var(--fs-label)] text-[var(--color-text-dim)]" role="status">
          {notice}
        </p>
      )}

      <Panel label="SQL" title="Query the flow table" bodyClassName="flex flex-col gap-2 p-3">
        <textarea
          value={sql}
          onChange={(e) => setSql(e.target.value)}
          onKeyDown={onEditorKeyDown}
          rows={8}
          spellCheck={false}
          aria-label="SQL query"
          placeholder="SELECT … FROM flow"
          className={cn(
            INPUT_BASE,
            "w-full resize-y px-3 py-2 font-mono-num text-[length:var(--fs-body)] leading-relaxed",
          )}
        />
        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={() => void runQuery()}
            disabled={!engineReady || running || sql.trim() === ""}
            className={BTN_PRIMARY}
          >
            <Play className="h-3.5 w-3.5" aria-hidden />
            {running ? "Running…" : "Run"}
          </button>
          <span className="text-[length:var(--fs-label)] text-[var(--color-text-faint)]">
            Ctrl/⌘ + Enter
          </span>
          <span
            className="ml-auto text-[length:var(--fs-label)] text-[var(--color-text-dim)]"
            role="status"
          >
            {engineStatus === "booting"
              ? "Preparing query engine…"
              : engineStatus === "error"
                ? "Query engine unavailable"
                : `${humanNumber(rows.length)} flows loaded · local only`}
          </span>
        </div>
        {(error || engineError) && (
          <p
            role="alert"
            className="rounded-[var(--r-tile)] border border-[var(--color-border)] bg-[var(--color-surface-2)] px-3 py-2 font-mono-num text-[length:var(--fs-label)] text-[var(--color-sev-high,#e5484d)]"
          >
            {error ?? engineError}
          </p>
        )}
      </Panel>

      <Panel
        className="min-h-0 flex-1"
        bodyClassName="min-h-0 flex-1 flex flex-col"
        label="Results"
        title={
          result
            ? `${humanNumber(result.rowCount)} row${result.rowCount === 1 ? "" : "s"}`
            : "Results"
        }
        right={
          result ? (
            <span className="flex items-center gap-2 text-[length:var(--fs-label)] text-[var(--color-text-dim)]">
              {result.truncated && (
                <span
                  title="The result was cut off at the row cap — add filters or aggregate."
                  className="rounded-[var(--r-chip)] border border-[var(--color-border)] px-1.5 py-0.5"
                >
                  truncated
                </span>
              )}
              {result.limitApplied && (
                <span title="No LIMIT in the query — a default LIMIT was applied.">
                  auto-limit
                </span>
              )}
              <span className="font-mono-num">{result.elapsedMs} ms</span>
              {flowIds && (
                <button
                  type="button"
                  onClick={() => onOpenInFlows(flowIds)}
                  title="Filter the Flows tab to this result's flow_ids"
                  className={BTN_OUTLINE}
                >
                  <ExternalLink className="h-3.5 w-3.5" aria-hidden />
                  Open in Flows ({humanNumber(flowIds.size)})
                </button>
              )}
              <button
                type="button"
                onClick={exportCsv}
                disabled={result.rows.length === 0}
                title="Export this result to CSV"
                className={BTN_OUTLINE}
              >
                <Download className="h-3.5 w-3.5" aria-hidden />
                CSV
              </button>
            </span>
          ) : undefined
        }
      >
        {result ? (
          result.rows.length === 0 ? (
            <EmptyState title="No rows" hint="The query matched nothing in this capture." />
          ) : (
            <ResultsGrid result={result} />
          )
        ) : (
          <EmptyState
            title="Run a query"
            hint="Results appear here. Try a bundled query from the toolbar."
          />
        )}
      </Panel>
    </div>
  );
}

export default QueryView;
