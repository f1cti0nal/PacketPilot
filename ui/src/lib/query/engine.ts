/**
 * The in-browser query engine: DuckDB-Wasm over the loaded capture's flows.
 *
 * IMPORTANT: consumers must load this module with a dynamic `import()` — it
 * statically imports the DuckDB wasm/worker assets (~35 MB, vendored
 * same-origin per the CSP: `worker-src 'self'`, no CDN), and a static import
 * would drag all of that into the main bundle. `getQueryEngine()` is the only
 * intended entry point.
 *
 * Hardening (three layers, see the NLQ plan §3.2): `guardSql` screens every
 * statement; the session runs with `enable_external_access = false` +
 * `lock_configuration = true` set before any user SQL; and `run()` caps
 * materialization at {@link MAX_RESULT_ROWS} rows / {@link QUERY_TIMEOUT_MS} ms
 * (over-cap and overtime queries are cancelled in the worker, not just
 * abandoned).
 */

import * as duckdb from "@duckdb/duckdb-wasm";
import wasmMvp from "@duckdb/duckdb-wasm/dist/duckdb-mvp.wasm?url";
import workerMvp from "@duckdb/duckdb-wasm/dist/duckdb-browser-mvp.worker.js?url";
import wasmEh from "@duckdb/duckdb-wasm/dist/duckdb-eh.wasm?url";
import workerEh from "@duckdb/duckdb-wasm/dist/duckdb-browser-eh.worker.js?url";

import type { FlowRow } from "../../types";
import {
  FLOW_INGEST_TABLE,
  buildFlowArrowTable,
  buildFlowInsertSql,
  makeValueConverter,
} from "./arrow";
import { guardSql } from "./guard";
import { FLOW_TABLE_DDL } from "./schema";

/** Materialization cap; queries producing more rows are truncated + cancelled. */
export const MAX_RESULT_ROWS = 5000;
/** Wall-clock budget per query before it is cancelled in the worker. */
export const QUERY_TIMEOUT_MS = 20_000;
/**
 * Ingestion ceiling: captures beyond this many flows are queryable only for
 * their first N rows (the UI says so explicitly — never a silent degrade).
 * Far above what the bounded-memory engine emits for realistic captures;
 * benchmarked at this scale in e2e/query-perf.spec.ts.
 */
export const QUERY_ROW_CEILING = 1_000_000;

export interface LoadedFlows {
  /** Rows actually ingested into the `flow` table. */
  loaded: number;
  /** True when the dataset exceeded {@link QUERY_ROW_CEILING} and was cut off. */
  capped: boolean;
}

export interface QueryResultColumn {
  name: string;
  /** Arrow type label as reported by DuckDB (e.g. "Utf8", "Uint64", "Timestamp<MICROSECOND>"). */
  type: string;
}

export interface QueryResult {
  columns: QueryResultColumn[];
  /** Row-major values; BigInt for 64-bit ints, epoch-ms number for timestamps. */
  rows: unknown[][];
  rowCount: number;
  /** True when the result was cut off at {@link MAX_RESULT_ROWS}. */
  truncated: boolean;
  /** True when the guard appended the default LIMIT (no top-level LIMIT given). */
  limitApplied: boolean;
  elapsedMs: number;
}

export class QueryEngine {
  private loadedCaptureKey: string | null = null;
  /** Serializes loadFlows/run — one in-flight operation per connection. */
  private queue: Promise<unknown> = Promise.resolve();

  private constructor(
    private readonly db: duckdb.AsyncDuckDB,
    private readonly conn: duckdb.AsyncDuckDBConnection,
  ) {}

  static async create(): Promise<QueryEngine> {
    const bundle = await duckdb.selectBundle({
      mvp: { mainModule: wasmMvp, mainWorker: workerMvp },
      eh: { mainModule: wasmEh, mainWorker: workerEh },
    });
    const worker = new Worker(bundle.mainWorker!);
    const db = new duckdb.AsyncDuckDB(
      new duckdb.ConsoleLogger(duckdb.LogLevel.WARNING),
      worker,
    );
    await db.instantiate(bundle.mainModule, bundle.pthreadWorker);
    const conn = await db.connect();
    // Before any user SQL: no filesystem/network table functions, then freeze
    // the configuration so guarded SQL cannot turn them back on.
    await conn.query("SET enable_external_access = false");
    await conn.query("SET lock_configuration = true");
    return new QueryEngine(db, conn);
  }

  /** Best-effort teardown: close the connection and terminate the worker. */
  async dispose(): Promise<void> {
    try {
      await this.conn.close();
    } catch {
      /* connection may already be gone (worker crash) */
    }
    try {
      await this.db.terminate();
    } catch {
      /* worker may already be dead */
    }
  }

  private enqueue<T>(op: () => Promise<T>): Promise<T> {
    const next = this.queue.then(op, op);
    this.queue = next.then(
      () => undefined,
      () => undefined,
    );
    return next;
  }

  /**
   * (Re)build the `flow` table from the capture's normalized rows (up to
   * {@link QUERY_ROW_CEILING}). No-op when `captureKey` matches the
   * already-loaded capture.
   */
  loadFlows(rows: FlowRow[], captureKey: string): Promise<LoadedFlows> {
    const capped = rows.length > QUERY_ROW_CEILING;
    const toLoad = capped ? rows.slice(0, QUERY_ROW_CEILING) : rows;
    return this.enqueue(async () => {
      if (this.loadedCaptureKey === captureKey) {
        return { loaded: toLoad.length, capped };
      }
      this.loadedCaptureKey = null;
      await this.conn.query("DROP TABLE IF EXISTS flow");
      await this.conn.query(`DROP TABLE IF EXISTS ${FLOW_INGEST_TABLE}`);
      await this.conn.query(FLOW_TABLE_DDL);
      await this.conn.insertArrowTable(buildFlowArrowTable(toLoad), {
        name: FLOW_INGEST_TABLE,
      });
      await this.conn.query(buildFlowInsertSql());
      await this.conn.query(`DROP TABLE ${FLOW_INGEST_TABLE}`);
      this.loadedCaptureKey = captureKey;
      return { loaded: toLoad.length, capped };
    });
  }

  /** Guard + execute one statement, streaming batches so caps cancel early. */
  run(inputSql: string): Promise<QueryResult> {
    const guarded = guardSql(inputSql);
    if (!guarded.ok) return Promise.reject(new Error(guarded.reason));

    return this.enqueue(async () => {
      const started = performance.now();
      let timedOut = false;
      const timer = setTimeout(() => {
        timedOut = true;
        void this.conn.cancelSent();
      }, QUERY_TIMEOUT_MS);

      try {
        const reader = await this.conn.send(guarded.sql);
        let columns: QueryResultColumn[] = [];
        let converters: ((v: unknown) => unknown)[] = [];
        const rows: unknown[][] = [];
        let truncated = false;

        try {
          for await (const batch of reader) {
            if (columns.length === 0) {
              columns = batch.schema.fields.map((f) => ({
                name: f.name,
                type: String(f.type),
              }));
              converters = batch.schema.fields.map((f) => makeValueConverter(f.type));
            }
            for (let i = 0; i < batch.numRows; i++) {
              if (rows.length >= MAX_RESULT_ROWS) {
                truncated = true;
                break;
              }
              const row = new Array<unknown>(converters.length);
              for (let j = 0; j < converters.length; j++) {
                row[j] = converters[j](batch.getChildAt(j)?.get(i));
              }
              rows.push(row);
            }
            if (truncated) {
              await this.conn.cancelSent();
              break;
            }
          }
        } catch (err) {
          // cancelSent aborts the stream mid-read; that is expected for the
          // timeout path (and harmless after truncation).
          if (!timedOut) throw err;
        }
        if (timedOut) {
          throw new Error(
            `Query cancelled after ${QUERY_TIMEOUT_MS / 1000}s — narrow it down (add filters or a LIMIT).`,
          );
        }
        if (columns.length === 0 && reader.schema) {
          columns = reader.schema.fields.map((f) => ({
            name: f.name,
            type: String(f.type),
          }));
        }
        return {
          columns,
          rows,
          rowCount: rows.length,
          truncated,
          limitApplied: guarded.limitApplied,
          elapsedMs: Math.round(performance.now() - started),
        };
      } finally {
        clearTimeout(timer);
      }
    });
  }
}

let enginePromise: Promise<QueryEngine> | null = null;

/**
 * Lazy singleton. The first call boots the wasm worker (one-time cost); a
 * failed boot resets so the next call can retry (e.g. after a flaky reload).
 */
export function getQueryEngine(): Promise<QueryEngine> {
  if (!enginePromise) {
    enginePromise = QueryEngine.create();
    enginePromise.catch(() => {
      enginePromise = null;
    });
  }
  return enginePromise;
}

/**
 * Tear down the singleton (terminating its worker) so the next
 * getQueryEngine() boots fresh. The user-facing recovery path for a failed
 * boot or a wedged engine — wired to the Query tab's Retry button.
 */
export async function resetQueryEngine(): Promise<void> {
  const previous = enginePromise;
  enginePromise = null;
  if (!previous) return;
  try {
    // A wedged boot (e.g. the wasm fetch died inside the worker) may never
    // settle — don't let recovery hang on it; the orphaned worker is abandoned.
    const engine = await Promise.race([
      previous,
      new Promise<null>((resolve) => setTimeout(() => resolve(null), 2000)),
    ]);
    if (engine) await engine.dispose();
  } catch {
    /* the boot itself failed — nothing to dispose */
  }
}
