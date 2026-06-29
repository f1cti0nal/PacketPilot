// In-browser capture analysis via the WebAssembly build of the Rust engine (`ppcap-wasm`).
//
// This is what lets the browser build accept a raw .pcap/.pcapng — the same streaming
// pipeline the desktop app runs natively, compiled to wasm, with the capture bytes never
// leaving the page (no upload, no server). The .wasm is lazily instantiated on first use.

import type { AnalysisOutput, FlowRow, ReputationVerdict, WasmFlow, WireFlowPackets } from "../types";
import { flowRowFromWasm } from "./data";
import { sha256Hex } from "./recent";
import initWasm, {
  analyze as wasmAnalyze,
  extract_packets as wasmExtractPackets,
  apply_reputation as wasmApplyReputation,
  apply_domain_reputation as wasmApplyDomainReputation,
  apply_rules as wasmApplyRules,
  export_csv as wasmExportCsv,
  export_stix as wasmExportStix,
  export_misp as wasmExportMisp,
  export_cef as wasmExportCef,
  export_sigma as wasmExportSigma,
  carve_pcap as wasmCarvePcap,
  render_report as wasmRenderReport,
} from "../wasm/ppcap_wasm.js";

export async function extractPacketsViaWasm(bytes: ArrayBuffer, query: object): Promise<WireFlowPackets> {
  await ensureWasm();
  const json = wasmExtractPackets(new Uint8Array(bytes), JSON.stringify(query), "{}") as string;
  return JSON.parse(json) as WireFlowPackets;
}

/** Capture extensions the in-browser engine can analyze. */
export const CAPTURE_EXTENSIONS = ["pcap", "pcapng", "cap"] as const;

/** True if `name` looks like a raw capture (vs. an already-analyzed summary/parquet import). */
export function isCaptureFile(name: string): boolean {
  const lower = name.toLowerCase();
  return CAPTURE_EXTENSIONS.some((ext) => lower.endsWith(`.${ext}`));
}

let initPromise: Promise<unknown> | null = null;
function ensureWasm(): Promise<unknown> {
  // Reset the cache on failure so a transient init error (.wasm 404, CDN hiccup, OOM)
  // doesn't permanently wedge analysis for the session — a retry re-initializes.
  if (!initPromise) {
    initPromise = initWasm().catch((e) => {
      initPromise = null;
      throw e;
    });
  }
  return initPromise;
}

interface WasmAnalyzeResult {
  summary: AnalysisOutput;
  flows: WasmFlow[];
}

// --- Off-main-thread analyze (Web Worker) ------------------------------------------------------
// The WASM `analyze` pass can run for seconds on a large capture; on the main thread that freezes
// the whole UI. We run it in a Web Worker instead and TRANSFER the bytes in (zero-copy). A one-time
// ping/ready handshake confirms the worker environment is healthy before we commit to transferring;
// if it's unavailable (jsdom tests, CSP, no-WASM-in-worker), `analyzeInWorker` returns null with the
// bytes UNtouched so the caller transparently falls back to main-thread analysis.
let analyzeWorker: Worker | null = null;
let workerReady: Promise<boolean> | null = null;
let workerMsgId = 0;

function getAnalyzeWorker(): Promise<boolean> {
  if (workerReady) return workerReady;
  workerReady = new Promise<boolean>((resolve) => {
    let w: Worker;
    try {
      w = new Worker(new URL("./analyzeWorker.ts", import.meta.url), { type: "module" });
    } catch {
      resolve(false);
      return;
    }
    let settled = false;
    const done = (ok: boolean) => {
      if (settled) return;
      settled = true;
      w.removeEventListener("message", onMsg);
      w.removeEventListener("error", onErr);
      if (ok) {
        analyzeWorker = w;
        resolve(true);
      } else {
        try { w.terminate(); } catch { /* noop */ }
        resolve(false);
      }
    };
    const onMsg = (e: MessageEvent) => {
      if (e.data?.type === "ready") done(true);
      else if (e.data?.type === "init-failed") done(false);
    };
    const onErr = () => done(false);
    w.addEventListener("message", onMsg);
    w.addEventListener("error", onErr);
    w.postMessage({ type: "ping" });
    setTimeout(() => done(false), 10_000); // worker env wedged → fall back to main thread
  });
  return workerReady;
}

interface WorkerAnalyzeResult { json: string; sha256: string | null }

/**
 * Run analyze in the worker. Returns null ONLY when the worker is unavailable (the bytes were never
 * transferred, so the caller can still read them for the main-thread fallback). Once the bytes are
 * transferred, a genuine analysis failure REJECTS (not null) — there's no falling back to neutered
 * bytes; the error surfaces to the load dialog exactly as a main-thread failure would.
 */
async function analyzeInWorker(bytes: ArrayBuffer, name: string): Promise<WorkerAnalyzeResult | null> {
  const ok = await getAnalyzeWorker();
  if (!ok || !analyzeWorker) return null;
  const worker = analyzeWorker;
  return await new Promise<WorkerAnalyzeResult>((resolve, reject) => {
    const id = ++workerMsgId;
    const onMsg = (e: MessageEvent) => {
      if (e.data?.id !== id) return;
      worker.removeEventListener("message", onMsg);
      if (e.data.ok) resolve({ json: e.data.json, sha256: e.data.sha256 ?? null });
      else reject(new Error(e.data.error || "worker analyze failed"));
    };
    worker.addEventListener("message", onMsg);
    worker.postMessage({ type: "analyze", id, bytes, name }, [bytes]); // transfer — zero-copy
  });
}

/**
 * Analyze a raw capture in the browser. Returns the summary plus normalized flow rows,
 * ready to drop into the same App state the desktop/native and sample paths use.
 *
 * The wasm pass doesn't hash the source (that lives behind the native `--hash` flag), so we
 * fill in `source_sha256` here via WebCrypto — cheap, and it gives the capture a stable
 * identity for the Recent list.
 */
export async function analyzeViaWasm(
  bytes: ArrayBuffer,
  name: string,
): Promise<{ summary: AnalysisOutput; rows: FlowRow[] }> {
  // wasm returns a JSON string (large i64 ns timestamps survive as JSON integers, parsed to f64
  // here — identical to how the native summary.json is consumed). Prefer the worker (off-main-
  // thread → no UI freeze); fall back to the main thread when the worker env is unavailable.
  let json: string;
  let sha256: string | null;
  const viaWorker = await analyzeInWorker(bytes, name);
  if (viaWorker) {
    json = viaWorker.json;
    sha256 = viaWorker.sha256;
  } else {
    await ensureWasm();
    json = wasmAnalyze(new Uint8Array(bytes), name) as string;
    sha256 = await sha256Hex(bytes);
  }
  const result = JSON.parse(json) as WasmAnalyzeResult;
  const summary = result.summary;
  if (!summary.source_sha256 && sha256) summary.source_sha256 = sha256;
  const rows = (result.flows ?? []).map(flowRowFromWasm);
  return { summary, rows };
}

/**
 * Apply reputation verdicts to an existing analysis output via WASM.
 * Single-sourced scoring: the same engine logic runs in-browser as on the desktop.
 */
export async function applyReputationWasm(
  outputJson: string,
  verdicts: Record<string, ReputationVerdict[]>,
): Promise<AnalysisOutput> {
  await ensureWasm();
  const updated = wasmApplyReputation(outputJson, JSON.stringify(verdicts)) as string;
  return JSON.parse(updated) as AnalysisOutput;
}

/**
 * Apply domain reputation verdicts to an existing analysis output via WASM.
 * Single-sourced scoring: the same engine logic runs in-browser as on the desktop.
 */
export async function applyDomainReputationWasm(
  outputJson: string,
  verdicts: Record<string, ReputationVerdict[]>,
): Promise<AnalysisOutput> {
  await ensureWasm();
  const updated = wasmApplyDomainReputation(outputJson, JSON.stringify(verdicts)) as string;
  return JSON.parse(updated) as AnalysisOutput;
}

/** Result of applying detection rules to a capture. `output` is the full updated AnalysisOutput. */
export interface RuleApplyResult {
  output: AnalysisOutput;
  loaded: number;
  skipped: number;
  matches: number;
}

/**
 * Apply Suricata/custom detection rules to an existing analysis output via WASM.
 * Single-sourced rule evaluation: same engine logic in-browser as on the desktop.
 */
export async function applyRulesWasm(
  bytes: ArrayBuffer,
  rulesText: string,
  output: AnalysisOutput,
): Promise<RuleApplyResult> {
  await ensureWasm();
  const json = wasmApplyRules(new Uint8Array(bytes), rulesText, JSON.stringify(output)) as string;
  return JSON.parse(json) as RuleApplyResult;
}

/** Carve a sub-pcap in the browser. Returns the raw pcap bytes for the matching frames. */
export async function carvePcapViaWasm(bytes: ArrayBuffer, query: object): Promise<Uint8Array> {
  await ensureWasm();
  return wasmCarvePcap(new Uint8Array(bytes), JSON.stringify(query)) as Uint8Array;
}

/** Export findings as CSV via WASM (browser path). */
export async function exportCsvWasm(outputJson: string): Promise<string> {
  await ensureWasm();
  return wasmExportCsv(outputJson);
}

/**
 * Export findings as a STIX bundle via WASM (browser path).
 * `generatedUnixSecs` is the bundle creation timestamp.
 * wasm-bindgen maps Rust `i64` → JS `bigint`, so we wrap with BigInt().
 */
export async function exportStixWasm(outputJson: string, generatedUnixSecs: number): Promise<string> {
  await ensureWasm();
  return wasmExportStix(outputJson, BigInt(generatedUnixSecs));
}

/**
 * Export findings as a MISP event via WASM (browser path).
 * `generatedUnixSecs` is the event creation timestamp.
 * wasm-bindgen maps Rust `i64` → JS `bigint`, so we wrap with BigInt().
 */
export async function exportMispWasm(outputJson: string, generatedUnixSecs: number): Promise<string> {
  await ensureWasm();
  return wasmExportMisp(outputJson, BigInt(generatedUnixSecs));
}

/** Export findings as CEF (Common Event Format) via WASM (browser path). */
export async function exportCefWasm(outputJson: string): Promise<string> {
  await ensureWasm();
  return wasmExportCef(outputJson);
}

/** Export findings as Sigma detection rules (multi-document YAML) via WASM (browser path). */
export async function exportSigmaWasm(outputJson: string): Promise<string> {
  await ensureWasm();
  return wasmExportSigma(outputJson);
}

/**
 * Render the full HTML report via WASM (browser path).
 * `generatedUnixSecs` is the report creation timestamp.
 * wasm-bindgen maps Rust `i64` → JS `bigint`, so we wrap with BigInt().
 */
export async function renderReportWasm(outputJson: string, generatedUnixSecs: number, aiSummary?: string): Promise<string> {
  await ensureWasm();
  return wasmRenderReport(outputJson, BigInt(generatedUnixSecs), aiSummary ?? undefined) as string;
}
