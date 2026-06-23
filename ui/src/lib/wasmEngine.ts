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
  if (!initPromise) initPromise = initWasm();
  return initPromise;
}

interface WasmAnalyzeResult {
  summary: AnalysisOutput;
  flows: WasmFlow[];
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
  await ensureWasm();
  // wasm returns a JSON string (large i64 ns timestamps survive as JSON integers, parsed to
  // f64 here — identical to how the native summary.json is consumed).
  const json = wasmAnalyze(new Uint8Array(bytes), name) as string;
  const result = JSON.parse(json) as WasmAnalyzeResult;
  const summary = result.summary;
  if (!summary.source_sha256) {
    const hex = await sha256Hex(bytes);
    if (hex) summary.source_sha256 = hex;
  }
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

/**
 * Render the full HTML report via WASM (browser path).
 * `generatedUnixSecs` is the report creation timestamp.
 * wasm-bindgen maps Rust `i64` → JS `bigint`, so we wrap with BigInt().
 */
export async function renderReportWasm(outputJson: string, generatedUnixSecs: number, aiSummary?: string): Promise<string> {
  await ensureWasm();
  return wasmRenderReport(outputJson, BigInt(generatedUnixSecs), aiSummary ?? undefined) as string;
}
