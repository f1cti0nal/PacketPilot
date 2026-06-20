// In-browser capture analysis via the WebAssembly build of the Rust engine (`ppcap-wasm`).
//
// This is what lets the browser build accept a raw .pcap/.pcapng — the same streaming
// pipeline the desktop app runs natively, compiled to wasm, with the capture bytes never
// leaving the page (no upload, no server). The .wasm is lazily instantiated on first use.

import type { AnalysisOutput, FlowRow, WasmFlow } from "../types";
import { flowRowFromWasm } from "./data";
import { sha256Hex } from "./recent";
import initWasm, { analyze as wasmAnalyze } from "../wasm/ppcap_wasm.js";

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
