import { invoke } from "@tauri-apps/api/core";
import { open, save } from "@tauri-apps/plugin-dialog";
import type { AnalysisOutput, FlowRow, WireFlowPackets } from "../types";
import { loadFlows } from "./data";
import { isTauri } from "./tauri-detect";
export { isTauri } from "./tauri-detect";
import { exportCsvWasm, exportStixWasm } from "./wasmEngine";

interface AnalyzeDto {
  summary: AnalysisOutput;
  flows_b64: string;
}

function base64ToArrayBuffer(b64: string): ArrayBuffer {
  const bin = atob(b64);
  const len = bin.length;
  const buf = new ArrayBuffer(len);
  const bytes = new Uint8Array(buf);
  for (let i = 0; i < len; i++) bytes[i] = bin.charCodeAt(i);
  return buf;
}

export async function extractPacketsViaTauri(
  path: string,
  query: object,
): Promise<WireFlowPackets> {
  return invoke<WireFlowPackets>("extract_flow_packets", { path, query });
}

export async function analyzeViaTauri(
  path: string,
): Promise<{ summary: AnalysisOutput; rows: FlowRow[] }> {
  const dto = await invoke<AnalyzeDto>("analyze_capture", { path });
  const buf = base64ToArrayBuffer(dto.flows_b64);
  const rows = await loadFlows(buf);
  return { summary: dto.summary, rows };
}

export async function openCaptureDialog(): Promise<string | null> {
  const selected = await open({
    multiple: false,
    directory: false,
    filters: [{ name: "Captures", extensions: ["pcap", "pcapng", "cap", "gz"] }],
  });
  return typeof selected === "string" ? selected : null;
}

/** Result of an export attempt; `ok=false` with no message means the user cancelled. */
export interface ExportResult {
  ok: boolean;
  message: string;
}

/**
 * Export the analysis. On desktop (Tauri) renders the engine's HTML report via the
 * `save_report` command after prompting for a path. In the browser, downloads the
 * summary as pretty JSON. Returns a small result so the UI can show a transient hint.
 *
 * `aiSummary` is optional — when provided it is embedded in the HTML report (desktop only).
 */
export async function exportReport(
  summary: AnalysisOutput,
  aiSummary?: string,
): Promise<ExportResult> {
  if (isTauri()) {
    const path = await save({
      defaultPath: "packetpilot-report.html",
      filters: [{ name: "HTML report", extensions: ["html"] }],
    });
    if (!path) return { ok: false, message: "" }; // cancelled
    await invoke("save_report", { summary, path, aiSummary: aiSummary ?? null });
    return { ok: true, message: "Report saved" };
  }

  // Browser fallback: download the summary as pretty JSON via a temporary anchor.
  const json = JSON.stringify(summary, null, 2);
  const blob = new Blob([json], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  try {
    const a = document.createElement("a");
    a.href = url;
    a.download = "packetpilot-summary.json";
    document.body.appendChild(a);
    a.click();
    a.remove();
  } finally {
    URL.revokeObjectURL(url);
  }
  return { ok: true, message: "Downloaded" };
}

// ── Structured export: CSV / STIX ────────────────────────────────────────────

/** Basename of the capture source (no extension), used for export filenames. */
function captureBase(summary: AnalysisOutput): string {
  const p = summary.source_path || "";
  return p.split(/[\\/]/).pop()?.replace(/\.[^.]+$/, "") || "packetpilot";
}

export function downloadBinary(bytes: Uint8Array, filename: string, mime: string): void {
  // Cast needed because TypeScript's Blob constructor expects Uint8Array<ArrayBuffer>
  // but wasm-bindgen returns Uint8Array<ArrayBufferLike>; they are equivalent at runtime.
  const blob = new Blob([bytes as Uint8Array<ArrayBuffer>], { type: mime });
  const url = URL.createObjectURL(blob);
  try {
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
  } finally {
    URL.revokeObjectURL(url);
  }
}

function downloadText(content: string, filename: string, mime: string): void {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  try {
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
  } finally {
    URL.revokeObjectURL(url);
  }
}

export async function exportCsv(summary: AnalysisOutput): Promise<ExportResult> {
  const name = `${captureBase(summary)}-findings.csv`;
  if (isTauri()) {
    const path = await save({ defaultPath: name, filters: [{ name: "CSV", extensions: ["csv"] }] });
    if (!path) return { ok: false, message: "" };
    try {
      await invoke("save_csv", { summary, path });
      return { ok: true, message: "CSV saved" };
    } catch (e) {
      return { ok: false, message: `Save failed: ${e}` };
    }
  }
  try {
    const csv = await exportCsvWasm(JSON.stringify(summary));
    downloadText(csv, name, "text/csv");
    return { ok: true, message: "Downloaded" };
  } catch (e) {
    return { ok: false, message: `Export failed: ${e}` };
  }
}

export async function exportStix(summary: AnalysisOutput): Promise<ExportResult> {
  const name = `${captureBase(summary)}-stix.json`;
  if (isTauri()) {
    const path = await save({ defaultPath: name, filters: [{ name: "STIX bundle", extensions: ["json"] }] });
    if (!path) return { ok: false, message: "" };
    try {
      await invoke("save_stix", { summary, path });
      return { ok: true, message: "STIX bundle saved" };
    } catch (e) {
      return { ok: false, message: `Save failed: ${e}` };
    }
  }
  try {
    const stix = await exportStixWasm(JSON.stringify(summary), Math.floor(Date.now() / 1000));
    downloadText(stix, name, "application/json");
    return { ok: true, message: "Downloaded" };
  } catch (e) {
    return { ok: false, message: `Export failed: ${e}` };
  }
}

async function copyText(text: string): Promise<ExportResult> {
  try {
    await navigator.clipboard.writeText(text);
    return { ok: true, message: "Copied to clipboard" };
  } catch (e) {
    return { ok: false, message: `Copy failed: ${e}` };
  }
}

export async function copyCsv(summary: AnalysisOutput): Promise<ExportResult> {
  try {
    const csv = isTauri()
      ? await invoke<string>("export_csv", { summary })
      : await exportCsvWasm(JSON.stringify(summary));
    return copyText(csv);
  } catch (e) {
    return { ok: false, message: `Copy failed: ${e}` };
  }
}

export async function copyStix(summary: AnalysisOutput): Promise<ExportResult> {
  try {
    const stix = isTauri()
      ? await invoke<string>("export_stix", { summary })
      : await exportStixWasm(JSON.stringify(summary), Math.floor(Date.now() / 1000));
    return copyText(stix);
  } catch (e) {
    return { ok: false, message: `Copy failed: ${e}` };
  }
}
