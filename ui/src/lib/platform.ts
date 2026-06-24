import { invoke } from "@tauri-apps/api/core";
import { open, save } from "@tauri-apps/plugin-dialog";
import type { ActiveSource, AnalysisOutput, FlowRow, WireFlowPackets } from "../types";
import { loadFlows } from "./data";
import { isTauri } from "./tauri-detect";
export { isTauri } from "./tauri-detect";
import { exportCsvWasm, exportStixWasm, exportMispWasm, exportCefWasm, exportSigmaWasm, applyRulesWasm, renderReportWasm } from "./wasmEngine";
export type { RuleApplyResult } from "./wasmEngine";

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
 * Export the analysis as the engine's HTML triage report. On desktop (Tauri) the
 * `save_report` command renders it after prompting for a path; in the browser it is
 * rendered via WASM (`render_report`) and downloaded. Returns a small result so the
 * UI can show a transient hint.
 *
 * `aiSummary` is optional — when provided it is embedded in the report on both surfaces.
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

  // Browser: render the full HTML report via WASM (parity with the desktop save_report).
  try {
    const html = await renderReportWasm(JSON.stringify(summary), Math.floor(Date.now() / 1000), aiSummary);
    downloadText(html, `${captureBase(summary)}-report.html`, "text/html");
    return { ok: true, message: "Downloaded" };
  } catch (e) {
    return { ok: false, message: e instanceof Error ? e.message : "Report export failed" };
  }
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

export function downloadText(content: string, filename: string, mime: string): void {
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

export async function exportMisp(summary: AnalysisOutput): Promise<ExportResult> {
  const name = `${captureBase(summary)}-misp.json`;
  if (isTauri()) {
    const path = await save({ defaultPath: name, filters: [{ name: "MISP event", extensions: ["json"] }] });
    if (!path) return { ok: false, message: "" };
    try {
      await invoke("save_misp", { summary, path });
      return { ok: true, message: "MISP event saved" };
    } catch (e) {
      return { ok: false, message: `Save failed: ${e}` };
    }
  }
  try {
    downloadText(await exportMispWasm(JSON.stringify(summary), Math.floor(Date.now() / 1000)), name, "application/json");
    return { ok: true, message: "Downloaded" };
  } catch (e) {
    return { ok: false, message: `Export failed: ${e}` };
  }
}

export async function exportCef(summary: AnalysisOutput): Promise<ExportResult> {
  const name = `${captureBase(summary)}-cef.txt`;
  if (isTauri()) {
    const path = await save({ defaultPath: name, filters: [{ name: "CEF", extensions: ["txt", "cef"] }] });
    if (!path) return { ok: false, message: "" };
    try {
      await invoke("save_cef", { summary, path });
      return { ok: true, message: "CEF saved" };
    } catch (e) {
      return { ok: false, message: `Save failed: ${e}` };
    }
  }
  try {
    downloadText(await exportCefWasm(JSON.stringify(summary)), name, "text/plain");
    return { ok: true, message: "Downloaded" };
  } catch (e) {
    return { ok: false, message: `Export failed: ${e}` };
  }
}

export async function copyMisp(summary: AnalysisOutput): Promise<ExportResult> {
  try {
    const s = isTauri()
      ? await invoke<string>("export_misp", { summary })
      : await exportMispWasm(JSON.stringify(summary), Math.floor(Date.now() / 1000));
    return copyText(s);
  } catch (e) {
    return { ok: false, message: `Copy failed: ${e}` };
  }
}

export async function copyCef(summary: AnalysisOutput): Promise<ExportResult> {
  try {
    const s = isTauri()
      ? await invoke<string>("export_cef", { summary })
      : await exportCefWasm(JSON.stringify(summary));
    return copyText(s);
  } catch (e) {
    return { ok: false, message: `Copy failed: ${e}` };
  }
}

export async function exportSigma(summary: AnalysisOutput): Promise<ExportResult> {
  const name = `${captureBase(summary)}-sigma.yml`;
  if (isTauri()) {
    const path = await save({ defaultPath: name, filters: [{ name: "Sigma", extensions: ["yml", "yaml"] }] });
    if (!path) return { ok: false, message: "" };
    try {
      await invoke("save_sigma", { summary, path });
      return { ok: true, message: "Sigma rules saved" };
    } catch (e) {
      return { ok: false, message: `Save failed: ${e}` };
    }
  }
  try {
    downloadText(await exportSigmaWasm(JSON.stringify(summary)), name, "text/yaml");
    return { ok: true, message: "Downloaded" };
  } catch (e) {
    return { ok: false, message: `Export failed: ${e}` };
  }
}

export async function copySigma(summary: AnalysisOutput): Promise<ExportResult> {
  try {
    const s = isTauri()
      ? await invoke<string>("export_sigma", { summary })
      : await exportSigmaWasm(JSON.stringify(summary));
    return copyText(s);
  } catch (e) {
    return { ok: false, message: `Copy failed: ${e}` };
  }
}

// ── Rule application ─────────────────────────────────────────────────────────

import type { RuleApplyResult } from "./wasmEngine";

/**
 * Apply detection rules to a capture.
 * - Browser (bytes source): runs via WASM in-page, no upload.
 * - Desktop (path source): invokes the native `apply_rules_to` Tauri command.
 * - null source: throws — rules require raw pcap bytes.
 */
export async function applyRules(
  rulesText: string,
  output: AnalysisOutput,
  source: ActiveSource,
): Promise<RuleApplyResult> {
  if (!source) throw new Error("Packets are only available for captures analyzed from a pcap");
  if (source.kind === "bytes") return applyRulesWasm(source.bytes, rulesText, output);
  const { invoke: tauriInvoke } = await import("@tauri-apps/api/core");
  const json = await tauriInvoke<string>("apply_rules_to", {
    path: source.path,
    rulesText,
    outputJson: JSON.stringify(output),
  });
  return JSON.parse(json) as RuleApplyResult;
}
