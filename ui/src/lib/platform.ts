import { invoke } from "@tauri-apps/api/core";
import { open, save } from "@tauri-apps/plugin-dialog";
import type { AnalysisOutput, FlowRow } from "../types";
import { loadFlows } from "./data";

/** True only inside the Tauri webview (the injected internals object). */
export function isTauri(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

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
    filters: [{ name: "Captures", extensions: ["pcap", "pcapng", "cap"] }],
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
 */
export async function exportReport(
  summary: AnalysisOutput,
): Promise<ExportResult> {
  if (isTauri()) {
    const path = await save({
      defaultPath: "packetpilot-report.html",
      filters: [{ name: "HTML report", extensions: ["html"] }],
    });
    if (!path) return { ok: false, message: "" }; // cancelled
    await invoke("save_report", { summary, path });
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
