import { describe, it, expect, vi, beforeEach } from "vitest";

const { invoke, save, isTauri, exportCsvWasm, exportStixWasm, exportMispWasm, exportCefWasm, exportSigmaWasm, applyRulesWasm, renderReportWasm } = vi.hoisted(() => ({
  invoke: vi.fn(),
  save: vi.fn(),
  isTauri: vi.fn(),
  exportCsvWasm: vi.fn(),
  exportStixWasm: vi.fn(),
  exportMispWasm: vi.fn(),
  exportCefWasm: vi.fn(),
  exportSigmaWasm: vi.fn(),
  applyRulesWasm: vi.fn(),
  renderReportWasm: vi.fn(),
}));

vi.mock("@tauri-apps/api/core", () => ({ invoke }));
vi.mock("@tauri-apps/plugin-dialog", () => ({ save, open: vi.fn() }));
vi.mock("./tauri-detect", () => ({ isTauri }));
vi.mock("./wasmEngine", () => ({ exportCsvWasm, exportStixWasm, exportMispWasm, exportCefWasm, exportSigmaWasm, applyRulesWasm, renderReportWasm }));
vi.mock("./data", () => ({ loadFlows: vi.fn() }));

import { exportCsv, exportStix, copyCsv, copyStix, exportMisp, copyMisp, exportCef, copyCef, exportSigma, copySigma, applyRules, exportReport } from "./platform";
import type { AnalysisOutput, ActiveSource } from "../types";

const summary = { source_path: "cap.pcap", summary: { findings: [] } } as unknown as AnalysisOutput;

beforeEach(() => {
  invoke.mockReset(); save.mockReset(); isTauri.mockReset();
  exportCsvWasm.mockReset(); exportStixWasm.mockReset();
  exportMispWasm.mockReset(); exportCefWasm.mockReset(); exportSigmaWasm.mockReset(); renderReportWasm.mockReset();
});

describe("platform structured export", () => {
  it("exportCsv on desktop opens a save dialog and invokes save_csv", async () => {
    isTauri.mockReturnValue(true);
    save.mockResolvedValue("/tmp/out.csv");
    const r = await exportCsv(summary);
    expect(save).toHaveBeenCalled();
    expect(invoke).toHaveBeenCalledWith("save_csv", { summary, path: "/tmp/out.csv" });
    expect(r.ok).toBe(true);
  });

  it("exportCsv in the browser generates via WASM and downloads", async () => {
    isTauri.mockReturnValue(false);
    exportCsvWasm.mockResolvedValue("kind,severity\nbeacon,high\n");
    vi.stubGlobal("URL", { createObjectURL: vi.fn(() => "blob:fake"), revokeObjectURL: vi.fn() });
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
    const r = await exportCsv(summary);
    expect(exportCsvWasm).toHaveBeenCalledWith(JSON.stringify(summary));
    expect(click).toHaveBeenCalled();
    expect(r.ok).toBe(true);
    click.mockRestore();
  });

  it("copyStix writes the bundle to the clipboard", async () => {
    isTauri.mockReturnValue(false);
    exportStixWasm.mockResolvedValue('{"type":"bundle"}');
    const writeText = vi.fn().mockResolvedValue(undefined);
    vi.stubGlobal("navigator", { clipboard: { writeText } });
    const r = await copyStix(summary);
    expect(writeText).toHaveBeenCalledWith('{"type":"bundle"}');
    expect(r.ok).toBe(true);
  });

  it("copyCsv on desktop invokes export_csv and writes to clipboard", async () => {
    isTauri.mockReturnValue(true);
    const csvString = "kind,severity\nbeacon,high\n";
    invoke.mockResolvedValue(csvString);
    const writeText = vi.fn().mockResolvedValue(undefined);
    vi.stubGlobal("navigator", { clipboard: { writeText } });
    const r = await copyCsv(summary);
    expect(invoke).toHaveBeenCalledWith("export_csv", { summary });
    expect(writeText).toHaveBeenCalledWith(csvString);
    expect(r.ok).toBe(true);
  });

  it("exportStix in the browser generates via WASM and downloads", async () => {
    isTauri.mockReturnValue(false);
    exportStixWasm.mockResolvedValue('{"type":"bundle"}');
    vi.stubGlobal("URL", { createObjectURL: vi.fn(() => "blob:fake"), revokeObjectURL: vi.fn() });
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
    const r = await exportStix(summary);
    expect(exportStixWasm).toHaveBeenCalledWith(
      JSON.stringify(summary),
      expect.any(Number),
    );
    expect(click).toHaveBeenCalled();
    expect(r.ok).toBe(true);
    click.mockRestore();
  });

  it("exportCsv on desktop returns ok:false when invoke throws", async () => {
    isTauri.mockReturnValue(true);
    save.mockResolvedValue("/tmp/x.csv");
    invoke.mockRejectedValue(new Error("disk full"));
    const r = await exportCsv(summary);
    expect(r.ok).toBe(false);
  });

  it("copyCsv returns ok:false when string-generation throws on desktop", async () => {
    isTauri.mockReturnValue(true);
    invoke.mockRejectedValue(new Error("boom"));
    const r = await copyCsv(summary);
    expect(r.ok).toBe(false);
  });

  it("exportCsv in the browser returns ok:false when WASM generation throws", async () => {
    isTauri.mockReturnValue(false);
    exportCsvWasm.mockRejectedValue(new Error("wasm boom"));
    const r = await exportCsv(summary);
    expect(r.ok).toBe(false);
  });

  // ── MISP ────────────────────────────────────────────────────────────────────

  it("exportMisp on desktop opens a save dialog and invokes save_misp", async () => {
    isTauri.mockReturnValue(true);
    save.mockResolvedValue("/tmp/out-misp.json");
    const r = await exportMisp(summary);
    expect(save).toHaveBeenCalled();
    expect(invoke).toHaveBeenCalledWith("save_misp", { summary, path: "/tmp/out-misp.json" });
    expect(r.ok).toBe(true);
  });

  it("exportMisp in the browser generates via WASM and downloads", async () => {
    isTauri.mockReturnValue(false);
    exportMispWasm.mockResolvedValue('{"Event":{}}');
    vi.stubGlobal("URL", { createObjectURL: vi.fn(() => "blob:fake"), revokeObjectURL: vi.fn() });
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
    const r = await exportMisp(summary);
    expect(exportMispWasm).toHaveBeenCalledWith(JSON.stringify(summary), expect.any(Number));
    expect(click).toHaveBeenCalled();
    expect(r.ok).toBe(true);
    click.mockRestore();
  });

  it("copyMisp writes the MISP event to the clipboard", async () => {
    isTauri.mockReturnValue(false);
    exportMispWasm.mockResolvedValue('{"Event":{}}');
    const writeText = vi.fn().mockResolvedValue(undefined);
    vi.stubGlobal("navigator", { clipboard: { writeText } });
    const r = await copyMisp(summary);
    expect(writeText).toHaveBeenCalledWith('{"Event":{}}');
    expect(r.ok).toBe(true);
  });

  it("exportMisp in the browser returns ok:false when WASM throws", async () => {
    isTauri.mockReturnValue(false);
    exportMispWasm.mockRejectedValue(new Error("misp boom"));
    const r = await exportMisp(summary);
    expect(r.ok).toBe(false);
  });

  // ── CEF ─────────────────────────────────────────────────────────────────────

  it("exportCef on desktop opens a save dialog and invokes save_cef", async () => {
    isTauri.mockReturnValue(true);
    save.mockResolvedValue("/tmp/out.cef.txt");
    const r = await exportCef(summary);
    expect(save).toHaveBeenCalled();
    expect(invoke).toHaveBeenCalledWith("save_cef", { summary, path: "/tmp/out.cef.txt" });
    expect(r.ok).toBe(true);
  });

  it("exportCef in the browser generates via WASM and downloads", async () => {
    isTauri.mockReturnValue(false);
    exportCefWasm.mockResolvedValue("CEF:0|PacketPilot|...");
    vi.stubGlobal("URL", { createObjectURL: vi.fn(() => "blob:fake"), revokeObjectURL: vi.fn() });
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
    const r = await exportCef(summary);
    expect(exportCefWasm).toHaveBeenCalledWith(JSON.stringify(summary));
    expect(click).toHaveBeenCalled();
    expect(r.ok).toBe(true);
    click.mockRestore();
  });

  it("copyCef writes the CEF string to the clipboard", async () => {
    isTauri.mockReturnValue(false);
    exportCefWasm.mockResolvedValue("CEF:0|PacketPilot|...");
    const writeText = vi.fn().mockResolvedValue(undefined);
    vi.stubGlobal("navigator", { clipboard: { writeText } });
    const r = await copyCef(summary);
    expect(writeText).toHaveBeenCalledWith("CEF:0|PacketPilot|...");
    expect(r.ok).toBe(true);
  });

  it("exportCef in the browser returns ok:false when WASM throws", async () => {
    isTauri.mockReturnValue(false);
    exportCefWasm.mockRejectedValue(new Error("cef boom"));
    const r = await exportCef(summary);
    expect(r.ok).toBe(false);
  });

  it("exportSigma on desktop opens a save dialog and invokes save_sigma", async () => {
    isTauri.mockReturnValue(true);
    save.mockResolvedValue("/tmp/out-sigma.yml");
    const r = await exportSigma(summary);
    expect(save).toHaveBeenCalled();
    expect(invoke).toHaveBeenCalledWith("save_sigma", { summary, path: "/tmp/out-sigma.yml" });
    expect(r.ok).toBe(true);
  });

  it("exportSigma in the browser generates via WASM and downloads", async () => {
    isTauri.mockReturnValue(false);
    exportSigmaWasm.mockResolvedValue("title: PacketPilot: ...");
    vi.stubGlobal("URL", { createObjectURL: vi.fn(() => "blob:fake"), revokeObjectURL: vi.fn() });
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
    const r = await exportSigma(summary);
    expect(exportSigmaWasm).toHaveBeenCalledWith(JSON.stringify(summary));
    expect(click).toHaveBeenCalled();
    expect(r.ok).toBe(true);
    click.mockRestore();
  });

  it("copySigma writes the Sigma rules to the clipboard", async () => {
    isTauri.mockReturnValue(false);
    exportSigmaWasm.mockResolvedValue("title: PacketPilot: ...");
    const writeText = vi.fn().mockResolvedValue(undefined);
    vi.stubGlobal("navigator", { clipboard: { writeText } });
    const r = await copySigma(summary);
    expect(writeText).toHaveBeenCalledWith("title: PacketPilot: ...");
    expect(r.ok).toBe(true);
  });

  // ── exportReport (browser) ───────────────────────────────────────────────────

  it("exportReport (browser) downloads the rendered HTML report", async () => {
    isTauri.mockReturnValue(false);
    renderReportWasm.mockResolvedValue("<!doctype html><html>…report…</html>");
    vi.stubGlobal("URL", { createObjectURL: vi.fn(() => "blob:fake"), revokeObjectURL: vi.fn() });
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
    const r = await exportReport(summary);
    expect(renderReportWasm).toHaveBeenCalledWith(
      JSON.stringify(summary),
      expect.any(Number),
      undefined,
    );
    expect(click).toHaveBeenCalled();
    expect(r).toEqual({ ok: true, message: "Downloaded" });
    click.mockRestore();
  });

  it("exportReport (browser) returns ok:false when the render rejects", async () => {
    isTauri.mockReturnValue(false);
    renderReportWasm.mockRejectedValue(new Error("boom"));
    const r = await exportReport(summary);
    expect(r.ok).toBe(false);
  });
});

// ── applyRules platform seam ──────────────────────────────────────────────────

const rulesText = 'alert tcp any any -> any any (msg:"test"; sid:1;)';
const fakeResult = { output: summary, loaded: 1, skipped: 0, matches: 1 };

describe("applyRules", () => {
  beforeEach(() => {
    applyRulesWasm.mockReset();
    invoke.mockReset();
    isTauri.mockReset();
  });

  it("bytes source routes to applyRulesWasm and returns RuleApplyResult", async () => {
    const bytes = new ArrayBuffer(8);
    const source: ActiveSource = { kind: "bytes", bytes };
    applyRulesWasm.mockResolvedValue(fakeResult);
    const result = await applyRules(rulesText, summary, source);
    expect(applyRulesWasm).toHaveBeenCalledWith(bytes, rulesText, summary);
    expect(result).toEqual(fakeResult);
  });

  it("path source with IS_TAURI invokes apply_rules_to with camelCase args and parses JSON", async () => {
    isTauri.mockReturnValue(true);
    const source: ActiveSource = { kind: "path", path: "/caps/test.pcap" };
    invoke.mockResolvedValue(JSON.stringify(fakeResult));
    const result = await applyRules(rulesText, summary, source);
    expect(invoke).toHaveBeenCalledWith("apply_rules_to", {
      path: "/caps/test.pcap",
      rulesText,
      outputJson: JSON.stringify(summary),
    });
    expect(result).toEqual(fakeResult);
  });

  it("null source rejects with source-unavailable message", async () => {
    await expect(applyRules(rulesText, summary, null)).rejects.toThrow(
      "Packets are only available for captures analyzed from a pcap",
    );
  });
});
