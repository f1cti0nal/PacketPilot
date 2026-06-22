import { describe, it, expect, vi, beforeEach } from "vitest";

const { invoke, save, isTauri, exportCsvWasm, exportStixWasm } = vi.hoisted(() => ({
  invoke: vi.fn(),
  save: vi.fn(),
  isTauri: vi.fn(),
  exportCsvWasm: vi.fn(),
  exportStixWasm: vi.fn(),
}));

vi.mock("@tauri-apps/api/core", () => ({ invoke }));
vi.mock("@tauri-apps/plugin-dialog", () => ({ save, open: vi.fn() }));
vi.mock("./tauri-detect", () => ({ isTauri }));
vi.mock("./wasmEngine", () => ({ exportCsvWasm, exportStixWasm }));
vi.mock("./data", () => ({ loadFlows: vi.fn() }));

import { exportCsv, copyStix } from "./platform";
import type { AnalysisOutput } from "../types";

const summary = { source_path: "cap.pcap", summary: { findings: [] } } as unknown as AnalysisOutput;

beforeEach(() => {
  invoke.mockReset(); save.mockReset(); isTauri.mockReset();
  exportCsvWasm.mockReset(); exportStixWasm.mockReset();
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
});
