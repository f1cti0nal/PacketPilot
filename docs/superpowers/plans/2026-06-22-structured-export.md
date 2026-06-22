# Structured Export (STIX 2.1 / CSV) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Expose the engine's existing pure `findings_csv` + `stix_bundle` to the UI on both surfaces (desktop save + browser download/copy) as STIX 2.1 / CSV artifacts.

**Architecture:** Engine-seam plumbing + UI, no new `ppcap-core` analytics. Two WASM exports + four Tauri commands wrap the existing pure `ppcap_core::export::{findings_csv, stix_bundle}`; a `platform.ts` layer mirrors `exportReport`; an Export dropdown menu surfaces the formats. WASM rebuild required.

**Tech Stack:** Rust (`ppcap-wasm`, `src-tauri`) for the seam; React 18 + TS + Tailwind for the UI; Vitest + RTL.

## Global Constraints

- **No change to `ppcap-core`** — call the existing pure fns `ppcap_core::export::findings_csv(&out)` and `ppcap_core::export::stix_bundle(&out, generated_unix_secs)` (the `export` module is `pub mod`).
- **WASM rebuild required:** after editing `ppcap-wasm`, run `cd ui && npm run build:wasm` (regenerates the gitignored `ui/src/wasm/`). The new exports must appear in `ui/src/wasm/ppcap_wasm.js`. CI's `ui` job runs `build:wasm` before tsc/vite.
- **Both surfaces emit the identical artifact** (pure engine fns); the browser must NOT fall back to a different format.
- **STIX `generated_unix_secs`:** `Math.floor(Date.now()/1000)` (browser) / `SystemTime::now()` Unix secs (desktop, as `save_report` does). CSV needs no time.
- **No new runtime dependencies.** Export actions gated on `canExport = summary.status === "ready" && !!summary.data`. Match cockpit styling.
- **`npm run test:coverage` gate stays green** (80/70). Verify under the locked toolchain (`npm ci` → `npm run build:wasm` → `npm run build` → `npm run test:coverage`; CI uses vitest 1.6.1) before completion.
- **TOOLCHAIN:** node/npx at `/c/Program Files/nodejs/`; cargo at `/c/Users/ravid/.cargo/bin`. Do NOT run `npm install`. Stage specific files (never `git add -A`).

---

### Task 1: WASM exports — `export_csv` / `export_stix`

**Files:**
- Modify: `engine/crates/ppcap-wasm/src/lib.rs` (add two exports after `apply_reputation`, ~line 173)
- Test: `ui/src/lib/wasmExport.test.ts` (create — loads the rebuilt wasm)

**Interfaces:**
- Produces (WASM): `export_csv(output_json: &str) -> Result<String, JsValue>`; `export_stix(output_json: &str, generated_unix_secs: i64) -> Result<String, JsValue>`. After `build:wasm` these are importable from `ui/src/wasm/ppcap_wasm.js`.

- [ ] **Step 1: Implement the Rust exports** — in `engine/crates/ppcap-wasm/src/lib.rs`, after the `apply_reputation` fn:

```rust
/// Export the analysis findings as RFC 4180 CSV. `output_json` is the `AnalysisOutput` from `analyze`.
#[wasm_bindgen]
pub fn export_csv(output_json: &str) -> Result<String, JsValue> {
    let out: ppcap_core::AnalysisOutput =
        serde_json::from_str(output_json).map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(ppcap_core::export::findings_csv(&out))
}

/// Export the analysis findings as a STIX 2.1 bundle stamped with `generated_unix_secs`.
#[wasm_bindgen]
pub fn export_stix(output_json: &str, generated_unix_secs: i64) -> Result<String, JsValue> {
    let out: ppcap_core::AnalysisOutput =
        serde_json::from_str(output_json).map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(ppcap_core::export::stix_bundle(&out, generated_unix_secs))
}
```

- [ ] **Step 2: Rebuild the wasm** — `cd ui && export PATH="/c/Program Files/nodejs:/c/Users/ravid/.cargo/bin:$PATH" && npm run build:wasm`. Expected: builds clean. Confirm the exports landed: `grep -E "export_csv|export_stix" src/wasm/ppcap_wasm.js` → both present.

- [ ] **Step 3: Write the round-trip test** — `ui/src/lib/wasmExport.test.ts` (mirror the synchronous wasm-load used by `ui/src/lib/reputation/parity.test.ts`):

```ts
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { initSync, export_csv, export_stix } from "../wasm/ppcap_wasm.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const wasmBytes = readFileSync(resolve(__dirname, "../wasm/ppcap_wasm_bg.wasm"));
initSync({ module: wasmBytes });

// A minimal but serde-valid AnalysisOutput with one finding.
const output = {
  schema_version: 1, engine_version: "test", source_path: "cap.pcap",
  source_sha256: "", source_bytes: 0, link_type: "EN10MB",
  summary: {
    findings: [{
      kind: "beacon", severity: "high", score: 88, title: "beacon to 2.2.2.2",
      src_ip: "10.0.0.5", dst_ip: "2.2.2.2", dst_port: 443,
      attack: ["T1071"], evidence: ["c2: 60s period"],
      interval_ns: null, jitter_cv: null, contacts: null,
    }],
  },
};
const json = JSON.stringify(output);

describe("wasm export round-trip", () => {
  it("export_csv emits the header + a finding row", () => {
    const csv = export_csv(json) as string;
    expect(csv.split("\n")[0]).toContain("kind,severity,score");
    expect(csv).toContain("beacon");
  });

  it("export_stix emits a STIX 2.1 bundle", () => {
    const stix = export_stix(json, 1_700_000_000) as string;
    const obj = JSON.parse(stix);
    expect(obj.type).toBe("bundle");
    expect(stix).toContain("2.1");
  });
});
```

> NOTE: if `export_csv(json)` throws a JsValue parse error, the minimal `output` is missing a serde-required `Summary`/`AnalysisOutput` field — add the field the error names (or replace `output` with `JSON.stringify((await import("../test/<the makeOutput helper>")).makeOutput())` after injecting a `findings` entry). The goal is a parseable `AnalysisOutput` with ≥1 finding.

- [ ] **Step 4: Run the test** — `cd ui && npx vitest run src/lib/wasmExport.test.ts` → 2 PASS. (`export PATH="/c/Program Files/nodejs:$PATH"` if npx not found.)

- [ ] **Step 5: Commit** — stage the Rust source + the test (NOT the gitignored `src/wasm/`):

```bash
git add engine/crates/ppcap-wasm/src/lib.rs ui/src/lib/wasmExport.test.ts
git commit -m "feat(wasm): export_csv + export_stix bindings for structured export"
```

---

### Task 2: Tauri commands — `save_csv` / `save_stix` / `export_csv` / `export_stix`

**Files:**
- Modify: `ui/src-tauri/src/lib.rs` (4 commands + register in `generate_handler!`)

**Interfaces:**
- Produces (Tauri): `save_csv(summary, path)` / `save_stix(summary, path)` (native file write); `export_csv(summary) -> String` / `export_stix(summary) -> String` (return the string for clipboard). `save_stix`/`export_stix` compute `now` internally.

- [ ] **Step 1: Add the four commands** — in `ui/src-tauri/src/lib.rs`, after `save_report`:

```rust
fn now_unix_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Write the findings CSV for `summary` to `path`.
#[tauri::command]
fn save_csv(summary: AnalysisOutput, path: String) -> Result<(), String> {
    let csv = ppcap_core::export::findings_csv(&summary);
    std::fs::write(&path, csv).map_err(|e| format!("write csv: {e}"))
}

/// Write the STIX 2.1 bundle for `summary` to `path`.
#[tauri::command]
fn save_stix(summary: AnalysisOutput, path: String) -> Result<(), String> {
    let stix = ppcap_core::export::stix_bundle(&summary, now_unix_secs());
    std::fs::write(&path, stix).map_err(|e| format!("write stix: {e}"))
}

/// Return the findings CSV string for `summary` (used for copy-to-clipboard).
#[tauri::command]
fn export_csv(summary: AnalysisOutput) -> Result<String, String> {
    Ok(ppcap_core::export::findings_csv(&summary))
}

/// Return the STIX 2.1 bundle string for `summary` (used for copy-to-clipboard).
#[tauri::command]
fn export_stix(summary: AnalysisOutput) -> Result<String, String> {
    Ok(ppcap_core::export::stix_bundle(&summary, now_unix_secs()))
}
```

- [ ] **Step 2: Register them** — in the `tauri::generate_handler![ ... ]` list (after `save_report`):

```rust
        .invoke_handler(tauri::generate_handler![
            analyze_capture,
            save_report,
            save_csv,
            save_stix,
            export_csv,
            export_stix,
            extract_flow_packets,
            set_reputation_key,
            reputation_key_status,
            reputation_lookup,
            set_ai_key,
            ai_key_status,
            ai_chat_stream
        ])
```

- [ ] **Step 3: Build to verify** — `cd ui/src-tauri && export PATH="/c/Users/ravid/.cargo/bin:$PATH" && cargo build` → compiles clean. (If `ring`/C-compiler errors appear from the `online` default feature, prepend `/c/Users/ravid/opt/mingw64/bin` to PATH and retry — per the build-toolchain notes.)

- [ ] **Step 4: Commit**

```bash
git add ui/src-tauri/src/lib.rs
git commit -m "feat(tauri): save_csv/save_stix + export_csv/export_stix commands"
```

---

### Task 3: Platform layer — `exportCsv` / `exportStix` / `copyCsv` / `copyStix`

**Files:**
- Modify: `ui/src/lib/wasmEngine.ts` (add `exportCsvWasm` / `exportStixWasm` wrappers)
- Modify: `ui/src/lib/platform.ts` (add the four export fns)
- Test: `ui/src/lib/platform.test.ts` (create)

**Interfaces:**
- Consumes: WASM `export_csv`/`export_stix` (Task 1); Tauri `save_csv`/`save_stix`/`export_csv`/`export_stix` (Task 2); existing `ExportResult { ok: boolean; message: string }` (`platform.ts:48`), `isTauri()`, `save` (dialog), `invoke`.
- Produces: `exportCsv(summary)`, `exportStix(summary)`, `copyCsv(summary)`, `copyStix(summary)` → `Promise<ExportResult>`.

- [ ] **Step 1: Add the WASM wrappers** — in `ui/src/lib/wasmEngine.ts`, extend the wasm import (line ~10) and add wrappers (mirror `applyReputationWasm`, which already uses `ensureWasm()`):

```ts
import initWasm, {
  analyze as wasmAnalyze,
  extract_packets as wasmExtractPackets,
  apply_reputation as wasmApplyReputation,
  export_csv as wasmExportCsv,
  export_stix as wasmExportStix,
} from "../wasm/ppcap_wasm.js";

// …existing ensureWasm() / wrappers…

export async function exportCsvWasm(outputJson: string): Promise<string> {
  await ensureWasm();
  return wasmExportCsv(outputJson) as string;
}

export async function exportStixWasm(outputJson: string, generatedUnixSecs: number): Promise<string> {
  await ensureWasm();
  return wasmExportStix(outputJson, generatedUnixSecs) as string;
}
```

- [ ] **Step 2: Write the failing test** — `ui/src/lib/platform.test.ts`:

```ts
import { describe, it, expect, vi, beforeEach } from "vitest";

const invoke = vi.fn();
const save = vi.fn();
const isTauri = vi.fn();
const exportCsvWasm = vi.fn();
const exportStixWasm = vi.fn();

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
```

- [ ] **Step 3: Run it to verify it fails** — `cd ui && npx vitest run src/lib/platform.test.ts` → FAIL (exports not defined).

- [ ] **Step 4: Implement** — append to `ui/src/lib/platform.ts` (it already imports `invoke`, `save`, `isTauri`, `AnalysisOutput`, `ExportResult`):

```ts
import { exportCsvWasm, exportStixWasm } from "./wasmEngine";

/** Basename of the capture source (no extension), for export filenames. */
function captureBase(summary: AnalysisOutput): string {
  const p = summary.source_path || "";
  return p.split(/[\\/]/).pop()?.replace(/\.[^.]+$/, "") || "packetpilot";
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
    await invoke("save_csv", { summary, path });
    return { ok: true, message: "CSV saved" };
  }
  const csv = await exportCsvWasm(JSON.stringify(summary));
  downloadText(csv, name, "text/csv");
  return { ok: true, message: "Downloaded" };
}

export async function exportStix(summary: AnalysisOutput): Promise<ExportResult> {
  const name = `${captureBase(summary)}-stix.json`;
  if (isTauri()) {
    const path = await save({ defaultPath: name, filters: [{ name: "STIX bundle", extensions: ["json"] }] });
    if (!path) return { ok: false, message: "" };
    await invoke("save_stix", { summary, path });
    return { ok: true, message: "STIX bundle saved" };
  }
  const stix = await exportStixWasm(JSON.stringify(summary), Math.floor(Date.now() / 1000));
  downloadText(stix, name, "application/json");
  return { ok: true, message: "Downloaded" };
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
  const csv = isTauri()
    ? await invoke<string>("export_csv", { summary })
    : await exportCsvWasm(JSON.stringify(summary));
  return copyText(csv);
}

export async function copyStix(summary: AnalysisOutput): Promise<ExportResult> {
  const stix = isTauri()
    ? await invoke<string>("export_stix", { summary })
    : await exportStixWasm(JSON.stringify(summary), Math.floor(Date.now() / 1000));
  return copyText(stix);
}
```

- [ ] **Step 5: Run it to verify it passes** — `cd ui && npx vitest run src/lib/platform.test.ts` → 3 PASS. `npx tsc --noEmit 2>&1 | grep -v "FlowsView.test"` → no new errors.

- [ ] **Step 6: Commit**

```bash
git add ui/src/lib/wasmEngine.ts ui/src/lib/platform.ts ui/src/lib/platform.test.ts
git commit -m "feat(export): platform exportCsv/exportStix/copyCsv/copyStix"
```

---

### Task 4: Export dropdown menu + UI wiring

**Files:**
- Create: `ui/src/cockpit/ExportMenu.tsx` + `ExportMenu.test.tsx`
- Modify: `ui/src/cockpit/CommandBar.tsx` (use ExportMenu in place of the single Export `ActionButton`)
- Modify: `ui/src/components/layout/AppShell.tsx` (new handlers + palette actions, pass the action list to CommandBar)
- Modify: `ui/src/App.tsx` (handlers calling the new platform fns)

**Interfaces:**
- Consumes: `exportCsv`/`exportStix`/`copyCsv`/`copyStix` (Task 3), existing `exportReport`, `ExportResult`.
- `ExportMenu` props: `{ actions: { id: string; label: string; run: () => void }[]; disabled?: boolean; busy?: boolean }`.

- [ ] **Step 1: Write the failing test** — `ui/src/cockpit/ExportMenu.test.tsx`:

```tsx
import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ExportMenu } from "./ExportMenu";

describe("ExportMenu", () => {
  it("opens on click and runs the chosen action", async () => {
    const user = userEvent.setup();
    const run = vi.fn();
    render(<ExportMenu actions={[{ id: "csv", label: "Export CSV", run }]} />);
    await user.click(screen.getByRole("button", { name: /export/i }));
    await user.click(screen.getByText("Export CSV"));
    expect(run).toHaveBeenCalled();
  });

  it("disables the trigger when disabled", () => {
    render(<ExportMenu actions={[]} disabled />);
    expect(screen.getByRole("button", { name: /export/i })).toBeDisabled();
  });
});
```

- [ ] **Step 2: Run it to verify it fails** — `cd ui && npx vitest run src/cockpit/ExportMenu.test.tsx` → FAIL (module not found).

- [ ] **Step 3: Implement `ExportMenu`** — `ui/src/cockpit/ExportMenu.tsx`:

```tsx
import { useEffect, useRef, useState } from "react";
import { FileDown, Loader2 } from "lucide-react";

export interface ExportAction {
  id: string;
  label: string;
  run: () => void;
}

/** A small dropdown of export actions (download/copy per format). */
export function ExportMenu({
  actions,
  disabled,
  busy,
}: {
  actions: ExportAction[];
  disabled?: boolean;
  busy?: boolean;
}) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", onDoc);
    return () => document.removeEventListener("mousedown", onDoc);
  }, [open]);

  return (
    <div ref={ref} className="relative inline-flex">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        disabled={disabled || busy}
        aria-expanded={open}
        className="inline-flex items-center gap-1.5 rounded-md border border-[var(--color-border)] bg-[var(--color-surface-2)] px-2.5 py-1.5 text-xs font-medium text-[var(--color-text)] transition-colors hover:border-[var(--color-accent)] hover:text-[var(--color-accent)] disabled:opacity-50"
      >
        {busy ? <Loader2 size={14} className="animate-spin" /> : <FileDown size={14} />}
        Export
      </button>
      {open && (
        <div className="absolute right-0 top-full z-30 mt-1 min-w-[12rem] overflow-hidden rounded-md border border-[var(--color-border)] bg-[var(--color-surface-2)] py-1 shadow-lg">
          {actions.map((a) => (
            <button
              key={a.id}
              type="button"
              onClick={() => { setOpen(false); a.run(); }}
              className="block w-full px-3 py-1.5 text-left text-xs text-[var(--color-text-dim)] transition-colors hover:bg-[var(--color-surface)] hover:text-[var(--color-accent)]"
            >
              {a.label}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
```

- [ ] **Step 4: Run the ExportMenu test** — `cd ui && npx vitest run src/cockpit/ExportMenu.test.tsx` → 2 PASS.

- [ ] **Step 5: Wire App handlers** — in `ui/src/App.tsx`, the existing `handleExport` (line ~411) calls `exportReport`. Extend the import (line ~36) and add four sibling handlers, each guarding `summary.data`:

```tsx
import {
  exportReport,
  exportCsv,
  exportStix,
  copyCsv,
  copyStix,
  // …existing imports…
} from "./lib/platform";
```

```tsx
  const handleExportCsv = useCallback(async () => {
    if (summary.status !== "ready" || !summary.data) return undefined;
    return exportCsv(summary.data);
  }, [summary]);
  const handleExportStix = useCallback(async () => {
    if (summary.status !== "ready" || !summary.data) return undefined;
    return exportStix(summary.data);
  }, [summary]);
  const handleCopyCsv = useCallback(async () => {
    if (summary.status !== "ready" || !summary.data) return undefined;
    return copyCsv(summary.data);
  }, [summary]);
  const handleCopyStix = useCallback(async () => {
    if (summary.status !== "ready" || !summary.data) return undefined;
    return copyStix(summary.data);
  }, [summary]);
```

Pass them to `<AppShell>` (next to the existing `onExport={handleExport}`, line ~445):

```tsx
        onExportCsv={handleExportCsv}
        onExportStix={handleExportStix}
        onCopyCsv={handleCopyCsv}
        onCopyStix={handleCopyStix}
```

- [ ] **Step 6: Wire AppShell** — in `ui/src/components/layout/AppShell.tsx`:

(a) Add the four optional props to `AppShellProps` (next to `onExport`, line ~41):

```ts
  onExportCsv?: () => Promise<ExportResult | undefined>;
  onExportStix?: () => Promise<ExportResult | undefined>;
  onCopyCsv?: () => Promise<ExportResult | undefined>;
  onCopyStix?: () => Promise<ExportResult | undefined>;
```

(b) Destructure them in the component params (next to `onExport`).

(c) Generalize the existing `handleExportClick` (line ~115, which wraps `onExport` with the `exporting` state + result message) into a runner any action can use, then build the export action list. After the existing `handleExportClick`:

```tsx
  const runExport = useCallback(
    async (fn?: () => Promise<ExportResult | undefined>) => {
      if (!fn || !canExport || exporting) return;
      setExporting(true);
      try {
        const res = await fn();
        if (res) setExportMsg(res.message);   // reuse the existing result-message state/var name from handleExportClick
      } finally {
        setExporting(false);
      }
    },
    [canExport, exporting],
  );

  const exportActions = useMemo(
    () => [
      { id: "report", label: "HTML report", run: () => void runExport(onExport) },
      { id: "csv", label: "CSV — download", run: () => void runExport(onExportCsv) },
      { id: "csv-copy", label: "CSV — copy", run: () => void runExport(onCopyCsv) },
      { id: "stix", label: "STIX bundle — download", run: () => void runExport(onExportStix) },
      { id: "stix-copy", label: "STIX bundle — copy", run: () => void runExport(onCopyStix) },
    ],
    [runExport, onExport, onExportCsv, onCopyCsv, onExportStix, onCopyStix],
  );
```

> NOTE: read the existing `handleExportClick` body and reuse its exact state setters (`setExporting` + whatever holds the result message). `runExport` must mirror it; if `handleExportClick` is now redundant, replace its body with `runExport(onExport)` rather than duplicating.

(d) Add the format actions to `paletteActions` (line ~153), conditionally on `canExport`, after the existing `export` action:

```tsx
    ...(canExport ? [
      { id: "export", label: "Export report", hint: "action", run: () => void runExport(onExport) },
      { id: "export-csv", label: "Export CSV", hint: "action", run: () => void runExport(onExportCsv) },
      { id: "export-csv-copy", label: "Copy CSV", hint: "action", run: () => void runExport(onCopyCsv) },
      { id: "export-stix", label: "Export STIX bundle", hint: "action", run: () => void runExport(onExportStix) },
      { id: "export-stix-copy", label: "Copy STIX bundle", hint: "action", run: () => void runExport(onCopyStix) },
    ] : []),
```

(replace the single existing `export` palette entry). Add `runExport`, `onExportCsv`, `onCopyCsv`, `onExportStix`, `onCopyStix` to the `useMemo` deps.

(e) Pass the actions to `<CommandBar>` (it currently gets `onExport`/`exporting`, line ~167): add `exportActions={canExport ? exportActions : []}`.

- [ ] **Step 7: Use ExportMenu in CommandBar** — in `ui/src/cockpit/CommandBar.tsx`, add `exportActions?: ExportAction[]` to the props, import `ExportMenu`/`ExportAction`, and replace the single Export `ActionButton` (line ~149) with:

```tsx
        <ExportMenu actions={exportActions ?? []} disabled={(exportActions?.length ?? 0) === 0} busy={exporting} />
```

(Keep the `exporting` prop; drop `onExport` if it is now unused — or keep it for back-compat if other call sites use it; check and remove only if unreferenced to avoid an unused-prop/`noUnusedLocals` issue.)

- [ ] **Step 8: Verify** — `cd ui && npx vitest run src/cockpit/ExportMenu.test.tsx src/components/layout/AppShell.test.tsx src/App.test.tsx` (whichever exist; `grep -rl "AppShell\|App.test" ui/src --include=*.test.tsx`) → existing tests stay green; the menu test passes. `npx tsc --noEmit 2>&1 | grep -v "FlowsView.test"` → no new errors.

- [ ] **Step 9: Commit**

```bash
git add ui/src/cockpit/ExportMenu.tsx ui/src/cockpit/ExportMenu.test.tsx ui/src/cockpit/CommandBar.tsx ui/src/components/layout/AppShell.tsx ui/src/App.tsx
git commit -m "feat(export): Export dropdown menu + CSV/STIX actions in command bar + palette"
```

---

### Task 5: Coverage gate + CI-toolchain verification

**Files:**
- Add focused tests wherever `npm run test:coverage` shows a new file below the bar.

- [ ] **Step 1: Realign + rebuild wasm** —

```bash
cd ui && export PATH="/c/Program Files/nodejs:/c/Users/ravid/.cargo/bin:$PATH"
git diff --stat package.json package-lock.json
git checkout -- package.json package-lock.json 2>/dev/null || true
npm ci
node -p "require('./node_modules/vitest/package.json').version"   # MUST print 1.6.1
npm run build:wasm   # regenerate src/wasm with export_csv/export_stix (gitignored)
```

Do NOT run `npm install`.

- [ ] **Step 2: Build gate** — `cd ui && npm run build; echo "build EXIT: $?"` → EXIT 0, zero `error TS`.

- [ ] **Step 3: Coverage gate** — `cd ui && npm run test:coverage; echo "EXIT: $?"` → EXIT 0; `All files` lines/functions/statements ≥ 80, branches ≥ 70. Paste the line into the report.

- [ ] **Step 4: Fill gaps** — if `platform.ts`/`ExportMenu`/`wasmEngine.ts` branches dip a metric below the bar, add a real behavior test (e.g. `exportStix` desktop branch invokes `save_stix`; `copyCsv` desktop branch invokes the `export_csv` command; a cancelled save dialog → `{ ok: false }`). Re-run step 3.

- [ ] **Step 5: Commit** (only if tests were added)

```bash
git add ui/src/lib/platform.test.ts ui/src/cockpit/ExportMenu.test.tsx
git commit -m "test(export): hold the coverage gate for structured export"
```

---

## Self-Review

**1. Spec coverage:** WASM exports (T1) + Tauri commands (T2) → spec §"Engine seam"; platform fns (T3) → §"Platform layer" (file + copy, desktop/browser split, filenames, STIX time); Export menu + palette + handlers (T4) → §"UI — Export dropdown menu"; coverage + wasm rebuild (T5) → §"Testing" + the WASM-rebuild constraint. CSV + STIX, copy + file, dropdown menu, expose-existing-fns — all covered. MISP/CEF, reputation-in-STIX, AI-narrative correctly absent (out of scope). ✓

**2. Placeholder scan:** every code step has complete code. The notes (round-trip fixture fallback in T1; reuse `handleExportClick`'s exact state setters in T4; drop `onExport` only if unreferenced) are concrete in-repo verifications, not placeholders. ✓

**3. Type consistency:** `export_csv`/`export_stix` (WASM, JSON-in/String-out) ⇄ `exportCsvWasm`/`exportStixWasm` (TS wrappers) ⇄ `exportCsv`/`exportStix`/`copyCsv`/`copyStix` (platform, `Promise<ExportResult>`) ⇄ App `handleExport*`/`handleCopy*` ⇄ AppShell `onExport*`/`onCopy*` props ⇄ `ExportMenu` `ExportAction { id, label, run }`. Tauri `save_csv`/`save_stix`/`export_csv`/`export_stix`. All consistent across T1–T4. ✓
