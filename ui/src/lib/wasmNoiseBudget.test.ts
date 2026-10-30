import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { initSync, apply_suppressions } from "../wasm/ppcap_wasm.js";
import { makeOutput } from "../test/fixtures.js";
import type { AnalysisOutput } from "../types";

const __dirname = dirname(fileURLToPath(import.meta.url));
initSync({ module: readFileSync(resolve(__dirname, "../wasm/ppcap_wasm_bg.wasm")) });

describe("wasm noise budget", () => {
  it("is re-derived with the alert queue", () => {
    const out = makeOutput();
    delete out.summary.noise_budget;
    const res = JSON.parse(apply_suppressions(JSON.stringify(out), '{"version":1,"rules":[]}', "")) as {
      output: AnalysisOutput;
    };
    const b = res.output.summary.noise_budget!;
    expect(b.packets).toBe(out.summary.total_packets);
    expect(b.flows).toBe(out.summary.total_flows);
    expect(b.findings).toBe(out.summary.findings!.length);
    expect(b.stories).toBe(res.output.summary.alerts!.length);
    expect(b.rates.minutes_per_story).toBe(15);
    expect(b.saved_minutes).toBeGreaterThanOrEqual(0);
  });
});
