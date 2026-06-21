/**
 * Cross-surface parity test: verifies that the WASM `apply_reputation` export
 * produces IDENTICAL results to the native Rust implementation.
 *
 * The fixture `ui/src/test/reputation-parity.fixture.json` is the single source
 * of truth. The Rust side asserts the same `expected` block in
 * `engine/crates/ppcap-core/tests/reputation_parity.rs`.
 *
 * WASM initialization: jsdom has no dev-server, so we load the `.wasm` binary
 * from disk via Node's `fs.readFileSync` and call the synchronous `initSync`
 * export instead of the async `default` export (which does a network fetch).
 */
import { describe, it, expect } from "vitest";
import { readFileSync } from "fs";
import { fileURLToPath } from "url";
import { dirname, resolve } from "path";
import type { AnalysisOutput } from "../../types";
import fixture from "../../test/reputation-parity.fixture.json";
import { initSync, apply_reputation } from "../../wasm/ppcap_wasm.js";

// Load + instantiate the WASM module synchronously from the build artefact on disk.
// This bypasses the `fetch()` that the async default export would otherwise use.
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const wasmBytes = readFileSync(resolve(__dirname, "../../wasm/ppcap_wasm_bg.wasm"));
initSync({ module: wasmBytes });

describe("cross-surface parity", () => {
  it("WASM apply matches the shared expected (== native)", () => {
    const outputJson = JSON.stringify((fixture as any).output);
    const verdictsJson = JSON.stringify((fixture as any).verdicts);
    const resultJson = apply_reputation(outputJson, verdictsJson);
    const enriched = JSON.parse(resultJson) as AnalysisOutput;
    const got = enriched.summary.ip_threats.map((t) => ({ ip: t.ip, severity: t.severity, score: t.score }));
    const want = (fixture as any).expected.ip_threats.map((t: any) => ({ ip: t.ip, severity: t.severity, score: t.score }));
    expect(got).toEqual(want);
  });
});
