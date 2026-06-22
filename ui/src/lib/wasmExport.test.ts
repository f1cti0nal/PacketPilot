import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { initSync, export_csv, export_stix } from "../wasm/ppcap_wasm.js";
import { makeOutput } from "../test/fixtures.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const wasmBytes = readFileSync(resolve(__dirname, "../wasm/ppcap_wasm_bg.wasm"));
initSync({ module: wasmBytes });

// Use the project's canonical fixture (has ≥1 finding — beacon + sweep + data_exfil).
const json = JSON.stringify(makeOutput());

describe("wasm export round-trip", () => {
  it("export_csv emits the header + a finding row", () => {
    const csv = export_csv(json) as string;
    expect(csv.split("\n")[0]).toContain("kind,severity,score");
    expect(csv).toContain("beacon");
  });

  it("export_stix emits a STIX 2.1 bundle", () => {
    const stix = export_stix(json, BigInt(1_700_000_000)) as string;
    const obj = JSON.parse(stix);
    expect(obj.type).toBe("bundle");
    expect(stix).toContain("2.1");
  });
});
