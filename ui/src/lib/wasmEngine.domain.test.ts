import { describe, it, expect, vi } from "vitest";

vi.mock("../wasm/ppcap_wasm.js", () => ({
  default: vi.fn(async () => {}),
  analyze: vi.fn(), extract_packets: vi.fn(), apply_reputation: vi.fn(),
  apply_domain_reputation: vi.fn((o: string) => o), // echo the output json
  export_csv: vi.fn(), export_stix: vi.fn(),
}));
vi.mock("./data", () => ({ loadFlows: vi.fn(), flowRowFromWasm: vi.fn() }));

import { applyDomainReputationWasm } from "./wasmEngine";

describe("applyDomainReputationWasm", () => {
  it("calls the wasm export and parses the result", async () => {
    const out = await applyDomainReputationWasm(JSON.stringify({ summary: { domain_threats: [] } }), {});
    expect((out as any).summary.domain_threats).toEqual([]);
  });
});
