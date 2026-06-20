import { describe, it, expect, vi } from "vitest";
import { makeFlows } from "../test/fixtures";

vi.mock("./platform", () => ({ isTauri: () => false, extractPacketsViaTauri: vi.fn() }));
vi.mock("./wasmEngine", () => ({
  extractPacketsViaWasm: vi.fn(async () => ({
    total: 1, truncated: false,
    packets: [{
      index: 0, ts_ns: 1_700_000_000_000_000, direction: "c2s",
      wire_len: 74, cap_len: 74, tcp_flags: 24, seq: 1, ack: 1,
      payload_len: 3, payload_b64: btoa("GET"), payload_truncated: false,
    }],
  })),
}));

import { extractFlowPackets, packetsAvailable, PacketsUnavailableError } from "./packets";

describe("extractFlowPackets", () => {
  const flow = makeFlows(1)[0];

  it("unavailable when no source", async () => {
    expect(packetsAvailable(null)).toBe(false);
    await expect(extractFlowPackets(null, flow)).rejects.toBeInstanceOf(PacketsUnavailableError);
  });

  it("routes bytes → wasm and decodes payload", async () => {
    const fp = await extractFlowPackets({ kind: "bytes", bytes: new ArrayBuffer(8) }, flow);
    expect(fp.packets[0].payloadLen).toBe(3);
    expect(new TextDecoder().decode(fp.packets[0].payload)).toBe("GET");
    expect(fp.packets[0].direction).toBe("c2s");
  });
});
