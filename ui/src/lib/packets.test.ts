import { describe, it, expect, vi, beforeEach } from "vitest";
import { makeFlows } from "../test/fixtures";

const { isTauri, extractPacketsViaTauri, invokeStub, saveStub, carvePcapViaWasm, extractPacketsViaWasm, downloadBinary } = vi.hoisted(() => ({
  isTauri: vi.fn(() => false),
  extractPacketsViaTauri: vi.fn(),
  invokeStub: vi.fn(),
  saveStub: vi.fn(),
  carvePcapViaWasm: vi.fn(),
  downloadBinary: vi.fn(),
  extractPacketsViaWasm: vi.fn(async () => ({
    total: 1, truncated: false,
    packets: [{
      index: 0, ts_ns: 1_700_000_000_000_000, direction: "c2s",
      wire_len: 74, cap_len: 74, tcp_flags: 24, seq: 1, ack: 1,
      payload_len: 3, payload_b64: btoa("GET"), payload_truncated: false,
    }],
  })),
}));

vi.mock("./platform", () => ({ isTauri, extractPacketsViaTauri, downloadBinary }));
vi.mock("./wasmEngine", () => ({ extractPacketsViaWasm, carvePcapViaWasm }));
vi.mock("@tauri-apps/api/core", () => ({ invoke: invokeStub }));
vi.mock("@tauri-apps/plugin-dialog", () => ({ save: saveStub, open: vi.fn() }));

import { extractFlowPackets, packetsAvailable, PacketsUnavailableError, carveSubPcap } from "./packets";
import type { ActiveSource, CarveQuery } from "../types";

const browserSource: ActiveSource = { kind: "bytes", bytes: new ArrayBuffer(8) };
const desktopSource: ActiveSource = { kind: "path", path: "/captures/test.pcap" };
const carveQuery: CarveQuery = { host: "9.9.9.9", start_ns: 0, end_ns: 9 };

beforeEach(() => {
  isTauri.mockReturnValue(false);
  carvePcapViaWasm.mockReset();
  invokeStub.mockReset();
  saveStub.mockReset();
  downloadBinary.mockReset();
});

describe("carveSubPcap", () => {
  it("browser (bytes) carves via wasm and downloads binary", async () => {
    const fakeBytes = new Uint8Array([0xa1, 0xb2, 0xc3, 0xd4]);
    carvePcapViaWasm.mockResolvedValue(fakeBytes);
    downloadBinary.mockImplementation(() => {});
    const res = await carveSubPcap(carveQuery, browserSource, "9.9.9.9-carve.pcap");
    expect(carvePcapViaWasm).toHaveBeenCalledWith(browserSource.bytes, carveQuery);
    expect(downloadBinary).toHaveBeenCalledWith(
      fakeBytes,
      "9.9.9.9-carve.pcap",
      "application/vnd.tcpdump.pcap",
    );
    expect(res.ok).toBe(true);
    expect(res.message).toBe("Downloaded");
  });

  it("desktop (path+tauri) saves via invoke carve_pcap_to", async () => {
    isTauri.mockReturnValue(true);
    saveStub.mockResolvedValue("/tmp/out.pcap");
    invokeStub.mockResolvedValue(42);
    const res = await carveSubPcap(carveQuery, desktopSource, "test-carve.pcap");
    expect(saveStub).toHaveBeenCalled();
    expect(invokeStub).toHaveBeenCalledWith("carve_pcap_to", {
      pathIn: "/captures/test.pcap",
      query: carveQuery,
      pathOut: "/tmp/out.pcap",
    });
    expect(res.ok).toBe(true);
    expect(res.message).toBe("Carved 42 packets");
  });

  it("desktop (path+tauri) returns ok:false when user cancels save dialog", async () => {
    isTauri.mockReturnValue(true);
    saveStub.mockResolvedValue(null);
    const res = await carveSubPcap(carveQuery, desktopSource, "test-carve.pcap");
    expect(res.ok).toBe(false);
    expect(res.message).toBe("");
    expect(invokeStub).not.toHaveBeenCalled();
  });

  it("desktop (path+tauri) returns ok:false when invoke throws", async () => {
    isTauri.mockReturnValue(true);
    saveStub.mockResolvedValue("/tmp/out.pcap");
    invokeStub.mockRejectedValue(new Error("disk full"));
    const res = await carveSubPcap(carveQuery, desktopSource, "test-carve.pcap");
    expect(res.ok).toBe(false);
    expect(res.message).toContain("Carve failed");
  });

  it("null source returns ok:false with descriptive message", async () => {
    const res = await carveSubPcap(carveQuery, null, "test-carve.pcap");
    expect(res.ok).toBe(false);
    expect(res.message).toContain("Packets are only available");
  });

  it("path source without tauri returns ok:false", async () => {
    isTauri.mockReturnValue(false);
    const res = await carveSubPcap(carveQuery, desktopSource, "test-carve.pcap");
    expect(res.ok).toBe(false);
    expect(res.message).toContain("Packets are only available");
  });
});

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

  it("throws a descriptive error for path source outside Tauri (isTauri=false)", async () => {
    // The platform mock above sets isTauri() → false, so a {kind:"path"} source
    // must produce a clear diagnostic rather than the generic PacketsUnavailableError.
    await expect(
      extractFlowPackets({ kind: "path", path: "/captures/test.pcap" }, flow),
    ).rejects.toThrow("Path-based packet sources require the Tauri desktop runtime.");
  });
});
