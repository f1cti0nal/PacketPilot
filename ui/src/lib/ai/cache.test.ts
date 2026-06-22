import { describe, it, expect } from "vitest";
import "fake-indexeddb/auto";
import { putAiSummary, getAiSummary, captureKey } from "./cache";

describe("ai summary cache", () => {
  it("round-trips by capture id", async () => {
    await putAiSummary("cap-1", "the brief", "claude-opus-4-8", 1000);
    const got = await getAiSummary("cap-1");
    expect(got?.text).toBe("the brief");
    expect(got?.model).toBe("claude-opus-4-8");
    expect(await getAiSummary("absent")).toBeNull();
  });
});

describe("captureKey", () => {
  it("returns source_sha256 when present", () => {
    expect(captureKey({ source_sha256: "deadbeef", source_path: "/tmp/foo.pcap" })).toBe("deadbeef");
  });

  it("falls back to source_path when sha256 is empty", () => {
    expect(captureKey({ source_sha256: "", source_path: "/tmp/foo.pcap" })).toBe("/tmp/foo.pcap");
  });

  it("falls back to 'capture' when both are empty", () => {
    expect(captureKey({ source_sha256: "", source_path: "" })).toBe("capture");
  });
});
