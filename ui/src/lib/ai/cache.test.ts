import { describe, it, expect } from "vitest";
import "fake-indexeddb/auto";
import { putAiSummary, getAiSummary } from "./cache";

describe("ai summary cache", () => {
  it("round-trips by capture id", async () => {
    await putAiSummary("cap-1", "the brief", "claude-opus-4-8", 1000);
    const got = await getAiSummary("cap-1");
    expect(got?.text).toBe("the brief");
    expect(got?.model).toBe("claude-opus-4-8");
    expect(await getAiSummary("absent")).toBeNull();
  });
});
