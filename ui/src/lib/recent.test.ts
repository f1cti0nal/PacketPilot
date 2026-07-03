import { describe, it, expect, beforeEach } from "vitest";
import "fake-indexeddb/auto";
import { recordRecent, listRecent, updateRecentSummary } from "./recent";
import { makeOutput } from "../test/fixtures";

function record(id: string) {
  return recordRecent({
    id,
    name: `${id}.pcap`,
    sizeBytes: 1000,
    origin: "wasm",
    summary: makeOutput(),
    flowCount: 0,
    flowsCached: false,
  });
}

describe("updateRecentSummary", () => {
  beforeEach(() => localStorage.clear());

  it("swaps the summary of an existing entry in place, preserving id, position, and metadata", () => {
    record("a");
    record("b"); // newest-first ordering => [b, a]
    const enriched = makeOutput({ engine_version: "enriched" });

    const next = updateRecentSummary("a", enriched);

    expect(next.map((e) => e.id)).toEqual(["b", "a"]); // order untouched
    const a = next.find((e) => e.id === "a")!;
    expect(a.summary).toBe(enriched);
    expect(a.name).toBe("a.pcap"); // sibling metadata untouched
    // Persisted: a fresh read of localStorage sees the enriched summary (so a reopen restores it).
    expect(listRecent().find((e) => e.id === "a")!.summary.engine_version).toBe("enriched");
    // The other entry is left alone.
    expect(listRecent().find((e) => e.id === "b")!.summary.engine_version).toBe("0.1.0");
  });

  it("no-ops and returns the current list when the id is absent", () => {
    record("a");
    const before = listRecent();
    const next = updateRecentSummary("missing", makeOutput({ engine_version: "x" }));
    expect(next).toEqual(before);
    expect(listRecent().find((e) => e.id === "a")!.summary.engine_version).toBe("0.1.0");
  });
});
