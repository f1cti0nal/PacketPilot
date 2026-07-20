import { beforeEach, describe, expect, it } from "vitest";

import {
  clearSavedQueries,
  importSavedQueries,
  listSavedQueries,
  removeSavedQuery,
  saveQuery,
  serializeSavedQueries,
} from "./savedQueries";

describe("savedQueries", () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it("starts empty and round-trips a save", () => {
    expect(listSavedQueries()).toEqual([]);
    const list = saveQuery("Top DNS", "SELECT * FROM flow WHERE app_proto = 'dns'");
    expect(list).toHaveLength(1);
    expect(list[0]).toMatchObject({ id: "sq_Top DNS", name: "Top DNS" });
    expect(listSavedQueries()).toEqual(list);
  });

  it("upserts by trimmed name (no duplicates, latest wins)", () => {
    saveQuery("  A  ", "SELECT 1");
    const list = saveQuery("A", "SELECT 2");
    expect(list).toHaveLength(1);
    expect(list[0].sql).toBe("SELECT 2");
  });

  it("rejects empty names and empty SQL", () => {
    expect(saveQuery("", "SELECT 1")).toEqual([]);
    expect(saveQuery("name", "   ")).toEqual([]);
  });

  it("removes by id and clears", () => {
    saveQuery("A", "SELECT 1");
    saveQuery("B", "SELECT 2");
    expect(removeSavedQuery("sq_A").map((q) => q.name)).toEqual(["B"]);
    expect(clearSavedQueries()).toEqual([]);
    expect(listSavedQueries()).toEqual([]);
  });

  it("survives corrupted storage", () => {
    localStorage.setItem(
      Object.keys(localStorage).length ? Object.keys(localStorage)[0] : "x",
      "not json",
    );
    // Whatever the scoped key is, a corrupt value must yield [] rather than throw.
    saveQuery("A", "SELECT 1");
    const key = Object.keys(localStorage).find((k) => k.includes("savedQueries"))!;
    localStorage.setItem(key, "{broken");
    expect(listSavedQueries()).toEqual([]);
  });

  it("imports valid entries, merging by name, and rejects junk", () => {
    saveQuery("Keep", "SELECT 1");
    const res = importSavedQueries(
      JSON.stringify([
        { id: "sq_New", name: "New", sql: "SELECT 2" },
        { name: "Keep", sql: "SELECT 3" }, // overrides by name; id regenerated
        { name: "", sql: "SELECT 4" }, // invalid: dropped
      ]),
    );
    expect(res.ok).toBe(true);
    const byName = new Map(res.queries.map((q) => [q.name, q]));
    expect(byName.get("Keep")?.sql).toBe("SELECT 3");
    expect(byName.get("New")?.sql).toBe("SELECT 2");

    expect(importSavedQueries("nope").ok).toBe(false);
    expect(importSavedQueries("{}").ok).toBe(false);
    expect(importSavedQueries("[]").ok).toBe(false);
  });

  it("serializes to importable JSON", () => {
    saveQuery("A", "SELECT 1");
    const json = serializeSavedQueries();
    clearSavedQueries();
    expect(importSavedQueries(json).ok).toBe(true);
    expect(listSavedQueries().map((q) => q.name)).toEqual(["A"]);
  });
});
