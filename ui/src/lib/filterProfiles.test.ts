import { describe, it, expect, beforeEach } from "vitest";
import {
  listProfiles, saveProfile, removeProfile, clearProfiles, serializeProfiles, importProfiles,
  type FlowFilter,
} from "./filterProfiles";
import { scopedKey } from "./storageScope";

const f = (over: Partial<FlowFilter> = {}): FlowFilter => ({ query: "10.0.0.5", category: "c2", severity: undefined, proto: undefined, ...over });

describe("filterProfiles", () => {
  beforeEach(() => localStorage.clear());

  it("saves and lists, persisting under the v1 key", () => {
    saveProfile("C2 hunt", f());
    expect(listProfiles().map((p) => p.name)).toEqual(["C2 hunt"]);
    expect(localStorage.getItem(scopedKey("packetpilot.filterProfiles.v1"))).toContain("C2 hunt");
  });

  it("upserts by name (same name keeps one, updated filter)", () => {
    saveProfile("hunt", f({ query: "a" }));
    saveProfile("hunt", f({ query: "b" }));
    const list = listProfiles();
    expect(list).toHaveLength(1);
    expect(list[0].filter.query).toBe("b");
  });

  it("removes and clears", () => {
    const list = saveProfile("x", f());
    expect(removeProfile(list[0].id)).toHaveLength(0);
    saveProfile("y", f());
    expect(clearProfiles()).toHaveLength(0);
    expect(listProfiles()).toHaveLength(0);
  });

  it("round-trips via serialize/import", () => {
    saveProfile("p1", f({ query: "one" }));
    saveProfile("p2", f({ query: "two", severity: "high" as any }));
    const json = serializeProfiles();
    localStorage.clear();
    const res = importProfiles(json);
    expect(res.ok).toBe(true);
    expect(listProfiles().map((p) => p.name).sort()).toEqual(["p1", "p2"]);
  });

  it("rejects malformed import without throwing or persisting", () => {
    saveProfile("keep", f());
    const res = importProfiles("{ not json");
    expect(res.ok).toBe(false);
    expect(listProfiles().map((p) => p.name)).toEqual(["keep"]); // unchanged
  });

  it("gives distinct names distinct ids even when they would slug alike", () => {
    // 'DNS' and 'dns' previously both slugged to id 'fp_dns' → React key dupes + one
    // delete removing both. Ids are now 1:1 with the unique name.
    saveProfile("DNS", f());
    saveProfile("dns", f());
    const list = listProfiles();
    expect(list).toHaveLength(2);
    expect(new Set(list.map((p) => p.id)).size).toBe(2);
  });

  it("removeProfile deletes exactly one of two slug-colliding names", () => {
    saveProfile("Web traffic", f());
    saveProfile("Web/traffic", f());
    const target = listProfiles().find((p) => p.name === "Web traffic")!;
    const rest = removeProfile(target.id);
    expect(rest.map((p) => p.name)).toEqual(["Web/traffic"]);
  });

  it("imports valid entries and skips invalid ones", () => {
    const res = importProfiles(JSON.stringify([
      { id: "a", name: "good", filter: { query: "q", category: "web" } },
      { id: "b", name: "", filter: { query: "x", category: "web" } }, // invalid: empty name
      { nope: true },                                                  // invalid: wrong shape
    ]));
    expect(res.ok).toBe(true);
    expect(listProfiles().map((p) => p.name)).toEqual(["good"]);
  });
});
