import { beforeEach, describe, expect, it } from "vitest";
import {
  emptyProgress,
  loadProgress,
  loadTeamPlaybooks,
  saveProgress,
  saveTeamPlaybooks,
  setNote,
  stepKey,
  toggleDone,
} from "./playbooks";
import type { PlaybookRun } from "../types";

describe("playbook progress", () => {
  beforeEach(() => localStorage.clear());

  it("round-trips per capture and alert", () => {
    let p = toggleDone(emptyProgress(), "c2-channel/cadence");
    p = setNote(p, "c2-channel/cadence", "60s, low jitter");
    saveProgress("cap-a", "alert:1", p);
    expect(loadProgress("cap-a", "alert:1")).toEqual(p);
    expect(loadProgress("cap-b", "alert:1")).toEqual(emptyProgress());
    expect(loadProgress("cap-a", "alert:2")).toEqual(emptyProgress());
  });

  it("toggles and clears", () => {
    const p = toggleDone(toggleDone(emptyProgress(), "a/b"), "a/b");
    expect(p.done).toEqual([]);
    expect(setNote(setNote(p, "a/b", "x"), "a/b", "  ").notes).toEqual({});
  });

  it("keeps the most recent captures only", () => {
    for (let i = 0; i < 55; i++) saveProgress(`cap-${i}`, "a", toggleDone(emptyProgress(), "x/y"), i);
    expect(loadProgress("cap-0", "a").done).toEqual([]);
    expect(loadProgress("cap-54", "a").done).toEqual(["x/y"]);
  });

  it("survives a corrupt store", () => {
    localStorage.setItem("packetpilot.playbooks.progress.v1", "{not json");
    expect(loadProgress("cap", "a")).toEqual(emptyProgress());
  });

  it("stores and removes the team file", () => {
    expect(loadTeamPlaybooks()).toBeNull();
    saveTeamPlaybooks('{"version":1,"playbooks":[]}');
    expect(loadTeamPlaybooks()).toBe('{"version":1,"playbooks":[]}');
    saveTeamPlaybooks(null);
    expect(loadTeamPlaybooks()).toBeNull();
  });

  it("keys steps like the engine", () => {
    const run = { playbook_id: "c2-channel" } as PlaybookRun;
    expect(stepKey(run, { id: "cadence" } as PlaybookRun["steps"][number])).toBe("c2-channel/cadence");
  });
});
