import { beforeEach, describe, expect, it } from "vitest";
import {
  emptyProgress,
  legacyCaptureKey,
  loadProgress,
  progressCaptureKey,
  loadTeamPlaybooks,
  saveProgress,
  saveTeamPlaybooks,
  setNote,
  stepKey,
  toggleDone,
} from "./playbooks";
import type { AnalysisOutput, PlaybookRun } from "../types";

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

  it("keys progress by capture content, not just its path", () => {
    const out = (sha: string | null, first: number) =>
      ({
        source_path: "/cases/traffic.pcap",
        source_sha256: sha,
        summary: { first_ts_ns: first, last_ts_ns: first + 10, total_packets: 5, total_bytes: 500 },
      }) as unknown as AnalysisOutput;
    expect(progressCaptureKey(out("ab12", 1))).toBe("sha256:ab12");
    expect(progressCaptureKey(out(null, 1))).not.toBe(progressCaptureKey(out(null, 2)));
    expect(progressCaptureKey(out(null, 1))).toBe(progressCaptureKey(out(null, 1)));
  });

  it("moves progress saved under the earlier bare-SHA key", () => {
    const p = toggleDone(emptyProgress(), "c2-channel/cadence");
    saveProgress("ab12", "alert:1", p, 5);
    saveProgress("sha256:ab12", "alert:2", toggleDone(emptyProgress(), "x/y"), 6);
    const out = { source_path: "/c.pcap", source_sha256: "ab12" } as unknown as AnalysisOutput;
    expect(legacyCaptureKey(out)).toBe("ab12");
    expect(legacyCaptureKey({ ...out, source_sha256: null } as unknown as AnalysisOutput)).toBeNull();
    expect(loadProgress("sha256:ab12", "alert:1", "ab12")).toEqual(p);
    // Moved, not copied: the new key holds both alerts and the old key is gone.
    expect(loadProgress("ab12", "alert:1")).toEqual(emptyProgress());
    expect(loadProgress("sha256:ab12", "alert:1")).toEqual(p);
    expect(loadProgress("sha256:ab12", "alert:2").done).toEqual(["x/y"]);
  });

  it("keys steps like the engine", () => {
    const run = { playbook_id: "c2-channel" } as PlaybookRun;
    expect(stepKey(run, { id: "cadence" } as PlaybookRun["steps"][number])).toBe("c2-channel/cadence");
  });
});
