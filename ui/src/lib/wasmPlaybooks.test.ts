import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { initSync, alert_playbooks, playbook_markdown, lint_playbooks, builtin_playbooks } from "../wasm/ppcap_wasm.js";
import { makeOutput } from "../test/fixtures.js";
import type { PlaybookRun } from "../types";

const __dirname = dirname(fileURLToPath(import.meta.url));
initSync({ module: readFileSync(resolve(__dirname, "../wasm/ppcap_wasm_bg.wasm")) });

const out = makeOutput();
const s = out.summary;
const slice = JSON.stringify({
  findings: s.findings,
  resolved_ips: s.resolved_ips ?? [],
  carved_files: s.carved_files ?? [],
  first_ts_ns: s.first_ts_ns,
  last_ts_ns: s.last_ts_ns,
});

describe("wasm hunt playbooks", () => {
  it("renders the fixture's top alert with filled pivots", () => {
    const alert = s.alerts![0];
    const runs = JSON.parse(alert_playbooks(slice, JSON.stringify(alert), "")) as PlaybookRun[];
    expect(runs.length).toBeGreaterThan(0);
    expect(runs[0].alert_id).toBe(alert.id);
    const text = JSON.stringify(runs);
    expect(text).not.toContain("{actor}");
    const md = playbook_markdown(JSON.stringify(runs), JSON.stringify({ done: [`${runs[0].playbook_id}/${runs[0].steps[0].id}`], notes: {} }));
    expect(md).toContain("# Hunt: ");
    expect(md).toContain("- [x] ");
  });

  it("applies a team file and rejects a bad one", () => {
    const team = JSON.stringify({
      version: 1,
      playbooks: [{ id: "ours", title: "Ours", kinds: s.findings!.map((f) => f.kind), steps: [{ id: "a", question: "Ticket {actor}", why: "Policy." }] }],
    });
    const runs = JSON.parse(alert_playbooks(slice, JSON.stringify(s.alerts![0]), team)) as PlaybookRun[];
    expect(runs.map((r) => r.playbook_id)).toEqual(["ours"]);
    expect(runs[0].origin).toBe("team playbooks");
    expect(() => alert_playbooks(slice, JSON.stringify(s.alerts![0]), '{"version":2,"playbooks":[]}')).toThrow(/version 2/);
  });

  it("lints and ships the built-ins", () => {
    const builtin = builtin_playbooks();
    const lint = JSON.parse(lint_playbooks(builtin));
    expect(lint.ok).toBe(true);
    expect(lint.playbooks).toBeGreaterThan(20);
    const bad = JSON.parse(lint_playbooks('{"version":1,"playbooks":[{"id":"x","title":"X","steps":[]}]}'));
    expect(bad.ok).toBe(false);
    expect(bad.problems.join(" ")).toContain("has no steps");
  });
});
