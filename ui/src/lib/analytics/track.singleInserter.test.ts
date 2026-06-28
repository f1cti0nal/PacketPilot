import { describe, expect, it } from "vitest";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";

// Walk ui/src and assert that an INSERT into analytics_events appears in exactly one
// non-test source file: the tracker. This is the privacy single-inserter invariant.
function sourceFiles(dir: string, acc: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    const s = statSync(p);
    if (s.isDirectory()) {
      if (name !== "node_modules") sourceFiles(p, acc);
    } else if (/\.(ts|tsx)$/.test(name) && !/\.test\.(ts|tsx)$/.test(name)) {
      acc.push(p);
    }
  }
  return acc;
}

describe("analytics single-inserter invariant", () => {
  it("only track.ts inserts into analytics_events", () => {
    const root = join(process.cwd(), "src");
    const offenders = sourceFiles(root).filter((f) => {
      const normalized = readFileSync(f, "utf8").replace(/\s+/g, "");
      return /\.from\(["']analytics_events["']\)\.insert\(/.test(normalized);
    });
    expect(offenders.map((f) => f.replace(/\\/g, "/")).filter((f) => !f.endsWith("/lib/analytics/track.ts"))).toEqual([]);
  });
});
