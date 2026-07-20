import { describe, expect, it } from "vitest";

import { guardSql } from "./guard";
import { SAMPLE_QUERIES } from "./samples";

describe("bundled sample queries", () => {
  it("every sample passes the read-only guard", () => {
    for (const sample of SAMPLE_QUERIES) {
      const r = guardSql(sample.sql);
      expect(r.ok, `${sample.id} (${sample.label}) should pass the guard`).toBe(true);
    }
  });

  it("ids and labels are unique and non-empty", () => {
    const ids = SAMPLE_QUERIES.map((s) => s.id);
    expect(new Set(ids).size).toBe(ids.length);
    for (const s of SAMPLE_QUERIES) {
      expect(s.label.trim().length).toBeGreaterThan(0);
      expect(s.sql.trim().length).toBeGreaterThan(0);
    }
  });

  it("the cross-filter sample exposes flow_id", () => {
    const flagged = SAMPLE_QUERIES.find((s) => s.id === "flagged");
    expect(flagged?.sql).toContain("flow_id");
  });
});
