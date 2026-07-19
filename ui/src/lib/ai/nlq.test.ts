import { describe, expect, it } from "vitest";

import { FLOW_COLUMNS } from "../../types";
import { guardSql } from "../query/guard";
import { buildNlqSystemPrompt, parseNlqResponse } from "./nlq";

describe("buildNlqSystemPrompt", () => {
  const prompt = buildNlqSystemPrompt();

  it("stays well under the proxy content cap (≤ 8 KiB)", () => {
    expect(new TextEncoder().encode(prompt).length).toBeLessThanOrEqual(8 * 1024);
  });

  it("teaches every canonical column and the token lists", () => {
    for (const name of FLOW_COLUMNS) expect(prompt).toContain(name);
    expect(prompt).toContain("file_transfer");
    expect(prompt).toContain("critical, high, medium, low, info");
  });

  it("contains the output contract markers", () => {
    expect(prompt).toContain("-- intent:");
    expect(prompt).toContain("-- error:");
  });

  it("every few-shot SQL answer passes the read-only guard", () => {
    // Answers follow "Q: ..." lines; SQL ones start with the intent comment.
    const answers = prompt
      .split(/\nQ: [^\n]+\n/)
      .slice(1)
      .map((block) => block.split("\n\n", 1)[0].trim())
      .filter((a) => a.startsWith("-- intent:"));
    expect(answers.length).toBeGreaterThanOrEqual(3);
    for (const sql of answers) {
      const r = guardSql(sql);
      expect(r.ok, `few-shot should pass guard:\n${sql}`).toBe(true);
    }
  });
});

describe("parseNlqResponse", () => {
  it("parses the contract shape: intent line + SQL", () => {
    const r = parseNlqResponse("-- intent: count flows\nSELECT COUNT(*) FROM flow");
    expect(r).toEqual({
      kind: "sql",
      sql: "-- intent: count flows\nSELECT COUNT(*) FROM flow",
      intent: "count flows",
    });
  });

  it("tolerates code fences despite the contract", () => {
    const r = parseNlqResponse("```sql\n-- intent: x\nSELECT 1\n```");
    expect(r.kind).toBe("sql");
    if (r.kind === "sql") {
      expect(r.sql).toBe("-- intent: x\nSELECT 1");
      expect(r.intent).toBe("x");
    }
  });

  it("accepts SQL without an intent line", () => {
    const r = parseNlqResponse("SELECT 1");
    expect(r).toEqual({ kind: "sql", sql: "SELECT 1", intent: null });
  });

  it("maps the error marker to a user-facing error", () => {
    const r = parseNlqResponse("-- error: payloads are not queryable");
    expect(r).toEqual({ kind: "error", message: "payloads are not queryable" });
  });

  it("rejects empty replies", () => {
    expect(parseNlqResponse("").kind).toBe("error");
    expect(parseNlqResponse("```sql\n\n```").kind).toBe("error");
  });
});
