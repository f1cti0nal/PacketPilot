import { describe, expect, it } from "vitest";

import { DEFAULT_ROW_LIMIT, guardSql } from "./guard.ts";

const allowed = (sql: string) => {
  const r = guardSql(sql);
  expect(r.ok, `should allow: ${sql}${r.ok ? "" : ` (got: ${r.reason})`}`).toBe(true);
  if (!r.ok) throw new Error("unreachable");
  return r;
};

const denied = (sql: string) => {
  const r = guardSql(sql);
  expect(r.ok, `should deny: ${sql}`).toBe(false);
  if (r.ok) throw new Error("unreachable");
  return r;
};

describe("guardSql — allowed queries", () => {
  it("plain SELECT gets the default LIMIT appended", () => {
    const r = allowed("SELECT * FROM flow");
    expect(r.sql).toBe(`SELECT * FROM flow LIMIT ${DEFAULT_ROW_LIMIT}`);
    expect(r.limitApplied).toBe(true);
  });

  it("an explicit top-level LIMIT is kept as-is", () => {
    const r = allowed("select src_ip, count(*) from flow group by 1 limit 10");
    expect(r.sql).toBe("select src_ip, count(*) from flow group by 1 limit 10");
    expect(r.limitApplied).toBe(false);
  });

  it("a LIMIT only inside a subquery still gets the outer LIMIT", () => {
    const r = allowed("SELECT * FROM (SELECT * FROM flow LIMIT 5) t");
    expect(r.limitApplied).toBe(true);
    expect(r.sql.endsWith(`LIMIT ${DEFAULT_ROW_LIMIT}`)).toBe(true);
  });

  it("WITH … SELECT (CTE) is allowed", () => {
    allowed("WITH t AS (SELECT src_ip FROM flow) SELECT * FROM t");
  });

  it("denied words inside string literals do not trip the guard", () => {
    allowed("SELECT * FROM flow WHERE sni = 'drop table; create load set'");
  });

  it("escaped quotes ('') stay inside the string", () => {
    allowed("SELECT * FROM flow WHERE http_ua = 'it''s; drop table'");
  });

  it("denied words inside comments do not trip the guard", () => {
    const r = allowed("SELECT 1 -- drop table flow");
    expect(r.sql.startsWith("SELECT 1")).toBe(true);
  });

  it("nested block comments are stripped", () => {
    allowed("/* outer /* inner drop */ still comment */ SELECT 1");
  });

  it("a trailing semicolon is fine", () => {
    allowed("SELECT 1;");
  });

  it("double-quoted identifiers are not tokenized", () => {
    allowed('SELECT "drop" FROM flow');
  });
});

describe("guardSql — denied queries", () => {
  it("empty / comment-only input", () => {
    expect(denied("").reason).toMatch(/empty/i);
    expect(denied("   \n").reason).toMatch(/empty/i);
    expect(denied("-- just a comment").reason).toMatch(/empty/i);
  });

  it("multiple statements", () => {
    expect(denied("SELECT 1; SELECT 2").reason).toMatch(/single statement/i);
    expect(denied("SELECT 1; DROP TABLE flow").reason).toMatch(/single statement/i);
  });

  it("non-SELECT statement prefixes", () => {
    for (const sql of [
      "DROP TABLE flow",
      "INSERT INTO flow VALUES (1)",
      "UPDATE flow SET ioc = true",
      "DELETE FROM flow",
      "CREATE TABLE x AS SELECT 1",
      "ALTER TABLE flow ADD COLUMN x INT",
      "PRAGMA version",
      "SET enable_external_access = true",
      "ATTACH 'x.db'",
      "COPY flow TO 'out.csv'",
      "EXPORT DATABASE 'dir'",
      "INSTALL httpfs",
      "LOAD httpfs",
      "CALL pragma_table_info('flow')",
      "CHECKPOINT",
      "VACUUM",
      "BEGIN TRANSACTION",
      "EXPLAIN SELECT 1",
      "DESCRIBE flow",
    ]) {
      expect(denied(sql).reason).toMatch(/read-only|SELECT/);
    }
  });

  it("denied words embedded in a SELECT are caught as tokens", () => {
    expect(denied("SELECT * FROM flow WHERE (DELETE FROM flow)").reason).toMatch(/DELETE/);
    expect(denied("SELECT set FROM flow").reason).toMatch(/SET/);
    expect(denied("WITH t AS (SELECT 1) INSERT INTO flow SELECT * FROM t").reason).toMatch(
      /INSERT/,
    );
  });
});
