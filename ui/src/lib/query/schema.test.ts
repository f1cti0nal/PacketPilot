import { describe, expect, it } from "vitest";

import { FLOW_COLUMNS } from "../../types";
import fixture from "./flow_columns.json";
import {
  FLOW_CATEGORY_TOKENS,
  FLOW_COLUMN_TYPES,
  FLOW_SCHEMA_VERSION,
  FLOW_SEVERITY_TOKENS,
  FLOW_TABLE_DDL,
} from "./schema";

describe("flow schema drift guard (UI side)", () => {
  it("FLOW_COLUMNS has all 31 canonical columns", () => {
    expect(FLOW_COLUMNS).toHaveLength(31);
  });

  it("FLOW_COLUMNS matches the shared fixture exactly (names and order)", () => {
    expect([...FLOW_COLUMNS]).toEqual(fixture.columns);
  });

  it("schema version matches the fixture", () => {
    expect(FLOW_SCHEMA_VERSION).toBe(fixture.flow_schema_version);
  });

  it("FLOW_COLUMN_TYPES covers exactly the canonical columns", () => {
    expect(Object.keys(FLOW_COLUMN_TYPES).sort()).toEqual([...FLOW_COLUMNS].sort());
  });
});

describe("FLOW_TABLE_DDL", () => {
  const ddlColumns = (): { name: string; notNull: boolean }[] => {
    const body = FLOW_TABLE_DDL.slice(
      FLOW_TABLE_DDL.indexOf("(") + 1,
      FLOW_TABLE_DDL.lastIndexOf(")"),
    );
    return body
      .split(",")
      .map((line) => line.trim())
      .filter((line) => line.length > 0)
      .map((line) => ({
        name: line.split(/\s+/)[0],
        notNull: /\bNOT NULL$/.test(line),
      }));
  };

  it("lists the canonical columns in canonical order", () => {
    expect(ddlColumns().map((c) => c.name)).toEqual([...FLOW_COLUMNS]);
  });

  it("NOT NULL agrees with the nullability spec", () => {
    for (const col of ddlColumns()) {
      expect(col.notNull, col.name).toBe(
        !FLOW_COLUMN_TYPES[col.name as keyof typeof FLOW_COLUMN_TYPES].nullable,
      );
    }
  });

  it("is a single CREATE TABLE statement for `flow`", () => {
    expect(FLOW_TABLE_DDL.startsWith("CREATE TABLE flow (")).toBe(true);
    expect(FLOW_TABLE_DDL.trimEnd().endsWith(");")).toBe(true);
  });
});

describe("token lists", () => {
  it("category tokens are non-empty snake_case", () => {
    expect(FLOW_CATEGORY_TOKENS.length).toBeGreaterThan(0);
    for (const token of FLOW_CATEGORY_TOKENS) {
      expect(token).toMatch(/^[a-z][a-z0-9_]*$/);
    }
  });

  it("severity tokens are the five engine levels", () => {
    expect([...FLOW_SEVERITY_TOKENS]).toEqual(["critical", "high", "medium", "low", "info"]);
  });
});
