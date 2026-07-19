import { describe, expect, it } from "vitest";

import type { QueryResult } from "./engine";
import { formatCell, isTimestampColumn, resultsToCsv } from "./results";

const col = (name: string, type: string) => ({ name, type });

describe("formatCell", () => {
  it("formats timestamps (epoch ms) as UTC date-times", () => {
    const c = col("bucket", "Timestamp<MICROSECOND, UTC>");
    expect(isTimestampColumn(c)).toBe(true);
    expect(formatCell(1752900000000, c)).toBe("2025-07-19 04:40:00.000");
  });

  it("passes scalars through as strings and nulls as empty", () => {
    const utf8 = col("sni", "Utf8");
    expect(formatCell("example.com", utf8)).toBe("example.com");
    expect(formatCell(null, utf8)).toBe("");
    expect(formatCell(undefined, utf8)).toBe("");
    expect(formatCell(42n, col("flows", "Int64"))).toBe("42");
    expect(formatCell(true, col("ioc", "Bool"))).toBe("true");
  });

  it("renders nested values as JSON (bigint-safe)", () => {
    expect(formatCell({ a: 1n }, col("x", "Struct"))).toBe('{"a":"1"}');
  });
});

describe("resultsToCsv", () => {
  const result: QueryResult = {
    columns: [col("ip", "Utf8"), col("bytes", "Decimal"), col("note", "Utf8")],
    rows: [
      ["10.0.0.1", 10000n, 'has "quotes", commas\nand newlines'],
      ["10.0.0.2", 280n, null],
    ],
    rowCount: 2,
    truncated: false,
    limitApplied: false,
    elapsedMs: 3,
  };

  it("emits a header and RFC-4180-escaped rows", () => {
    expect(resultsToCsv(result)).toBe(
      'ip,bytes,note\n10.0.0.1,10000,"has ""quotes"", commas\nand newlines"\n10.0.0.2,280,\n',
    );
  });
});
