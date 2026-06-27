import { describe, it, expect } from "vitest";
import { flowsToCsv } from "./flowsCsv";
import { makeFlows } from "../test/fixtures";
import type { FlowRow } from "../types";

describe("flowsToCsv", () => {
  it("emits a header row plus one row per flow", () => {
    const lines = flowsToCsv(makeFlows(3)).split("\r\n");
    expect(lines).toHaveLength(4); // header + 3
    expect(lines[0]).toContain("flow_id");
    expect(lines[0]).toContain("src_ip");
    expect(lines[0]).toContain("hassh_server");
  });

  it("includes key flow fields in each row", () => {
    const csv = flowsToCsv(makeFlows(1));
    expect(csv).toContain("10.0.0.1"); // srcIp
    expect(csv).toContain("443"); // dstPort
    expect(csv).toContain("TCP"); // protoLabel
  });

  it("escapes fields containing commas or quotes", () => {
    const [row] = makeFlows(1);
    const dirty: FlowRow = { ...row, httpUa: 'Mozilla, "Evil"/1.0' };
    expect(flowsToCsv([dirty])).toContain('"Mozilla, ""Evil""/1.0"');
  });

  it("returns just the header for no rows", () => {
    expect(flowsToCsv([]).split("\r\n")).toHaveLength(1);
  });
});
