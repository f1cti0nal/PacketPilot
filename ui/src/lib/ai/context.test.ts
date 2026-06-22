import { describe, it, expect } from "vitest";
import { buildContext } from "./context";
import { makeOutput } from "../../test/fixtures";

describe("buildContext", () => {
  it("includes capture metadata, severity, and top incidents/threats; never raw flows", () => {
    const out = makeOutput();
    const ctx = buildContext(out);
    expect(ctx).toContain("# PacketPilot analysis summary");
    expect(ctx.toLowerCase()).toContain("severity");
    // incidents from the fixture appear by host
    const firstIncident = out.summary.incidents?.[0];
    if (firstIncident) expect(ctx).toContain(firstIncident.host);
    // no raw-flow leakage markers
    expect(ctx).not.toContain("payload");
    // bounded: stays compact even with many threats
    expect(ctx.length).toBeLessThan(20000);
  });

  it("is resilient to missing optional sections", () => {
    const out = makeOutput();
    out.summary.incidents = undefined;
    out.summary.ip_threats = undefined;
    expect(() => buildContext(out)).not.toThrow();
  });
});
