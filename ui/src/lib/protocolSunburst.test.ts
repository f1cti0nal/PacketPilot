import { describe, it, expect } from "vitest";
import { buildSunburst } from "./protocolSunburst";
import type { ProtocolHierarchyNode } from "../types";

const h = (path: string, bytes: number, pkts = 1): ProtocolHierarchyNode => ({ path, bytes, pkts });

describe("buildSunburst", () => {
  it("builds rings from ip.l4.l7 leaf paths, accumulating prefixes, deterministically", () => {
    const nodes = [h("ip.tcp.https", 800), h("ip.tcp.http", 200), h("ip.udp.dns", 100)];
    const m = buildSunburst(nodes);
    expect(m.total).toBe(1100);

    const d1 = m.arcs.filter((a) => a.depth === 1).map((a) => a.path).sort();
    expect(d1).toEqual(["ip.tcp", "ip.udp"]);
    const d2 = m.arcs.filter((a) => a.depth === 2).map((a) => a.path).sort();
    expect(d2).toEqual(["ip.tcp.http", "ip.tcp.https", "ip.udp.dns"]);

    // tcp aggregates its children (800 + 200).
    const tcp = m.arcs.find((a) => a.path === "ip.tcp")!;
    expect(tcp.bytes).toBe(1000);
    expect(tcp.fraction).toBeCloseTo(1000 / 1100);

    expect(m.arcs.every((a) => a.d.startsWith("M"))).toBe(true);
    expect(buildSunburst(nodes)).toEqual(m); // deterministic
  });

  it("handles a single 100% protocol without a degenerate full-circle arc", () => {
    const m = buildSunburst([h("ip.tcp.https", 500)]);
    const tcp = m.arcs.find((a) => a.path === "ip.tcp")!;
    expect(tcp.fraction).toBeCloseTo(1);
    expect(tcp.d).toContain("A"); // a real arc was drawn
  });

  it("includes 2-level paths (no L7) as one ring-1 arc and skips non-ip paths", () => {
    const m = buildSunburst([h("ip.icmp", 300), h("arp", 50), h("ip.tcp.https", 700)]);
    expect(m.total).toBe(1000); // arp skipped (not ip-rooted)
    expect(m.arcs.find((a) => a.path === "ip.icmp")!.depth).toBe(1);
    expect(m.arcs.some((a) => a.path.startsWith("ip.icmp."))).toBe(false);
  });

  it("returns an empty model for no data", () => {
    expect(buildSunburst([]).arcs).toEqual([]);
    expect(buildSunburst([]).total).toBe(0);
  });
});
