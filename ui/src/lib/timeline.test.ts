import { describe, it, expect } from "vitest";
import { bpfFor, carveFileName, carveQueryFor, filterByHosts, kindLabel, laneColor, offsetLabel, pickTimeline } from "./timeline";
import { makeOutput } from "../test/fixtures";

const timelines = () => makeOutput().summary.timelines!;

describe("timeline helpers", () => {
  it("maps a row scope to the carve request, omitting unset narrowing", () => {
    expect(carveQueryFor({ host: "10.0.0.1", peer: "8.8.8.8", port: 53, start_ns: 1, end_ns: 2 })).toEqual({
      host: "10.0.0.1", peer: "8.8.8.8", port: 53, start_ns: 1, end_ns: 2,
    });
    const bare = carveQueryFor({ host: "10.0.0.1", peer: null, port: null, start_ns: 1, end_ns: 2 });
    expect(bare).toEqual({ host: "10.0.0.1", start_ns: 1, end_ns: 2 });
    expect("peer" in bare).toBe(false);
  });

  it("renders the same capture filter the engine prints", () => {
    expect(bpfFor({ host: "10.0.0.1", start_ns: 0, end_ns: 0 })).toBe("host 10.0.0.1");
    expect(bpfFor({ host: "10.0.0.1", peer: "8.8.8.8", port: 0, start_ns: 0, end_ns: 0 })).toBe(
      "host 10.0.0.1 and host 8.8.8.8 and port 0",
    );
  });

  it("names carved files safely (IPv6 colons replaced)", () => {
    const e = timelines()[0].events[3];
    expect(carveFileName(e)).toBe("detection_10.66.0.1_45.77.13.37_p443_1700000010.pcap");
    expect(carveFileName({ ...e, packets: { host: "fe80::1", start_ns: 0, end_ns: 0 } })).toBe("detection_fe80--1_0.pcap");
  });

  it("formats offsets from the timeline start", () => {
    expect(offsetLabel(5e6, 0)).toBe("+5ms");
    expect(offsetLabel(2.5e9, 0)).toBe("+2.50s");
    expect(offsetLabel(125e9, 0)).toBe("+2m 5s");
    expect(offsetLabel(3_725e9, 0)).toBe("+1h 2m");
    expect(offsetLabel(null, 0)).toBe("");
  });

  it("filters rows touching a host as actor or peer", () => {
    const ev = timelines()[0].events;
    expect(filterByHosts(ev, new Set())).toHaveLength(4);
    // 10.13.37.7 owns the sweep and is the peer of the lateral hop.
    expect(filterByHosts(ev, new Set(["10.13.37.7"])).map((e) => e.kind)).toEqual(["detection", "pivot"]);
  });

  it("picks the focused timeline, else the top alert's", () => {
    const t = timelines();
    expect(pickTimeline(t, "alert:00c0ffee00c0ffee")?.alert_id).toBe("alert:00c0ffee00c0ffee");
    expect(pickTimeline(t, "alert:missing")?.alert_id).toBe(t[0].alert_id);
    expect(pickTimeline([], null)).toBeNull();
  });

  it("labels kinds and gives each host a stable lane colour", () => {
    expect(kindLabel("pivot")).toBe("Lateral hop");
    const hosts = ["a", "b"];
    expect(laneColor(hosts, "a")).not.toBe(laneColor(hosts, "b"));
    expect(laneColor(hosts, "a")).toBe(laneColor(hosts, "a"));
  });
});
