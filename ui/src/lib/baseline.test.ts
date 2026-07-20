import { beforeEach, describe, expect, it, vi } from "vitest";

// Stub the wasm layer so the pure-localStorage helpers can be tested without instantiating wasm.
vi.mock("./wasmEngine", () => ({
  buildBaselineViaWasm: vi.fn(),
  compareToBaselineViaWasm: vi.fn(),
}));

import type { BaselineProfile } from "../types";
import { clearBaseline, forgetHost, hasBaseline, loadBaseline, saveBaseline } from "./baseline";

const profile = (hosts: string[]): BaselineProfile => ({
  schema_version: 1,
  engine_version: "t",
  first_analyzed_unix_secs: 0,
  last_analyzed_unix_secs: 0,
  first_ts_ns: 0,
  last_ts_ns: 0,
  hosts: hosts.map((h) => ({
    host: h,
    captures_seen: 3,
    bytes_out: { count: 3, mean: 1, m2: 0, min: 1, max: 1, ewma: 1 },
    bytes_in: { count: 3, mean: 0, m2: 0, min: 0, max: 0, ewma: 0 },
    flows: { count: 3, mean: 1, m2: 0, min: 1, max: 1, ewma: 1 },
    peers: [],
    services: [],
    first_seen_unix: 0,
    last_seen_unix: 0,
  })),
});

describe("baseline local persistence", () => {
  beforeEach(() => localStorage.clear());

  it("round-trips save/load and reports presence", () => {
    expect(loadBaseline()).toBeNull();
    expect(hasBaseline()).toBe(false);
    saveBaseline(profile(["10.0.0.5"]));
    expect(hasBaseline()).toBe(true);
    expect(loadBaseline()?.hosts[0].host).toBe("10.0.0.5");
  });

  it("clear removes the saved profile", () => {
    saveBaseline(profile(["10.0.0.5"]));
    clearBaseline();
    expect(loadBaseline()).toBeNull();
  });

  it("forgetHost drops exactly one host and persists", () => {
    saveBaseline(profile(["10.0.0.5", "10.0.0.6"]));
    const next = forgetHost("10.0.0.5");
    expect(next?.hosts.map((h) => h.host)).toEqual(["10.0.0.6"]);
    expect(loadBaseline()?.hosts.length).toBe(1);
  });

  it("returns null on corrupt storage rather than throwing", () => {
    localStorage.setItem("packetpilot.baseline.v1::anon", "{not valid json");
    expect(loadBaseline()).toBeNull();
  });
});
