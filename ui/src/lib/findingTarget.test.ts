import { describe, it, expect } from "vitest";
import { dstLabel, hasTarget } from "./findingTarget";

describe("dstLabel", () => {
  it("renders ip:port when a peer host and port are both named", () => {
    expect(dstLabel({ dst_ip: "8.8.8.8", dst_port: 443 })).toBe("8.8.8.8:443");
  });

  it("renders the bare ip when only a peer host is named (per-peer anomaly)", () => {
    expect(dstLabel({ dst_ip: "8.8.8.8", dst_port: null })).toBe("8.8.8.8");
  });

  it("renders 'port N' when only a service port is named (per-port anomaly / sweep / flood)", () => {
    // The old `dst_ip ? … : "—"` idiom dropped this to "—", hiding the attribution.
    expect(dstLabel({ dst_ip: null, dst_port: 4444 })).toBe("port 4444");
  });

  it("keeps port 0 (never happens in practice, but must not collapse to em dash)", () => {
    expect(dstLabel({ dst_ip: null, dst_port: 0 })).toBe("port 0");
  });

  it("renders an em dash for a pure fan-out finding with neither", () => {
    expect(dstLabel({ dst_ip: null, dst_port: null })).toBe("—");
  });
});

describe("hasTarget", () => {
  it("is true when a peer host or a service port is named", () => {
    expect(hasTarget({ dst_ip: "8.8.8.8", dst_port: null })).toBe(true);
    expect(hasTarget({ dst_ip: null, dst_port: 4444 })).toBe(true);
    expect(hasTarget({ dst_ip: null, dst_port: 0 })).toBe(true);
  });

  it("is false when a finding names no destination at all", () => {
    expect(hasTarget({ dst_ip: null, dst_port: null })).toBe(false);
  });
});
