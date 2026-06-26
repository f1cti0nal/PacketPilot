import { describe, it, expect } from "vitest";
import { tcpFlagsLabel } from "./tcpFlags";

describe("tcpFlagsLabel", () => {
  it("returns an em-dash for no flags", () => {
    expect(tcpFlagsLabel(0)).toBe("—");
  });

  it("decodes SYN+ACK", () => {
    expect(tcpFlagsLabel(0x12)).toBe("SYN ACK");
  });

  it("decodes the ECN flags ECE + CWR (which the inspector's old copy dropped)", () => {
    expect(tcpFlagsLabel(0x40)).toBe("ECE");
    expect(tcpFlagsLabel(0x80)).toBe("CWR");
  });

  it("decodes all 8 bits in canonical order", () => {
    expect(tcpFlagsLabel(0xff)).toBe("FIN SYN RST PSH ACK URG ECE CWR");
  });
});
