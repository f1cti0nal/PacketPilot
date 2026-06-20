import { describe, it, expect } from "vitest";
import { humanBytes, humanNumber, compactNumber, percent, durationHumanNs, shortHash, basename } from "./format";

describe("format", () => {
  it("humanBytes", () => {
    expect(humanBytes(0)).toBe("0 B");
    expect(humanBytes(5_700_000)).toBe("5.44 MB");
    expect(humanBytes(1024)).toBe("1.00 KB");
  });
  it("humanNumber / compactNumber", () => {
    expect(humanNumber(40000)).toBe("40,000");
    expect(compactNumber(40000)).toBe("40K");
  });
  it("percent (incl. zero total)", () => {
    expect(percent(1, 4)).toBe("25.0%");
    expect(percent(1, 0)).toBe("0%");
  });
  it("durationHumanNs", () => {
    expect(durationHumanNs(120_000_000_000)).toBe("2m 0.0s");
  });
  it("shortHash / basename", () => {
    expect(shortHash("abcdef0123456789", 4, 4)).toBe("abcd…6789");
    expect(basename("a/b/c.pcap")).toBe("c.pcap");
    expect(basename("a\\b\\c.pcap")).toBe("c.pcap");
  });
});
