import { describe, it, expect } from "vitest";
import { humanBytes, humanNumber, compactNumber, percent, durationHumanNs, durationHumanMs, msToTime, shortHash, basename } from "./format";

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
  it("durationHumanMs covers ms, seconds, minutes, and hours branches", () => {
    expect(durationHumanMs(0)).toBe("0 ms");
    expect(durationHumanMs(0.5)).toBe("1 ms"); // toFixed(0) rounds 0.5 up to "1"
    expect(durationHumanMs(5_000)).toBe("5.00s");
    expect(durationHumanMs(90_000)).toBe("1m 30.0s");
    // hours branch: 2 hours 5 minutes
    expect(durationHumanMs(2 * 3_600_000 + 5 * 60_000)).toBe("2h 5m");
    expect(durationHumanMs(Infinity)).toBe("—");
  });
  it("msToTime formats millisecond epoch as HH:MM:SS.mmm", () => {
    // Just check it returns a string with colons
    const result = msToTime(1_700_000_000_000);
    expect(typeof result).toBe("string");
    expect(result).toMatch(/\d{2}:\d{2}:\d{2}/);
  });
});
