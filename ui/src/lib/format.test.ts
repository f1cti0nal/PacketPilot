import { describe, it, expect } from "vitest";
import { humanBytes, humanNumber, compactNumber, percent, durationHumanNs, durationHumanMs, msToTime, nsToTime, nsToDateTime, localTzLabel, shortHash, basename } from "./format";

const p2 = (n: number) => String(n).padStart(2, "0");
const p3 = (n: number) => String(n).padStart(3, "0");

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
  it("time helpers render LOCAL time (tz-independent assertions)", () => {
    // Times now render in the browser's local timezone (to match the analyst's Wireshark view),
    // so assert against the same local getters rather than a fixed UTC string.
    const ms = 1_700_000_000_000;
    const d = new Date(ms);
    const hms = `${p2(d.getHours())}:${p2(d.getMinutes())}:${p2(d.getSeconds())}`;
    expect(msToTime(ms)).toBe(`${hms}.${p3(d.getMilliseconds())}`);
    expect(nsToTime(ms * 1e6)).toBe(hms);
    // nsToDateTime is "YYYY-MM-DD HH:MM:SS <TZ>" with a non-empty tz label.
    const dt = nsToDateTime(ms * 1e6);
    expect(dt).toMatch(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} .+$/);
    expect(dt.endsWith(localTzLabel)).toBe(true);
    expect(localTzLabel.length).toBeGreaterThan(0);
  });
});
