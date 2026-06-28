import { describe, expect, it } from "vitest";
import { money, joinedDate, shortDay } from "./format";

describe("dashboard format helpers", () => {
  it("money: cents → whole-dollar string with separators", () => {
    expect(money(0)).toBe("$0");
    expect(money(5700)).toBe("$57");
    expect(money(199900)).toBe("$1,999");
  });
  it("joinedDate: ISO timestamp → YYYY-MM-DD", () => {
    expect(joinedDate("2026-06-25T12:30:00Z")).toBe("2026-06-25");
  });
  it("shortDay: YYYY-MM-DD → MM-DD", () => {
    expect(shortDay("2026-06-27")).toBe("06-27");
  });
});
