import { describe, it, expect } from "vitest";
import { hexLines } from "./hexdump";
describe("hexLines", () => {
  it("formats one full row", () => {
    const bytes = new Uint8Array([0x47, 0x45, 0x54, 0x20]); // "GET "
    const [row] = hexLines(bytes);
    expect(row.offset).toBe("00000000");
    expect(row.hex.startsWith("47 45 54 20")).toBe(true);
    expect(row.ascii.startsWith("GET ")).toBe(true);
  });
  it("renders non-printables as dots and splits at 16 bytes", () => {
    const bytes = new Uint8Array(20).map((_, i) => i);
    const rows = hexLines(bytes);
    expect(rows.length).toBe(2);
    expect(rows[1].offset).toBe("00000010");
    expect(rows[0].ascii).toContain("."); // 0x00 etc. → "."
  });
  it("empty input → no rows", () => { expect(hexLines(new Uint8Array())).toEqual([]); });
});
