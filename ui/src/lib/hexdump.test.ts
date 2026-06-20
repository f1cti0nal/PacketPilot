import { describe, it, expect } from "vitest";
import { hexLines } from "./hexdump";
describe("hexLines", () => {
  it("formats one full row", () => {
    const bytes = new TextEncoder().encode("GET / HTTP/1.1\r\n"); // 16 bytes
    const rows = hexLines(bytes);
    expect(rows.length).toBe(1);
    const [row] = rows;
    expect(row.offset).toBe("00000000");
    expect(row.hex).toBe("47 45 54 20 2f 20 48 54 54 50 2f 31 2e 31 0d 0a");
    expect(row.ascii).toBe("GET / HTTP/1.1..");
  });
  it("renders non-printables as dots and splits at 16 bytes", () => {
    const bytes = new Uint8Array(20).map((_, i) => i);
    const rows = hexLines(bytes);
    expect(rows.length).toBe(2);
    expect(rows[0].offset).toBe("00000000");
    expect(rows[0].hex).toBe("00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f");
    expect(rows[1].offset).toBe("00000010");
    expect(rows[1].hex).toBe("10 11 12 13");
    expect(rows[1].ascii).toBe("....");
  });
  it("empty input → no rows", () => { expect(hexLines(new Uint8Array())).toEqual([]); });
});
