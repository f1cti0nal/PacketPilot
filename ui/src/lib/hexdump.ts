export interface HexLine { offset: string; hex: string; ascii: string }
const BYTES_PER_ROW = 16;
export function hexLines(bytes: Uint8Array): HexLine[] {
  const rows: HexLine[] = [];
  for (let off = 0; off < bytes.length; off += BYTES_PER_ROW) {
    const slice = bytes.subarray(off, off + BYTES_PER_ROW);
    const hex = Array.from(slice, (b) => b.toString(16).padStart(2, "0")).join(" ");
    const ascii = Array.from(slice, (b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : ".")).join("");
    rows.push({ offset: off.toString(16).padStart(8, "0"), hex, ascii });
  }
  return rows;
}
