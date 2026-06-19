// Generates a 1024x1024 RGBA PNG app icon (PacketPilot radar/target motif) with no image
// deps — raw PNG via Node's built-in zlib. Output path is argv[2]. `tauri icon` then derives
// every platform size from it.
import zlib from "node:zlib";
import fs from "node:fs";

const W = 1024,
  H = 1024;
const BG = [10, 14, 20, 255]; // brand surface #0a0e14
const ACCENT = [56, 189, 248, 255]; // #38bdf8
const ACCENT2 = [14, 165, 233, 255]; // #0ea5e9

function pixel(x, y) {
  const cx = W / 2,
    cy = H / 2;
  const dx = x - cx,
    dy = y - cy;
  const r = Math.sqrt(dx * dx + dy * dy);
  for (const rr of [360, 250, 140]) if (Math.abs(r - rr) < 11) return ACCENT;
  if (r < 48) return ACCENT;
  const ang = Math.atan2(dy, dx);
  if (r < 372 && Math.abs(ang + Math.PI / 4) < 0.045) return ACCENT2; // sweep spoke
  return BG;
}

const raw = Buffer.alloc((W * 4 + 1) * H);
let o = 0;
for (let y = 0; y < H; y++) {
  raw[o++] = 0; // filter: none
  for (let x = 0; x < W; x++) {
    const p = pixel(x, y);
    raw[o++] = p[0];
    raw[o++] = p[1];
    raw[o++] = p[2];
    raw[o++] = p[3];
  }
}

function crc32(buf) {
  let c = ~0;
  for (let i = 0; i < buf.length; i++) {
    c ^= buf[i];
    for (let k = 0; k < 8; k++) c = (c >>> 1) ^ (0xedb88320 & -(c & 1));
  }
  return (~c) >>> 0;
}
function chunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length, 0);
  const t = Buffer.from(type, "ascii");
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(Buffer.concat([t, data])), 0);
  return Buffer.concat([len, t, data, crc]);
}

const ihdr = Buffer.alloc(13);
ihdr.writeUInt32BE(W, 0);
ihdr.writeUInt32BE(H, 4);
ihdr[8] = 8; // bit depth
ihdr[9] = 6; // color type RGBA
const png = Buffer.concat([
  Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]),
  chunk("IHDR", ihdr),
  chunk("IDAT", zlib.deflateSync(raw, { level: 9 })),
  chunk("IEND", Buffer.alloc(0)),
]);
const out = process.argv[2] || "icon-source.png";
fs.writeFileSync(out, png);
console.log("wrote", out, png.length, "bytes");
