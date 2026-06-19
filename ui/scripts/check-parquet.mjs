// Headless data-path smoke test. Proves the in-browser parquet path works
// without a browser by using the SAME hyparquet API as src/lib/data.ts.
//
// Run:  node scripts/check-parquet.mjs
//
// Mirrors src/lib/data.ts: Snappy is built into hyparquet, so NO `compressors`
// option is passed; rowFormat: "object".
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { parquetReadObjects } from "hyparquet";

const __dirname = dirname(fileURLToPath(import.meta.url));
const parquetPath = resolve(__dirname, "../public/sample/flows.parquet");

// hyparquet wants an AsyncBuffer ({ byteLength, slice }). A Node Buffer's
// underlying ArrayBuffer gives us exactly that, same shape as the ArrayBuffer
// branch of toAsyncBuffer() in src/lib/data.ts.
const buf = await readFile(parquetPath);
const ab = buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
const file = { byteLength: ab.byteLength, slice: (s, e) => ab.slice(s, e) };

const rows = await parquetReadObjects({ file, rowFormat: "object" });

console.log("row count:", rows.length);
console.log("columns:", Object.keys(rows[0]).join(", "));
console.log("first row:", rows[0]);
