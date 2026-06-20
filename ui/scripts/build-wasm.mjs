// Build the in-browser analysis engine: compile ../engine/crates/ppcap-wasm to wasm, then
// run wasm-bindgen to emit the JS bindings into src/wasm/.
//
// Prereqs (one-time):
//   rustup target add wasm32-unknown-unknown
//   cargo install wasm-bindgen-cli   # must match the wasm-bindgen crate version (0.2.x)
//
// Usage: npm run build:wasm   (from ui/)
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const uiDir = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const crate = resolve(uiDir, "../engine/crates/ppcap-wasm");
const wasmOut = resolve(
  crate,
  "target/wasm32-unknown-unknown/release/ppcap_wasm.wasm",
);
const outDir = resolve(uiDir, "src/wasm");

const run = (cmd, args) => {
  console.log(`$ ${cmd} ${args.join(" ")}`);
  execFileSync(cmd, args, { stdio: "inherit", cwd: uiDir });
};

run("cargo", [
  "build",
  "--release",
  "--target",
  "wasm32-unknown-unknown",
  "--manifest-path",
  resolve(crate, "Cargo.toml"),
]);
run("wasm-bindgen", [
  "--target",
  "web",
  "--out-dir",
  outDir,
  "--out-name",
  "ppcap_wasm",
  wasmOut,
]);
console.log("\n✓ wasm engine built → src/wasm/ppcap_wasm.js");
