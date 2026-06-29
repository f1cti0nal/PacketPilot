/// <reference lib="webworker" />
// Web Worker: runs the heavy WASM `analyze` OFF the main thread so a large capture's multi-second
// analysis never freezes the UI. The capture bytes are TRANSFERRED in (zero-copy); because the main
// thread gives them up, the worker also computes the provenance SHA-256 and returns it with the
// summary JSON. A "ping" → "ready"/"init-failed" handshake lets the main thread detect an
// unavailable worker environment (no WASM in worker, blocked by CSP, etc.) and fall back to
// main-thread analysis BEFORE it transfers anything.
import initWasm, { analyze as wasmAnalyze } from "../wasm/ppcap_wasm.js";

const ctx = self as unknown as DedicatedWorkerGlobalScope;

let ready: Promise<unknown> | null = null;
const ensureWasm = () => (ready ??= initWasm());

// Lowercase-hex SHA-256, byte-for-byte identical to lib/recent.ts `sha256Hex`, so a capture's
// identity (Recent list key) is the same whether it was analyzed in the worker or on the main thread.
async function sha256Hex(bytes: ArrayBuffer): Promise<string | null> {
  try {
    if (!ctx.crypto?.subtle) return null;
    const digest = await ctx.crypto.subtle.digest("SHA-256", bytes);
    return Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, "0")).join("");
  } catch {
    return null;
  }
}

ctx.onmessage = async (e: MessageEvent) => {
  const msg = e.data;
  if (msg?.type === "ping") {
    try {
      await ensureWasm();
      ctx.postMessage({ type: "ready" });
    } catch (err) {
      ctx.postMessage({ type: "init-failed", error: String((err as Error)?.message ?? err) });
    }
    return;
  }
  if (msg?.type === "analyze") {
    const { id, bytes, name } = msg as { id: number; bytes: ArrayBuffer; name: string };
    try {
      await ensureWasm();
      const sha256 = await sha256Hex(bytes);
      const json = wasmAnalyze(new Uint8Array(bytes), name) as string;
      ctx.postMessage({ id, ok: true, json, sha256 });
    } catch (err) {
      ctx.postMessage({ id, ok: false, error: String((err as Error)?.message ?? err) });
    }
  }
};
