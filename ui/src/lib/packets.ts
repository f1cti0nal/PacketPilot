import { invoke } from "@tauri-apps/api/core";
import { save } from "@tauri-apps/plugin-dialog";
import type { ActiveSource, CarveQuery, FlowPackets, FlowRow, PacketRow, TlsDecryptRecord, TlsDecryptResult, WireFlowPackets, WireTlsDecryptResult } from "../types";
import type { ExportResult } from "./platform";
import { isTauri, extractPacketsViaTauri, downloadBinary } from "./platform";
import { extractPacketsViaWasm, carvePcapViaWasm, decryptTlsFlowViaWasm } from "./wasmEngine";

export class PacketsUnavailableError extends Error {
  constructor() { super("Packets are only available for captures analyzed from a pcap."); this.name = "PacketsUnavailableError"; }
}

export function packetsAvailable(source: ActiveSource): boolean { return source !== null; }

function queryFor(flow: FlowRow) {
  return {
    src_ip: flow.srcIp, dst_ip: flow.dstIp, src_port: flow.srcPort, dst_port: flow.dstPort,
    proto: flow.proto, start_ns: flow.startMs * 1_000_000, end_ns: flow.endMs * 1_000_000,
  };
}

function b64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function normalize(wire: WireFlowPackets, flow: FlowRow): FlowPackets {
  const startNs = flow.startMs * 1_000_000;
  const packets: PacketRow[] = wire.packets.map((p) => ({
    index: p.index, tsNs: p.ts_ns, relMs: Math.max(0, (p.ts_ns - startNs) / 1e6),
    direction: p.direction, wireLen: p.wire_len, capLen: p.cap_len,
    tcpFlags: p.tcp_flags, seq: p.seq, ack: p.ack,
    payloadLen: p.payload_len, payload: b64ToBytes(p.payload_b64), payloadTruncated: p.payload_truncated,
  }));
  return { total: wire.total, truncated: wire.truncated, packets };
}

function normalizeDecrypt(wire: WireTlsDecryptResult): TlsDecryptResult {
  const records: TlsDecryptRecord[] = wire.records.map((r) => ({
    direction: r.direction, seq: r.seq, innerType: r.inner_type, plaintext: b64ToBytes(r.plaintext_b64),
  }));
  return {
    supported: wire.supported, sessionFound: wire.session_found,
    version: wire.version, cipher: wire.cipher, cipherName: wire.cipher_name,
    keylogSessions: wire.keylog_sessions, truncated: wire.truncated, reason: wire.reason, records,
  };
}

/**
 * Decrypt a single TLS 1.3 flow using the analyst's NSS key-log (`SSLKEYLOGFILE` text).
 * Browser-only (WASM path): the capture and the key-log both stay in the page. Only
 * `TLS_AES_128_GCM_SHA256` is decrypted in this build — other suites come back with
 * `supported: false` and an explaining `reason`.
 */
export async function decryptTlsFlow(source: ActiveSource, flow: FlowRow, keylogText: string): Promise<TlsDecryptResult> {
  if (!source) throw new PacketsUnavailableError();
  if (source.kind !== "bytes") {
    throw new Error("TLS key-log decryption is available in the browser build.");
  }
  const wire = await decryptTlsFlowViaWasm(source.bytes, queryFor(flow), keylogText);
  return normalizeDecrypt(wire);
}

export async function extractFlowPackets(source: ActiveSource, flow: FlowRow): Promise<FlowPackets> {
  if (!source) throw new PacketsUnavailableError();
  if (source.kind === "path" && !isTauri()) {
    throw new Error("Path-based packet sources require the Tauri desktop runtime.");
  }
  const query = queryFor(flow);
  const wire = source.kind === "path" && isTauri()
    ? await extractPacketsViaTauri(source.path, query)
    : source.kind === "bytes"
      ? await extractPacketsViaWasm(source.bytes, query)
      : (() => { throw new PacketsUnavailableError(); })();
  return normalize(wire as WireFlowPackets, flow);
}

const UNAVAILABLE_MESSAGE = "Packets are only available for captures analyzed from a pcap";

/**
 * Carve a sub-pcap containing only the frames matching `query` within the time window.
 * On desktop (Tauri + path source): prompts for a save path and writes the carved pcap via the
 * native `carve_pcap_to` command.
 * In the browser (bytes source): carves via WASM and triggers a binary download.
 */
export async function carveSubPcap(
  query: CarveQuery,
  source: ActiveSource,
  name: string,
): Promise<ExportResult> {
  if (source === null) {
    return { ok: false, message: `${UNAVAILABLE_MESSAGE}.` };
  }
  if (source.kind === "path" && isTauri()) {
    // The save() dialog must be inside the try too — a rejected save (IPC/permission
    // failure) would otherwise escape the documented no-throw contract that callers
    // (Dashboard carveHost, FlowsView carveFlow) rely on with no .catch.
    try {
      const path = await save({
        defaultPath: name,
        filters: [{ name: "PCAP", extensions: ["pcap"] }],
      });
      if (!path) return { ok: false, message: "" }; // user cancelled
      const n = await invoke<number>("carve_pcap_to", { pathIn: source.path, query, pathOut: path });
      return { ok: true, message: `Carved ${n} packets` };
    } catch (e) {
      return { ok: false, message: `Carve failed: ${e}` };
    }
  }
  if (source.kind === "bytes") {
    try {
      const bytes = await carvePcapViaWasm(source.bytes, query);
      downloadBinary(bytes, name, "application/vnd.tcpdump.pcap");
      return { ok: true, message: "Downloaded" };
    } catch (e) {
      return { ok: false, message: `Carve failed: ${e}` };
    }
  }
  // path source without Tauri
  return { ok: false, message: `${UNAVAILABLE_MESSAGE}.` };
}
