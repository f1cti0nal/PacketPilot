import type { ActiveSource, FlowPackets, FlowRow, PacketRow, WireFlowPackets } from "../types";
import { isTauri, extractPacketsViaTauri } from "./platform";
import { extractPacketsViaWasm } from "./wasmEngine";

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
    index: p.index, tsNs: p.ts_ns, relMs: (p.ts_ns - startNs) / 1e6,
    direction: p.direction, wireLen: p.wire_len, capLen: p.cap_len,
    tcpFlags: p.tcp_flags, seq: p.seq, ack: p.ack,
    payloadLen: p.payload_len, payload: b64ToBytes(p.payload_b64), payloadTruncated: p.payload_truncated,
  }));
  return { total: wire.total, truncated: wire.truncated, packets };
}

export async function extractFlowPackets(source: ActiveSource, flow: FlowRow): Promise<FlowPackets> {
  if (!source) throw new PacketsUnavailableError();
  const query = queryFor(flow);
  const wire = source.kind === "path" && isTauri()
    ? await extractPacketsViaTauri(source.path, query)
    : source.kind === "bytes"
      ? await extractPacketsViaWasm(source.bytes, query)
      : (() => { throw new PacketsUnavailableError(); })();
  return normalize(wire as WireFlowPackets, flow);
}
