// "Follow Stream" — reassemble a flow's per-packet payloads into a readable conversation, the way
// Wireshark's Follow TCP Stream does. Runs entirely in the UI over the packets already fetched for
// the inspector (PacketRow carries direction + payload), so no engine work is involved.
import type { PacketRow } from "../types";

export interface StreamSegment {
  direction: "c2s" | "s2c";
  /** Concatenated payload bytes for this contiguous same-direction run. */
  bytes: Uint8Array;
  /** Packet index of the first packet in this run (for "jump to packet"). */
  firstPacket: number;
  /** ≥1 contributing packet's payload was capped (engine PAYLOAD_CAP_BYTES) — bytes are a prefix. */
  truncatedPayload: boolean;
}

export interface StreamModel {
  /** Conversation as alternating client/server blocks, in capture order. */
  segments: StreamSegment[];
  bytesC2s: number;
  bytesS2c: number;
  /** True if the underlying packet LIST was capped (FlowPackets.truncated) — the stream is partial. */
  truncated: boolean;
  /** True if any packet payload was capped at the engine's per-packet limit — segments show a prefix. */
  payloadCapped: boolean;
}

function concat(arrs: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const a of arrs) total += a.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrs) { out.set(a, off); off += a.length; }
  return out;
}

/**
 * Reassemble `packets` into a conversation: consecutive same-direction payloads coalesce into one
 * segment (a client request block, then a server response block, …), preserving capture order.
 * Packets with no payload (pure ACK/SYN/FIN) are skipped. Capture order matches Wireshark's default
 * Follow-Stream rendering; it's correct for in-order streams and degrades gracefully on reordering.
 */
export function buildStream(packets: PacketRow[], truncated = false): StreamModel {
  const segments: StreamSegment[] = [];
  let bytesC2s = 0;
  let bytesS2c = 0;
  let curDir: "c2s" | "s2c" | null = null;
  let chunks: Uint8Array[] = [];
  let firstPacket = 0;
  let segTrunc = false;
  let payloadCapped = false;

  const flush = () => {
    if (curDir && chunks.length) {
      segments.push({ direction: curDir, bytes: concat(chunks), firstPacket, truncatedPayload: segTrunc });
    }
    chunks = [];
    segTrunc = false;
  };

  for (const p of packets) {
    if (!p.payload || p.payload.length === 0) continue;
    if (p.direction === "c2s") bytesC2s += p.payload.length;
    else bytesS2c += p.payload.length;
    if (p.direction !== curDir) {
      flush();
      curDir = p.direction;
      firstPacket = p.index;
    }
    chunks.push(p.payload);
    if (p.payloadTruncated) { segTrunc = true; payloadCapped = true; }
  }
  flush();

  return { segments, bytesC2s, bytesS2c, truncated, payloadCapped };
}

/**
 * Printable-ASCII rendering of stream bytes: keep newlines + tabs (so HTTP/text protocols read
 * naturally), map every other non-printable byte to "·". Lossy by design — use the hex view for
 * binary protocols.
 */
export function streamText(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i];
    if (b === 0x0a || b === 0x09 || (b >= 0x20 && b < 0x7f)) s += String.fromCharCode(b);
    else s += "·";
  }
  return s;
}
