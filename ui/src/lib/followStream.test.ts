import { describe, it, expect } from "vitest";
import { buildStream, streamText } from "./followStream";
import type { PacketRow } from "../types";

const pkt = (index: number, direction: "c2s" | "s2c", text: string): PacketRow => ({
  index, tsNs: 0, relMs: index, direction,
  wireLen: 60 + text.length, capLen: 60 + text.length, tcpFlags: 0x18,
  seq: index, ack: index, payloadLen: text.length,
  payload: new TextEncoder().encode(text), payloadTruncated: false,
});
const ack = (index: number, direction: "c2s" | "s2c"): PacketRow => ({ ...pkt(index, direction, ""), tcpFlags: 0x10 });

describe("buildStream", () => {
  it("coalesces consecutive same-direction payloads and alternates client/server blocks", () => {
    const s = buildStream([
      pkt(0, "c2s", "GET / HTTP/1.1\r\n"),
      pkt(1, "c2s", "Host: x\r\n\r\n"),
      ack(2, "s2c"),
      pkt(3, "s2c", "HTTP/1.1 200 OK\r\n"),
      pkt(4, "c2s", "next"),
    ]);
    expect(s.segments.map((x) => x.direction)).toEqual(["c2s", "s2c", "c2s"]);
    expect(new TextDecoder().decode(s.segments[0].bytes)).toBe("GET / HTTP/1.1\r\nHost: x\r\n\r\n");
    expect(s.segments[0].firstPacket).toBe(0);
    expect(s.segments[1].firstPacket).toBe(3);
  });

  it("counts bytes per direction and skips payload-less packets", () => {
    const s = buildStream([pkt(0, "c2s", "abcd"), ack(1, "c2s"), pkt(2, "s2c", "xyz")]);
    expect(s.bytesC2s).toBe(4);
    expect(s.bytesS2c).toBe(3);
    expect(s.segments).toHaveLength(2);
  });

  it("returns no segments for an all-control (no-payload) flow", () => {
    expect(buildStream([ack(0, "c2s"), ack(1, "s2c")]).segments).toHaveLength(0);
  });

  it("propagates the list-truncated flag", () => {
    expect(buildStream([pkt(0, "c2s", "a")], true).truncated).toBe(true);
  });

  it("flags payload-capped segments and the stream-level cap", () => {
    const capped: PacketRow = { ...pkt(0, "c2s", "0123456789"), payloadTruncated: true, payloadLen: 5000 };
    const s = buildStream([capped, pkt(1, "s2c", "ok")]);
    expect(s.payloadCapped).toBe(true);
    expect(s.segments[0].truncatedPayload).toBe(true);
    expect(s.segments[1].truncatedPayload).toBe(false);
  });
});

describe("streamText", () => {
  it("keeps printable + newline/tab and maps other bytes to ·", () => {
    const bytes = new Uint8Array([0x41, 0x0a, 0x09, 0x00, 0xff, 0x42]); // A \n \t NUL 0xff B
    expect(streamText(bytes)).toBe("A\n\t··B");
  });
});
