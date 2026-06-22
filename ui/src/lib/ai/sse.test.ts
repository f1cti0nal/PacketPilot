import { describe, it, expect } from "vitest";
import { SseAccumulator } from "./sse";

const ev = (content: string) => `data: ${JSON.stringify({ choices: [{ delta: { content } }] })}\n\n`;

describe("SseAccumulator", () => {
  it("extracts content deltas across well-formed events", () => {
    const a = new SseAccumulator();
    expect(a.push(ev("Hel") + ev("lo"))).toEqual(["Hel", "lo"]);
  });
  it("buffers a partial event split across pushes", () => {
    const a = new SseAccumulator();
    const whole = ev("world");
    const cut = Math.floor(whole.length / 2);
    expect(a.push(whole.slice(0, cut))).toEqual([]);
    expect(a.push(whole.slice(cut))).toEqual(["world"]);
  });
  it("ignores [DONE] and content-less deltas", () => {
    const a = new SseAccumulator();
    const role = `data: ${JSON.stringify({ choices: [{ delta: { role: "assistant" } }] })}\n\n`;
    expect(a.push(role + ev("x") + "data: [DONE]\n\n")).toEqual(["x"]);
  });
});
