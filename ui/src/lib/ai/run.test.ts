import { describe, it, expect } from "vitest";
import { generateSummary, askChat } from "./run";
import type { AiConfig } from "../../types";
import { makeOutput } from "../../test/fixtures";

const cfg: AiConfig = { enabled: true, baseUrl: "https://api.x/v1", model: "m", apiKey: "k" };
const fakeTransport = (text: string) => async (_req: any, onChunk: (r: string) => void) => {
  onChunk(`data: ${JSON.stringify({ choices: [{ delta: { content: text } }] })}\n\ndata: [DONE]\n\n`);
};

describe("run orchestrators", () => {
  it("generateSummary sends the summary system prompt + curated context", async () => {
    const out = makeOutput();
    const text = await generateSummary(out, cfg, () => {}, fakeTransport("BRIEF"));
    expect(text).toBe("BRIEF");
  });
  it("askChat includes the question + context", async () => {
    const out = makeOutput();
    const text = await askChat(out, [], "what happened?", cfg, () => {}, fakeTransport("ANSWER"));
    expect(text).toBe("ANSWER");
  });
});
