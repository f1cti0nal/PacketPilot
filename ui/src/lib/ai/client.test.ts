import { describe, it, expect } from "vitest";
import { chatCompletion } from "./client";
import type { StreamTransport } from "./transport";
import type { AiConfig } from "../../types";

const cfg: AiConfig = { enabled: true, baseUrl: "https://api.x/v1", model: "m", apiKey: "k" };

describe("chatCompletion", () => {
  it("builds an OpenAI-format request and assembles streamed deltas", async () => {
    let seen: any = null;
    const fake: StreamTransport = async (req, onChunk) => {
      seen = req;
      onChunk(`data: ${JSON.stringify({ choices: [{ delta: { content: "Hi" } }] })}\n\n`);
      onChunk(`data: ${JSON.stringify({ choices: [{ delta: { content: "!" } }] })}\n\ndata: [DONE]\n\n`);
    };
    const tokens: string[] = [];
    const text = await chatCompletion(cfg, [{ role: "user", content: "q" }], fake, (t) => tokens.push(t));
    expect(text).toBe("Hi!");
    expect(tokens).toEqual(["Hi", "!"]);
    expect(seen.url).toBe("https://api.x/v1/chat/completions");
    expect(seen.headers.Authorization).toBe("Bearer k");
    const body = JSON.parse(seen.body);
    expect(body).toMatchObject({ model: "m", stream: true });
    expect(body.messages).toEqual([{ role: "user", content: "q" }]);
  });

  it("omits the auth header when no key is set", async () => {
    let seen: any = null;
    const fake: StreamTransport = async (req) => { seen = req; };
    await chatCompletion({ ...cfg, apiKey: "" }, [], fake, () => {});
    expect(seen.headers.Authorization).toBeUndefined();
  });
});
