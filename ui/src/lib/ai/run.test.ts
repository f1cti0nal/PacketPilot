import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { generateSummary, askChat, tauriTransport } from "./run";
import type { AiConfig } from "../../types";
import { makeOutput } from "../../test/fixtures";

// ── Module-level mocks (hoisted by vitest) ────────────────────────────────
vi.mock("../tauri-detect", () => ({ isTauri: vi.fn(() => false) }));
vi.mock("./settings", () => ({ getProxyUrl: vi.fn(() => "") }));

// Mock @tauri-apps/api/core for tauriTransport tests
const mockInvoke = vi.fn<[string, any?], Promise<void>>(async () => {});
class MockChannel<T> {
  onmessage: ((msg: T) => void) | null = null;
  // Helper to simulate a message being delivered
  _deliver(msg: T) { this.onmessage?.(msg); }
}
vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: any[]) => mockInvoke(...(args as [string, any?])),
  Channel: MockChannel,
}));

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

describe("tauriTransport", () => {
  beforeEach(() => { mockInvoke.mockReset(); });

  it("invokes ai_chat_stream with url and body", async () => {
    mockInvoke.mockImplementation(async (_cmd, _args) => {
      // Simulate that the channel receives a chunk synchronously
    });
    const transport = tauriTransport();
    const seen: string[] = [];
    await transport({ url: "https://api.example/v1", headers: {}, body: '{"model":"m"}' }, (c) => seen.push(c));
    expect(mockInvoke).toHaveBeenCalledWith(
      "ai_chat_stream",
      expect.objectContaining({ url: "https://api.example/v1", body: '{"model":"m"}' }),
    );
  });

  it("forwards channel messages to onChunk", async () => {
    // The channel's onmessage is set by tauriTransport before invoke is called.
    // We capture the channel from the invoke args (it's the 2nd positional arg object's onChunk).
    mockInvoke.mockImplementation(async (...allArgs: any[]) => {
      // allArgs[0] = "ai_chat_stream", allArgs[1] = { url, body, onChunk: channel }
      const callArgs = allArgs[1] as Record<string, unknown>;
      const ch = callArgs?.["onChunk"] as MockChannel<string>;
      // Deliver the message synchronously via the already-set handler
      ch?.onmessage?.("data: hello\n\n");
    });
    const transport = tauriTransport();
    const seen: string[] = [];
    await transport({ url: "u", headers: {}, body: "{}" }, (c) => seen.push(c));
    expect(seen).toContain("data: hello\n\n");
  });
});

describe("pickTransport", () => {
  // We import the live module + the two mocked modules to control their return values per-test.
  let isTauriMock: ReturnType<typeof vi.fn>;
  let getProxyUrlMock: ReturnType<typeof vi.fn>;

  beforeEach(async () => {
    const tauriDetect = await import("../tauri-detect");
    const settings = await import("./settings");
    isTauriMock = tauriDetect.isTauri as ReturnType<typeof vi.fn>;
    getProxyUrlMock = settings.getProxyUrl as ReturnType<typeof vi.fn>;
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("returns proxyTransport when proxy is set (non-tauri browser)", async () => {
    isTauriMock.mockReturnValue(false);
    getProxyUrlMock.mockReturnValue("https://relay.example");
    const { pickTransport } = await import("./run");
    const transport = pickTransport({ ...cfg, baseUrl: "https://api.anthropic.com/v1" });
    // The proxy transport posts to the relay — a 502 from relay means it took the proxy path
    vi.stubGlobal("fetch", vi.fn(async () => new Response("err", { status: 502 })));
    await expect(transport({ url: "u", headers: {}, body: "{}" }, () => {})).rejects.toThrow(/relay error 502/);
  });

  it("returns directTransport for localhost endpoint with no proxy", async () => {
    isTauriMock.mockReturnValue(false);
    getProxyUrlMock.mockReturnValue("");
    const { pickTransport } = await import("./run");
    const transport = pickTransport({ ...cfg, baseUrl: "http://localhost:11434/v1" });
    // directTransport posts to req.url directly — a 503 means it took the direct path
    vi.stubGlobal("fetch", vi.fn(async () => new Response("err", { status: 503 })));
    await expect(transport({ url: "http://localhost:11434/v1/chat", headers: {}, body: "{}" }, () => {})).rejects.toThrow(/endpoint error 503/);
  });

  it("throws for non-local endpoint with no proxy in browser", async () => {
    isTauriMock.mockReturnValue(false);
    getProxyUrlMock.mockReturnValue("");
    const { pickTransport } = await import("./run");
    expect(() => pickTransport({ ...cfg, baseUrl: "https://api.openai.com/v1" })).toThrow(/relay/i);
  });

  it("REJECTS a malformed (non-absolute) relay URL instead of POSTing to the app origin", async () => {
    isTauriMock.mockReturnValue(false);
    // A scheme-less value would resolve relative to the page origin in fetch() → key/summary leak.
    for (const bad of ["relay", "/ai-relay", "ftp://relay.example"]) {
      getProxyUrlMock.mockReturnValue(bad);
      const { pickTransport } = await import("./run");
      expect(() => pickTransport({ ...cfg, baseUrl: "https://api.openai.com/v1" }), bad).toThrow(
        /valid http/i,
      );
    }
  });

  it("REJECTS spoofed-localhost hosts (exact-hostname gate, not a prefix)", async () => {
    isTauriMock.mockReturnValue(false);
    getProxyUrlMock.mockReturnValue("");
    const { pickTransport } = await import("./run");
    for (const url of [
      "http://localhost.evil.com/v1",
      "http://127.0.0.1.attacker.io/v1",
      "https://localhostx.example.com/v1",
      "http://notlocalhost/v1",
    ]) {
      // A spoofed host must fall through to the relay-required throw, NOT directTransport
      // (which would POST the capture context + Authorization header to the attacker origin).
      expect(() => pickTransport({ ...cfg, baseUrl: url }), url).toThrow(/relay/i);
    }
  });

  it("still allows genuine 127.0.0.1 / [::1] loopback direct", async () => {
    isTauriMock.mockReturnValue(false);
    getProxyUrlMock.mockReturnValue("");
    const { pickTransport } = await import("./run");
    expect(() => pickTransport({ ...cfg, baseUrl: "http://127.0.0.1:11434/v1" })).not.toThrow();
    expect(() => pickTransport({ ...cfg, baseUrl: "http://[::1]:11434/v1" })).not.toThrow();
  });

  it("returns tauriTransport when running in Tauri", async () => {
    isTauriMock.mockReturnValue(true);
    const { pickTransport } = await import("./run");
    const transport = pickTransport({ ...cfg, baseUrl: "https://api.anthropic.com/v1" });
    // tauriTransport will call invoke — if it calls invoke, it's the tauri path
    mockInvoke.mockResolvedValue(undefined);
    await transport({ url: "https://api.x/v1", headers: {}, body: "{}" }, () => {});
    expect(mockInvoke).toHaveBeenCalledWith("ai_chat_stream", expect.anything());
  });
});
