import { describe, it, expect, vi, beforeEach } from "vitest";
import type { AiMessage } from "./client";

// ── Module-level mocks ────────────────────────────────────────────────────
vi.mock("../supabase", () => ({
  supabase: {
    auth: {
      getSession: vi.fn(),
    },
  },
}));

// We'll stub global fetch per-test.

function makeSseStream(deltas: string[]): ReadableStream<Uint8Array> {
  const enc = new TextEncoder();
  const events = deltas.map(
    (d) => `data: ${JSON.stringify({ choices: [{ delta: { content: d } }] })}\n\n`,
  );
  events.push("data: [DONE]\n\n");
  return new ReadableStream({
    start(ctrl) {
      for (const ev of events) ctrl.enqueue(enc.encode(ev));
      ctrl.close();
    },
  });
}

describe("runViaProxy", () => {
  let getSession: ReturnType<typeof vi.fn>;
  let runViaProxy: (messages: AiMessage[], onToken: (t: string) => void) => Promise<string>;

  beforeEach(async () => {
    vi.resetModules();
    vi.clearAllMocks();

    const supabaseMod = await import("../supabase");
    getSession = supabaseMod.supabase!.auth.getSession as ReturnType<typeof vi.fn>;

    const mod = await import("./proxyClient");
    runViaProxy = mod.runViaProxy;
  });

  it("POSTs to the ai-proxy function URL with bearer token and messages", async () => {
    getSession.mockResolvedValue({ data: { session: { access_token: "tok-abc" } } });
    const fetchMock = vi.fn(async () =>
      new Response(makeSseStream(["Hello"]), { status: 200 }),
    );
    vi.stubGlobal("fetch", fetchMock);

    const messages: AiMessage[] = [{ role: "user", content: "hi" }];
    await runViaProxy(messages, () => {});

    expect(fetchMock).toHaveBeenCalledOnce();
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toContain("/functions/v1/ai-proxy");
    expect((init.headers as Record<string, string>)["Authorization"]).toBe("Bearer tok-abc");
    expect(typeof (init.headers as Record<string, string>)["apikey"]).toBe("string");
    expect(JSON.parse(init.body as string)).toEqual({ messages });
  });

  it("streams deltas to onToken and returns the full assembled text", async () => {
    getSession.mockResolvedValue({ data: { session: { access_token: "tok-abc" } } });
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(makeSseStream(["Hello", " world"]), { status: 200 })),
    );

    const tokens: string[] = [];
    const result = await runViaProxy([{ role: "user", content: "q" }], (t) => tokens.push(t));

    expect(tokens).toEqual(["Hello", " world"]);
    expect(result).toBe("Hello world");
  });

  it("throws a friendly error on non-OK response", async () => {
    getSession.mockResolvedValue({ data: { session: { access_token: "tok-abc" } } });
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(JSON.stringify({ error: "not configured" }), { status: 503 })),
    );

    await expect(runViaProxy([{ role: "user", content: "q" }], () => {})).rejects.toThrow(
      /AI is not enabled/i,
    );
  });

  it("throws a generic error for non-503 non-OK status", async () => {
    getSession.mockResolvedValue({ data: { session: { access_token: "tok-abc" } } });
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response("bad", { status: 502 })),
    );

    await expect(runViaProxy([{ role: "user", content: "q" }], () => {})).rejects.toThrow(
      /AI request failed/i,
    );
  });

  it("throws when there is no active session", async () => {
    getSession.mockResolvedValue({ data: { session: null } });

    await expect(runViaProxy([{ role: "user", content: "q" }], () => {})).rejects.toThrow(
      /Sign in/i,
    );
  });
});
