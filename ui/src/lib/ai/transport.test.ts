import { describe, it, expect, vi, afterEach } from "vitest";
import { proxyTransport, directTransport } from "./transport";

function streamResponse(text: string): Response {
  const body = new ReadableStream({
    start(c) {
      c.enqueue(new TextEncoder().encode(text));
      c.close();
    },
  });
  return new Response(body, { status: 200 });
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("proxyTransport", () => {
  it("pipes upstream SSE bytes to onChunk", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => streamResponse("data: x\n\n")));
    const seen: string[] = [];
    await proxyTransport("https://relay.test")({ url: "https://api.example/v1/messages", headers: {}, body: "{}" }, (c) => seen.push(c));
    expect(seen.join("")).toContain("data: x");
  });

  it("sends the relay contract: POST with {url,headers,method,body,stream}", async () => {
    const fetchSpy = vi.fn(async () => streamResponse(""));
    vi.stubGlobal("fetch", fetchSpy);
    await proxyTransport("https://relay.test")({ url: "https://upstream", headers: { authorization: "Bearer k" }, body: '{"x":1}' }, () => {});
    const [calledUrl, calledOpts] = fetchSpy.mock.calls[0];
    expect(calledUrl).toBe("https://relay.test");
    const sent = JSON.parse(calledOpts.body as string);
    expect(sent.url).toBe("https://upstream");
    expect(sent.stream).toBe(true);
    expect(sent.method).toBe("POST");
    expect(sent.headers).toMatchObject({ authorization: "Bearer k" });
  });

  it("throws on non-ok relay response", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response("error", { status: 502 })));
    await expect(
      proxyTransport("https://relay.test")({ url: "u", headers: {}, body: "{}" }, () => {}),
    ).rejects.toThrow(/relay error 502/);
  });

  it("handles response with no body (falls back to text())", async () => {
    const resp = new Response("plaintext", { status: 200 });
    // body is not null in Node fetch but let's simulate null body
    Object.defineProperty(resp, "body", { value: null });
    vi.stubGlobal("fetch", vi.fn(async () => resp));
    const seen: string[] = [];
    await proxyTransport("https://relay.test")({ url: "u", headers: {}, body: "{}" }, (c) => seen.push(c));
    expect(seen.join("")).toContain("plaintext");
  });
});

describe("directTransport", () => {
  it("pipes response bytes to onChunk", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => streamResponse("data: hello\n\n")));
    const seen: string[] = [];
    await directTransport()({ url: "http://localhost:11434/v1/chat", headers: {}, body: "{}" }, (c) => seen.push(c));
    expect(seen.join("")).toContain("data: hello");
  });

  it("throws on non-ok status", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response("", { status: 500 })));
    await expect(
      directTransport()({ url: "http://localhost:11434", headers: {}, body: "{}" }, () => {}),
    ).rejects.toThrow(/endpoint error 500/);
  });

  it("handles response with no body", async () => {
    const resp = new Response("plain", { status: 200 });
    Object.defineProperty(resp, "body", { value: null });
    vi.stubGlobal("fetch", vi.fn(async () => resp));
    const seen: string[] = [];
    await directTransport()({ url: "u", headers: {}, body: "{}" }, (c) => seen.push(c));
    expect(seen.join("")).toContain("plain");
  });
});
