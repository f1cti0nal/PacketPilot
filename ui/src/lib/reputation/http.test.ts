import { describe, it, expect, vi, beforeEach } from "vitest";
import { proxyHttp, unavailable } from "./http";

describe("proxyHttp", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("success path: returns status + body from proxy response", async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ status: 200, body: '{"abuseConfidenceScore":42}' }),
    });
    vi.stubGlobal("fetch", mockFetch);

    const get = proxyHttp("https://proxy.example/relay");
    const result = await get("https://api.abuseipdb.com/check", { "Key": "abc" });

    expect(result.status).toBe(200);
    expect(result.body).toBe('{"abuseConfidenceScore":42}');
    expect(mockFetch).toHaveBeenCalledWith(
      "https://proxy.example/relay",
      expect.objectContaining({
        method: "POST",
        headers: { "content-type": "application/json" },
      })
    );
    const sentBody = JSON.parse(mockFetch.mock.calls[0][1].body);
    expect(sentBody.url).toBe("https://api.abuseipdb.com/check");
    expect(sentBody.headers).toEqual({ "Key": "abc" });
  });

  it("non-ok response: returns {status: resp.status, body: ''}", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
      ok: false,
      status: 429,
    }));

    const get = proxyHttp("https://proxy.example/relay");
    const result = await get("https://api.example.com", {});

    expect(result.status).toBe(429);
    expect(result.body).toBe("");
  });

  it("fetch throws (network error): returns {status: 0, body: ''}", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("network failure")));

    const get = proxyHttp("https://proxy.example/relay");
    const result = await get("https://api.example.com", {});

    expect(result.status).toBe(0);
    expect(result.body).toBe("");
  });

  it("proxy returns non-string body: JSON-stringifies it", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ status: 200, body: { nested: true } }),
    }));

    const get = proxyHttp("https://proxy.example/relay");
    const result = await get("https://api.example.com", {});

    expect(result.status).toBe(200);
    expect(result.body).toBe(JSON.stringify({ nested: true }));
  });

  it("proxy returns missing/invalid status: coerces to 0", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ status: "not-a-number", body: "hello" }),
    }));

    const get = proxyHttp("https://proxy.example/relay");
    const result = await get("https://api.example.com", {});

    expect(result.status).toBe(0);
    expect(result.body).toBe("hello");
  });
});

describe("unavailable", () => {
  it("returns a well-formed unavailable verdict", () => {
    const v = unavailable("abuseipdb", 9999);
    expect(v.source).toBe("abuseipdb");
    expect(v.status).toBe("unavailable");
    expect(v.malicious).toBe(false);
    expect(v.score).toBeNull();
    expect(v.tags).toEqual([]);
    expect(v.link).toBeNull();
    expect(v.fetched_at).toBe(9999);
  });
});
