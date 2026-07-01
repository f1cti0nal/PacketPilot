import { describe, it, expect, vi, beforeEach } from "vitest";

// vi.hoisted runs before module mocking, so the spy is available when the factory is called.
const mockIdToken = vi.hoisted(() => vi.fn());

vi.mock("../supabase", () => ({ supabase: {} }));
vi.mock("../../auth/auth0Client", () => ({ auth0IdToken: mockIdToken }));

import { edgeRepHttp } from "./edgeHttp";

beforeEach(() => {
  vi.restoreAllMocks();
  mockIdToken.mockReset();
});

describe("edgeRepHttp", () => {
  it("returns {status:0,body:''} when there is no token", async () => {
    mockIdToken.mockResolvedValue(null);
    const get = edgeRepHttp();
    expect(await get("https://api.abuseipdb.com/api/v2/check?ipAddress=1.2.3.4", {})).toEqual({ status: 0, body: "" });
  });

  it("POSTs {url,headers} with the bearer token and returns {status,body}", async () => {
    mockIdToken.mockResolvedValue("tok123");
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ status: 200, body: '{"data":{"abuseConfidenceScore":42}}' }),
    });
    vi.stubGlobal("fetch", mockFetch);

    const get = edgeRepHttp();
    const result = await get("https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8", { Accept: "application/json" });

    expect(result.status).toBe(200);
    expect(result.body).toBe('{"data":{"abuseConfidenceScore":42}}');

    expect(mockFetch).toHaveBeenCalledOnce();
    const [_url, opts] = mockFetch.mock.calls[0] as [string, RequestInit];
    expect(opts.method).toBe("POST");
    const sentHeaders = opts.headers as Record<string, string>;
    expect(sentHeaders["Authorization"]).toBe("Bearer tok123");
    expect(sentHeaders["content-type"]).toBe("application/json");

    const sentBody = JSON.parse(opts.body as string);
    expect(sentBody.url).toBe("https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8");
    expect(sentBody.headers).toEqual({ Accept: "application/json" });
  });

  it("returns {status: resp.status, body:''} when fetch response is not ok", async () => {
    mockIdToken.mockResolvedValue("tok");
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: false, status: 401 }));
    const get = edgeRepHttp();
    expect(await get("https://api.abuseipdb.com/api/v2/check", {})).toEqual({ status: 401, body: "" });
  });

  it("returns {status:0,body:''} when fetch throws (network error)", async () => {
    mockIdToken.mockResolvedValue("tok");
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("network failure")));
    const get = edgeRepHttp();
    expect(await get("https://api.abuseipdb.com/api/v2/check", {})).toEqual({ status: 0, body: "" });
  });

  it("maps non-string body from proxy response to empty string", async () => {
    mockIdToken.mockResolvedValue("tok");
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ status: 200, body: { nested: true } }),
    }));
    const get = edgeRepHttp();
    const result = await get("https://api.abuseipdb.com/api/v2/check", {});
    expect(result.body).toBe("");
  });
});
