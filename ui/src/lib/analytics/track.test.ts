import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const insert = vi.fn((_payload: Record<string, unknown>) => ({ then: (res: () => void) => { res(); return Promise.resolve(); } }));
const from = vi.fn((_table: string) => ({ insert }));
vi.mock("../supabase", () => ({ supabase: { from: (t: string) => from(t) } }));

import { trackPageView, __resetTrackerForTests } from "./track";

beforeEach(() => {
  __resetTrackerForTests();
  sessionStorage.clear();
  from.mockClear(); insert.mockClear();
});
afterEach(() => {
  vi.restoreAllMocks();
});

const flush = () => new Promise((r) => setTimeout(r, 0));

describe("trackPageView", () => {
  it("inserts an allowlisted token with a session id, attributed anonymously", async () => {
    trackPageView("/app#flows");
    await flush();
    expect(from).toHaveBeenCalledWith("analytics_events");
    const payload = insert.mock.calls[0][0] as Record<string, unknown>;
    expect(payload.path).toBe("/app#flows");
    expect(typeof payload.session_id).toBe("string");
    expect((payload.session_id as string).length).toBeGreaterThan(10);
    expect(payload.user_id).toBeNull();
    expect(payload).not.toHaveProperty("referrer");
    expect(payload).not.toHaveProperty("user_agent");
    expect(payload).not.toHaveProperty("country");
    expect(payload).not.toHaveProperty("created_at");
  });

  it("drops non-allowlisted paths (capture-shaped, query, unknown)", async () => {
    trackPageView("/app/secret/10.0.0.1");
    trackPageView("/?host=evil.com");
    trackPageView("/admin#nope");
    await flush();
    expect(insert).not.toHaveBeenCalled();
  });

  it("dedupes consecutive identical tokens but re-fires after a change", async () => {
    trackPageView("/app#flows");
    trackPageView("/app#flows");
    await flush();
    expect(insert).toHaveBeenCalledTimes(1);
    trackPageView("/app#recent");
    await flush();
    expect(insert).toHaveBeenCalledTimes(2);
  });

  it("reuses one sessionStorage id across calls", async () => {
    trackPageView("/app#flows");
    trackPageView("/app#recent");
    await flush();
    const a = (insert.mock.calls[0][0] as { session_id: string }).session_id;
    const b = (insert.mock.calls[1][0] as { session_id: string }).session_id;
    expect(a).toBe(b);
    expect(sessionStorage.getItem("pp_sid")).toBe(a);
  });
});
