import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

describe("supabase client", () => {
  beforeEach(() => { vi.resetModules(); });
  afterEach(() => { vi.unstubAllEnvs(); });

  it("is unconfigured when env vars are missing", async () => {
    vi.stubEnv("VITE_SUPABASE_URL", "");
    vi.stubEnv("VITE_SUPABASE_ANON_KEY", "");
    const mod = await import("./client");
    expect(mod.supabaseConfigured).toBe(false);
    expect(mod.supabase).toBeNull();
  });

  it("creates a client when env vars are present", async () => {
    vi.stubEnv("VITE_SUPABASE_URL", "https://demo.supabase.co");
    vi.stubEnv("VITE_SUPABASE_ANON_KEY", "anon-key");
    const mod = await import("./client");
    expect(mod.supabaseConfigured).toBe(true);
    expect(mod.supabase).not.toBeNull();
  });
});
