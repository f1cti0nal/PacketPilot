import { describe, expect, it } from "vitest";
import { maskUrl, maskKey } from "./envMask";

describe("env masking", () => {
  it("masks a url to scheme + prefix, never the whole value", () => {
    const m = maskUrl("https://brkztcfhmrjjnbjzycie.supabase.co");
    expect(m).toMatch(/^https:\/\//);
    expect(m).toContain("…");
    expect(m).not.toContain("supabase.co");
  });
  it("masks a key to prefix + suffix only", () => {
    const m = maskKey("sb_publishable_SZeNFP9bBk5mqzjX4cGpKQ_f-ygy641");
    expect(m.startsWith("sb_pub")).toBe(true);
    expect(m.endsWith("y641")).toBe(true);
    expect(m).toContain("…");
    expect(m).not.toContain("SZeNFP9");
  });
  it("returns Missing for empty", () => {
    expect(maskUrl(undefined)).toBe("— Missing");
    expect(maskKey("")).toBe("— Missing");
  });
});
