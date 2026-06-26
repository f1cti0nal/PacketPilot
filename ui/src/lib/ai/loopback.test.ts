import { describe, it, expect, beforeEach } from "vitest";
import { isLoopbackUrl, aiNeedsRelay } from "./loopback";

describe("isLoopbackUrl", () => {
  it("accepts only genuine loopback hosts (exact hostname)", () => {
    expect(isLoopbackUrl("http://localhost:11434/v1")).toBe(true);
    expect(isLoopbackUrl("http://127.0.0.1:8080/v1")).toBe(true);
    expect(isLoopbackUrl("http://[::1]:1234/v1")).toBe(true);
  });
  it("rejects spoofed-localhost prefixes (the consent/transport spoof)", () => {
    expect(isLoopbackUrl("http://localhost.evil.com/v1")).toBe(false);
    expect(isLoopbackUrl("http://127.0.0.1.attacker.io/v1")).toBe(false);
    expect(isLoopbackUrl("https://localhostx.example.com/v1")).toBe(false);
    expect(isLoopbackUrl("http://notlocalhost/v1")).toBe(false);
  });
  it("rejects cloud hosts and unparseable URLs", () => {
    expect(isLoopbackUrl("https://api.anthropic.com/v1")).toBe(false);
    expect(isLoopbackUrl("not a url")).toBe(false);
    expect(isLoopbackUrl("")).toBe(false);
  });
});

describe("aiNeedsRelay (browser)", () => {
  beforeEach(() => localStorage.clear());
  it("is true for a cloud endpoint with no relay configured", () => {
    expect(aiNeedsRelay("https://api.anthropic.com/v1")).toBe(true);
  });
  it("is false for a loopback endpoint (talks to the provider directly)", () => {
    expect(aiNeedsRelay("http://localhost:11434/v1")).toBe(false);
  });
  it("is false once a relay URL is configured", () => {
    localStorage.setItem("pp.ai.proxyUrl", "https://relay.example/ai");
    expect(aiNeedsRelay("https://api.anthropic.com/v1")).toBe(false);
  });
  it("treats a whitespace-only relay as unset (still needs a real relay)", () => {
    localStorage.setItem("pp.ai.proxyUrl", "   ");
    expect(aiNeedsRelay("https://api.anthropic.com/v1")).toBe(true);
  });
});
