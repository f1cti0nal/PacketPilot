import { describe, it, expect, vi, beforeEach } from "vitest";
import { generateSummary, askChat } from "./run";
import { makeOutput } from "../../test/fixtures";
import { SUMMARY_SYSTEM, CHAT_SYSTEM } from "./prompts";
import { buildContext } from "./context";

// ── Module-level mocks ────────────────────────────────────────────────────
vi.mock("./proxyClient", () => ({
  runViaProxy: vi.fn(),
}));

describe("run orchestrators", () => {
  let runViaProxy: ReturnType<typeof vi.fn>;

  beforeEach(async () => {
    const mod = await import("./proxyClient");
    runViaProxy = mod.runViaProxy as ReturnType<typeof vi.fn>;
    runViaProxy.mockResolvedValue("mocked-result");
  });

  describe("generateSummary", () => {
    it("calls runViaProxy with system + user messages built from output", async () => {
      const output = makeOutput();
      const onToken = vi.fn();
      const result = await generateSummary(output, onToken);

      expect(runViaProxy).toHaveBeenCalledOnce();
      const [messages, cb] = runViaProxy.mock.calls[0] as [unknown[], unknown];
      expect(Array.isArray(messages)).toBe(true);
      expect((messages as { role: string; content: string }[])[0]).toEqual({
        role: "system",
        content: SUMMARY_SYSTEM,
      });
      expect((messages as { role: string; content: string }[])[1].role).toBe("user");
      expect((messages as { role: string; content: string }[])[1].content).toBe(buildContext(output));
      expect(cb).toBe(onToken);
      expect(result).toBe("mocked-result");
    });
  });

  describe("askChat", () => {
    it("calls runViaProxy with system+context, history slice, and question", async () => {
      const output = makeOutput();
      const history = [
        { role: "user" as const, content: "q1" },
        { role: "assistant" as const, content: "a1" },
      ];
      const onToken = vi.fn();
      const result = await askChat(output, history, "what happened?", onToken);

      expect(runViaProxy).toHaveBeenCalledOnce();
      const [messages, cb] = runViaProxy.mock.calls[0] as [{ role: string; content: string }[], unknown];
      expect(messages[0].role).toBe("system");
      expect(messages[0].content).toContain(CHAT_SYSTEM);
      expect(messages[0].content).toContain(buildContext(output));
      // history entries followed by the user question
      expect(messages[messages.length - 1]).toEqual({ role: "user", content: "what happened?" });
      expect(cb).toBe(onToken);
      expect(result).toBe("mocked-result");
    });

    it("slices history to the last 8 messages", async () => {
      const output = makeOutput();
      const history = Array.from({ length: 12 }, (_, i) => ({
        role: (i % 2 === 0 ? "user" : "assistant") as "user" | "assistant",
        content: `msg-${i}`,
      }));
      await askChat(output, history, "final?", vi.fn());

      const [messages] = runViaProxy.mock.calls[0] as [{ role: string; content: string }[]];
      // 1 system + 8 history + 1 question = 10
      expect(messages).toHaveLength(10);
    });
  });
});
