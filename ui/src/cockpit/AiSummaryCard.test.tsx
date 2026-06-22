import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AiSummaryCard } from "./AiSummaryCard";
import { makeOutput } from "../test/fixtures";

vi.mock("../lib/ai/settings", () => ({
  getAiEnabled: () => true, aiConsentGiven: () => true,
  getAiConfig: () => ({ enabled: true, baseUrl: "u", model: "m", apiKey: "k" }),
}));
vi.mock("../lib/ai/cache", () => ({ getAiSummary: vi.fn(async () => null), putAiSummary: vi.fn(async () => true) }));
vi.mock("../lib/ai/run", () => ({
  generateSummary: vi.fn(async (_o, _c, onToken) => { onToken("Generated brief."); return "Generated brief."; }),
}));

describe("AiSummaryCard", () => {
  beforeEach(() => vi.clearAllMocks());
  it("generates and renders the brief on click", async () => {
    const u = userEvent.setup();
    render(<AiSummaryCard output={makeOutput()} captureId="cap-1" />);
    await u.click(screen.getByRole("button", { name: /generate/i }));
    expect(await screen.findByText(/Generated brief\./)).toBeInTheDocument();
  });
});
