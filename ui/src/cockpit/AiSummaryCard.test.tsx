import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AiSummaryCard } from "./AiSummaryCard";
import { makeOutput } from "../test/fixtures";

// Default: consent given, AI enabled
const mockAiConsentGiven = vi.fn(() => true);
const mockGetAiEnabled = vi.fn(() => true);
const mockGiveAiConsent = vi.fn();

vi.mock("../lib/ai/settings", () => ({
  getAiEnabled: () => mockGetAiEnabled(),
  aiConsentGiven: () => mockAiConsentGiven(),
  giveAiConsent: () => mockGiveAiConsent(),
  getAiConfig: () => ({ enabled: true, baseUrl: "https://api.anthropic.com/v1", model: "claude-opus-4-8", apiKey: "k" }),
}));
vi.mock("../lib/ai/cache", () => ({ getAiSummary: vi.fn(async () => null), putAiSummary: vi.fn(async () => true) }));
vi.mock("../lib/ai/run", () => ({
  generateSummary: vi.fn(async (_o, _c, onToken) => { onToken("Generated brief."); return "Generated brief."; }),
}));

describe("AiSummaryCard", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockAiConsentGiven.mockReturnValue(true);
    mockGetAiEnabled.mockReturnValue(true);
  });

  it("generates and renders the brief on click", async () => {
    const u = userEvent.setup();
    render(<AiSummaryCard output={makeOutput()} captureId="cap-1" />);
    await u.click(screen.getByRole("button", { name: /generate/i }));
    expect(await screen.findByText(/Generated brief\./)).toBeInTheDocument();
  });

  it("opens consent dialog when consent not yet given", async () => {
    mockAiConsentGiven.mockReturnValue(false);
    const u = userEvent.setup();
    render(<AiSummaryCard output={makeOutput()} captureId="cap-2" />);
    await u.click(screen.getByRole("button", { name: /generate/i }));
    expect(await screen.findByRole("dialog", { name: /AI consent/i })).toBeInTheDocument();
  });

  it("proceeds after consent is given — calls giveAiConsent and generates", async () => {
    mockAiConsentGiven.mockReturnValue(false);
    const u = userEvent.setup();
    render(<AiSummaryCard output={makeOutput()} captureId="cap-3" />);
    await u.click(screen.getByRole("button", { name: /generate/i }));
    // Consent dialog should open
    expect(await screen.findByRole("dialog", { name: /AI consent/i })).toBeInTheDocument();
    // Click Proceed
    await u.click(screen.getByRole("button", { name: /proceed/i }));
    expect(mockGiveAiConsent).toHaveBeenCalled();
    expect(await screen.findByText(/Generated brief\./)).toBeInTheDocument();
  });
});
