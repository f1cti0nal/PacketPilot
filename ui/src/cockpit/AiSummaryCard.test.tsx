import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AiSummaryCard } from "./AiSummaryCard";
import { makeOutput } from "../test/fixtures";
import type { AiSummaryEntry } from "../types";

// Default: consent given, AI enabled
const mockAiConsentGiven = vi.fn(() => true);
const mockGetAiEnabled = vi.fn(() => true);
const mockGiveAiConsent = vi.fn();
const mockGetAiSummary = vi.fn<[string], Promise<AiSummaryEntry | null>>(async () => null);
const mockPutAiSummary = vi.fn<[string, string, string, number], Promise<boolean>>(async () => true);
const mockGenerateSummary = vi.fn<[any, any, (t: string) => void], Promise<string>>(async (_o, _c, onToken) => {
  onToken("Generated brief.");
  return "Generated brief.";
});

vi.mock("../lib/ai/settings", () => ({
  getAiEnabled: () => mockGetAiEnabled(),
  aiConsentGiven: () => mockAiConsentGiven(),
  giveAiConsent: () => mockGiveAiConsent(),
  getAiConfig: () => ({ enabled: true, baseUrl: "https://api.anthropic.com/v1", model: "claude-opus-4-8", apiKey: "k" }),
}));
vi.mock("../lib/ai/cache", () => ({
  getAiSummary: (...args: any[]) => mockGetAiSummary(...(args as [string])),
  putAiSummary: (...args: any[]) => mockPutAiSummary(...(args as [string, string, string, number])),
}));
vi.mock("../lib/ai/run", () => ({
  generateSummary: (...args: any[]) => mockGenerateSummary(...(args as [any, any, (t: string) => void])),
}));

describe("AiSummaryCard", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockAiConsentGiven.mockReturnValue(true);
    mockGetAiEnabled.mockReturnValue(true);
    mockGetAiSummary.mockResolvedValue(null);
    mockGenerateSummary.mockImplementation(async (_o, _c, onToken) => {
      onToken("Generated brief.");
      return "Generated brief.";
    });
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

  it("shows error message when AI is disabled", async () => {
    mockGetAiEnabled.mockReturnValue(false);
    const u = userEvent.setup();
    render(<AiSummaryCard output={makeOutput()} captureId="cap-disabled" />);
    await u.click(screen.getByRole("button", { name: /generate/i }));
    expect(await screen.findByText(/AI is off/i)).toBeInTheDocument();
  });

  it("pre-populates text from cache on mount", async () => {
    mockGetAiSummary.mockResolvedValue({ text: "Cached brief.", model: "m", cached_at: 1000 });
    render(<AiSummaryCard output={makeOutput()} captureId="cap-cached" />);
    // Wait for cache load effect to set ready state
    expect(await screen.findByText(/Cached brief\./)).toBeInTheDocument();
  });

  it("shows error state when generateSummary rejects", async () => {
    mockGetAiEnabled.mockReturnValue(true);
    mockAiConsentGiven.mockReturnValue(true);
    mockGenerateSummary.mockRejectedValue(new Error("network failure"));
    const u = userEvent.setup();
    render(<AiSummaryCard output={makeOutput()} captureId="cap-err" />);
    await u.click(screen.getByRole("button", { name: /generate/i }));
    expect(await screen.findByText(/AI request failed.*network failure/i)).toBeInTheDocument();
  });

  it("dismisses consent dialog on cancel without generating", async () => {
    mockAiConsentGiven.mockReturnValue(false);
    const u = userEvent.setup();
    render(<AiSummaryCard output={makeOutput()} captureId="cap-cancel" />);
    await u.click(screen.getByRole("button", { name: /generate/i }));
    await screen.findByRole("dialog", { name: /AI consent/i });
    await u.click(screen.getByRole("button", { name: /cancel/i }));
    await waitFor(() => expect(screen.queryByRole("dialog", { name: /AI consent/i })).not.toBeInTheDocument());
    expect(mockGenerateSummary).not.toHaveBeenCalled();
  });
});
