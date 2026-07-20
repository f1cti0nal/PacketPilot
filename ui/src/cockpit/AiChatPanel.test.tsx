import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AiChatPanel } from "./AiChatPanel";
import { makeOutput } from "../test/fixtures";

const mockAskChat = vi.fn<[any, any, string, (t: string) => void], Promise<string>>(async (_o, _h, q, onToken) => {
  onToken(`re: ${q}`);
  return `re: ${q}`;
});

// mock-prefixed so vitest allows referencing them inside the hoisted vi.mock factory.
const mockFlags = { consent: true };
const mockGiveConsent = vi.fn(() => { mockFlags.consent = true; });

vi.mock("../lib/ai/settings", () => ({
  aiConsentGiven: () => mockFlags.consent,
  giveAiConsent: () => mockGiveConsent(),
}));
vi.mock("../lib/ai/run", () => ({
  askChat: (...args: any[]) => mockAskChat(...(args as [any, any, string, (t: string) => void])),
}));

describe("AiChatPanel", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockFlags.consent = true;
    mockAskChat.mockImplementation(async (_o: any, _h: any, q: string, onToken: (t: string) => void) => {
      onToken(`re: ${q}`);
      return `re: ${q}`;
    });
  });

  it("sends a question and renders the streamed answer", async () => {
    const u = userEvent.setup();
    render(<AiChatPanel open onClose={vi.fn()} output={makeOutput()} model="claude-opus-4-8" />);
    await u.type(screen.getByRole("textbox"), "what happened?");
    await u.click(screen.getByRole("button", { name: /send/i }));
    expect(await screen.findByText(/re: what happened\?/)).toBeInTheDocument();
  });

  it("renders nothing when closed", () => {
    const { container } = render(<AiChatPanel open={false} onClose={vi.fn()} output={makeOutput()} model="claude-opus-4-8" />);
    expect(container).toBeEmptyDOMElement();
  });

  it("appends error bubble when askChat rejects", async () => {
    mockAskChat.mockRejectedValue(new Error("model overloaded"));
    const u = userEvent.setup();
    render(<AiChatPanel open onClose={vi.fn()} output={makeOutput()} model="claude-opus-4-8" />);
    await u.type(screen.getByRole("textbox"), "test question");
    await u.click(screen.getByRole("button", { name: /send/i }));
    expect(await screen.findByText(/model overloaded/i)).toBeInTheDocument();
  });

  it("calls onClose when Close button clicked", async () => {
    const onClose = vi.fn();
    const u = userEvent.setup();
    render(<AiChatPanel open onClose={onClose} output={makeOutput()} model="claude-opus-4-8" />);
    await u.click(screen.getByRole("button", { name: /close/i }));
    expect(onClose).toHaveBeenCalled();
  });

  it("sends on Enter key in the input", async () => {
    const u = userEvent.setup();
    render(<AiChatPanel open onClose={vi.fn()} output={makeOutput()} model="claude-opus-4-8" />);
    await u.type(screen.getByRole("textbox"), "enter question{Enter}");
    expect(await screen.findByText(/re: enter question/i)).toBeInTheDocument();
  });

  // --- privacy gate (mirrors AiSummaryCard) ---

  it("does NOT egress without consent — shows the consent dialog first, then sends on Proceed", async () => {
    mockFlags.consent = false;
    const u = userEvent.setup();
    render(<AiChatPanel open onClose={vi.fn()} output={makeOutput()} model="claude-opus-4-8" />);
    await u.type(screen.getByRole("textbox"), "what exfiltrated?");
    await u.click(screen.getByRole("button", { name: /send/i }));
    // The summary must not have been sent yet…
    expect(mockAskChat).not.toHaveBeenCalled();
    // …and the consent dialog must be shown.
    expect(screen.getByText(/Send the analysis summary to the model/i)).toBeInTheDocument();
    // Proceeding records consent and only then performs the egress.
    await u.click(screen.getByRole("button", { name: /proceed/i }));
    expect(mockGiveConsent).toHaveBeenCalled();
    expect(await screen.findByText(/re: what exfiltrated\?/)).toBeInTheDocument();
  });
});
