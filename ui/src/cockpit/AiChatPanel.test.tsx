import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AiChatPanel } from "./AiChatPanel";
import { makeOutput } from "../test/fixtures";

const mockAskChat = vi.fn<[any, any, string, any, (t: string) => void], Promise<string>>(async (_o, _h, q, _c, onToken) => {
  onToken(`re: ${q}`);
  return `re: ${q}`;
});

vi.mock("../lib/ai/settings", () => ({
  getAiConfig: () => ({ enabled: true, baseUrl: "u", model: "m", apiKey: "k" }),
}));
vi.mock("../lib/ai/run", () => ({
  askChat: (...args: any[]) => mockAskChat(...(args as [any, any, string, any, (t: string) => void])),
}));

describe("AiChatPanel", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockAskChat.mockImplementation(async (_o: any, _h: any, q: string, _c: any, onToken: (t: string) => void) => {
      onToken(`re: ${q}`);
      return `re: ${q}`;
    });
  });

  it("sends a question and renders the streamed answer", async () => {
    const u = userEvent.setup();
    render(<AiChatPanel open onClose={vi.fn()} output={makeOutput()} />);
    await u.type(screen.getByRole("textbox"), "what happened?");
    await u.click(screen.getByRole("button", { name: /send/i }));
    expect(await screen.findByText(/re: what happened\?/)).toBeInTheDocument();
  });

  it("renders nothing when closed", () => {
    const { container } = render(<AiChatPanel open={false} onClose={vi.fn()} output={makeOutput()} />);
    expect(container).toBeEmptyDOMElement();
  });

  it("appends error bubble when askChat rejects", async () => {
    mockAskChat.mockRejectedValue(new Error("model overloaded"));
    const u = userEvent.setup();
    render(<AiChatPanel open onClose={vi.fn()} output={makeOutput()} />);
    await u.type(screen.getByRole("textbox"), "test question");
    await u.click(screen.getByRole("button", { name: /send/i }));
    expect(await screen.findByText(/AI request failed.*model overloaded/i)).toBeInTheDocument();
  });

  it("calls onClose when Close button clicked", async () => {
    const onClose = vi.fn();
    const u = userEvent.setup();
    render(<AiChatPanel open onClose={onClose} output={makeOutput()} />);
    await u.click(screen.getByRole("button", { name: /close/i }));
    expect(onClose).toHaveBeenCalled();
  });

  it("sends on Enter key in the input", async () => {
    const u = userEvent.setup();
    render(<AiChatPanel open onClose={vi.fn()} output={makeOutput()} />);
    await u.type(screen.getByRole("textbox"), "enter question{Enter}");
    expect(await screen.findByText(/re: enter question/i)).toBeInTheDocument();
  });
});
