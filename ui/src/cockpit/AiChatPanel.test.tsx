import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AiChatPanel } from "./AiChatPanel";
import { makeOutput } from "../test/fixtures";

vi.mock("../lib/ai/settings", () => ({
  getAiConfig: () => ({ enabled: true, baseUrl: "u", model: "m", apiKey: "k" }),
}));
vi.mock("../lib/ai/run", () => ({
  askChat: vi.fn(async (_o, _h, q, _c, onToken) => { onToken(`re: ${q}`); return `re: ${q}`; }),
}));

describe("AiChatPanel", () => {
  beforeEach(() => vi.clearAllMocks());
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
});
