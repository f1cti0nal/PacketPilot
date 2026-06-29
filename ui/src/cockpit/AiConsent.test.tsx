import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AiConsent } from "./AiConsent";

describe("AiConsent", () => {
  it("shows the model name and confirms on Proceed", async () => {
    const u = userEvent.setup();
    const onProceed = vi.fn();
    render(<AiConsent model="claude-opus-4-8" onProceed={onProceed} onCancel={vi.fn()} />);
    expect(screen.getByText(/claude-opus-4-8/)).toBeInTheDocument();
    await u.click(screen.getByRole("button", { name: /proceed/i }));
    expect(onProceed).toHaveBeenCalled();
  });

  it("mentions PacketPilot's servers in the body copy", () => {
    render(<AiConsent model="claude-opus-4-8" onProceed={vi.fn()} onCancel={vi.fn()} />);
    expect(screen.getByText(/via PacketPilot's servers/i)).toBeInTheDocument();
  });

  it("mentions derived summary and never raw packets", () => {
    render(<AiConsent model="claude-opus-4-8" onProceed={vi.fn()} onCancel={vi.fn()} />);
    expect(screen.getByText(/derived summary/i)).toBeInTheDocument();
    expect(screen.getByText(/never raw packets/i)).toBeInTheDocument();
  });

  it("calls onCancel when Cancel is clicked", async () => {
    const u = userEvent.setup();
    const onCancel = vi.fn();
    render(<AiConsent model="claude-opus-4-8" onProceed={vi.fn()} onCancel={onCancel} />);
    await u.click(screen.getByRole("button", { name: /cancel/i }));
    expect(onCancel).toHaveBeenCalled();
  });
});
