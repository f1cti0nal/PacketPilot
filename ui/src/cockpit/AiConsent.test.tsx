import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AiConsent } from "./AiConsent";

describe("AiConsent", () => {
  it("shows the endpoint and confirms on Proceed", async () => {
    const u = userEvent.setup(); const onProceed = vi.fn();
    render(<AiConsent baseUrl="https://api.anthropic.com/v1" model="claude-opus-4-8" onProceed={onProceed} onCancel={vi.fn()} />);
    expect(screen.getByText(/anthropic\.com/)).toBeInTheDocument();
    await u.click(screen.getByRole("button", { name: /proceed/i }));
    expect(onProceed).toHaveBeenCalled();
  });

  it("shows localhost note for local endpoints", () => {
    render(<AiConsent baseUrl="http://localhost:11434/v1" model="llama3.1" onProceed={vi.fn()} onCancel={vi.fn()} />);
    expect(screen.getByText(/stays on this device/i)).toBeInTheDocument();
  });

  it("does NOT show the local note for a spoofed-localhost host", () => {
    render(<AiConsent baseUrl="http://localhost.evil.com/v1" model="m" onProceed={vi.fn()} onCancel={vi.fn()} />);
    expect(screen.queryByText(/stays on this device/i)).toBeNull();
    // …and it warns that this cloud endpoint needs a relay in the browser.
    expect(screen.getByText(/needs a/i)).toBeInTheDocument();
  });

  it("warns a cloud endpoint needs a relay; a localhost endpoint does not", () => {
    const { unmount } = render(<AiConsent baseUrl="https://api.anthropic.com/v1" model="m" onProceed={vi.fn()} onCancel={vi.fn()} />);
    expect(screen.getByText(/relay URL/i)).toBeInTheDocument();
    unmount();
    render(<AiConsent baseUrl="http://localhost:11434/v1" model="m" onProceed={vi.fn()} onCancel={vi.fn()} />);
    expect(screen.queryByText(/relay URL/i)).toBeNull();
  });

  it("calls onCancel when Cancel is clicked", async () => {
    const u = userEvent.setup();
    const onCancel = vi.fn();
    render(<AiConsent baseUrl="https://api.anthropic.com/v1" model="claude-opus-4-8" onProceed={vi.fn()} onCancel={onCancel} />);
    await u.click(screen.getByRole("button", { name: /cancel/i }));
    expect(onCancel).toHaveBeenCalled();
  });
});
