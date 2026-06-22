import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ReputationConsent } from "./ReputationConsent";

describe("ReputationConsent", () => {
  it("renders the consent dialog with ip count and providers", () => {
    render(<ReputationConsent ipCount={5} providers={["abuseipdb", "greynoise"]} onProceed={vi.fn()} onCancel={vi.fn()} />);
    expect(screen.getByRole("dialog", { name: /reputation consent/i })).toBeInTheDocument();
    expect(screen.getByText(/5 external IPs/i)).toBeInTheDocument();
    expect(screen.getByText(/abuseipdb/i)).toBeInTheDocument();
    expect(screen.getByText(/greynoise/i)).toBeInTheDocument();
  });

  it("uses singular 'IP' for a single ip", () => {
    render(<ReputationConsent ipCount={1} providers={["virustotal"]} onProceed={vi.fn()} onCancel={vi.fn()} />);
    // 1 IP → singular
    expect(screen.getByText(/1 public IP will be sent/i)).toBeInTheDocument();
  });

  it("calls onProceed when Proceed is clicked", async () => {
    const onProceed = vi.fn();
    const u = userEvent.setup();
    render(<ReputationConsent ipCount={3} providers={["abuseipdb"]} onProceed={onProceed} onCancel={vi.fn()} />);
    await u.click(screen.getByRole("button", { name: /proceed/i }));
    expect(onProceed).toHaveBeenCalled();
  });

  it("calls onCancel when Cancel is clicked", async () => {
    const onCancel = vi.fn();
    const u = userEvent.setup();
    render(<ReputationConsent ipCount={3} providers={["abuseipdb"]} onProceed={vi.fn()} onCancel={onCancel} />);
    await u.click(screen.getByRole("button", { name: /cancel/i }));
    expect(onCancel).toHaveBeenCalled();
  });
});
