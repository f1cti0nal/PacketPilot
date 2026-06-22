import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { DomainConsent } from "./DomainConsent";

describe("DomainConsent", () => {
  it("names VirusTotal + the count and fires the callbacks", () => {
    const onProceed = vi.fn();
    const onCancel = vi.fn();
    render(<DomainConsent domainCount={3} onProceed={onProceed} onCancel={onCancel} />);
    expect(screen.getAllByText(/VirusTotal/).length).toBeGreaterThan(0);
    expect(screen.getByRole("heading", { name: /3.*domain.*VirusTotal/i })).toBeInTheDocument();
    fireEvent.click(screen.getByText("Proceed"));
    expect(onProceed).toHaveBeenCalledTimes(1);
    fireEvent.click(screen.getByText("Cancel"));
    expect(onCancel).toHaveBeenCalledTimes(1);
  });
});
