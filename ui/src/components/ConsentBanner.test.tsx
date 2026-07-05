import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, cleanup, fireEvent } from "@testing-library/react";

const ga = vi.hoisted(() => ({
  configured: true,
  consent: null as ConsentChoiceT | null,
  grantConsent: vi.fn(),
  denyConsent: vi.fn(),
}));
type ConsentChoiceT = "granted" | "denied";

vi.mock("../lib/analytics/ga", () => ({
  get gaConfigured() {
    return ga.configured;
  },
  getConsent: () => ga.consent,
  grantConsent: ga.grantConsent,
  denyConsent: ga.denyConsent,
}));

import { ConsentBanner } from "./ConsentBanner";

beforeEach(() => {
  ga.configured = true;
  ga.consent = null;
  ga.grantConsent.mockClear();
  ga.denyConsent.mockClear();
});
afterEach(() => cleanup());

describe("ConsentBanner", () => {
  it("shows Accept/Decline when GA is configured and no choice has been made", () => {
    render(<ConsentBanner />);
    expect(screen.getByRole("button", { name: /accept/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /decline/i })).toBeInTheDocument();
  });

  it("renders nothing when GA is not configured", () => {
    ga.configured = false;
    const { container } = render(<ConsentBanner />);
    expect(container).toBeEmptyDOMElement();
  });

  it("renders nothing once a choice already exists", () => {
    ga.consent = "granted";
    const { container } = render(<ConsentBanner />);
    expect(container).toBeEmptyDOMElement();
  });

  it("Accept grants consent and dismisses the banner", () => {
    render(<ConsentBanner />);
    fireEvent.click(screen.getByRole("button", { name: /accept/i }));
    expect(ga.grantConsent).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole("button", { name: /accept/i })).not.toBeInTheDocument();
  });

  it("Decline denies consent and dismisses the banner", () => {
    render(<ConsentBanner />);
    fireEvent.click(screen.getByRole("button", { name: /decline/i }));
    expect(ga.denyConsent).toHaveBeenCalledTimes(1);
    expect(ga.grantConsent).not.toHaveBeenCalled();
    expect(screen.queryByRole("button", { name: /decline/i })).not.toBeInTheDocument();
  });

  it("links to the privacy policy", () => {
    render(<ConsentBanner />);
    expect(screen.getByRole("link", { name: /privacy policy/i })).toHaveAttribute("href", "/privacy");
  });
});
