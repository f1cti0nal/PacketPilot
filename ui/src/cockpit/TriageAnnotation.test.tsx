import { describe, it, expect, beforeEach } from "vitest";
import { render, screen, fireEvent } from "../test/render";
import { TriageAnnotation, TriageBadge } from "./TriageAnnotation";
import { getAnnotation } from "../lib/annotations";

beforeEach(() => localStorage.clear());

describe("TriageAnnotation", () => {
  it("persists a status selection and a note", () => {
    render(<TriageAnnotation captureKey="cap1" ip="10.0.0.1" />);

    fireEvent.click(screen.getByRole("button", { name: "Escalated" }));
    expect(getAnnotation("cap1", "10.0.0.1")?.status).toBe("escalated");
    expect(screen.getByRole("button", { name: "Escalated" })).toHaveAttribute("aria-pressed", "true");

    fireEvent.change(screen.getByLabelText("Triage note"), { target: { value: "c2 confirmed" } });
    expect(getAnnotation("cap1", "10.0.0.1")?.note).toBe("c2 confirmed");
  });

  it("shows no badge until triaged, then reflects the status live (event-synced)", () => {
    const { container } = render(
      <>
        <TriageBadge captureKey="cap1" ip="10.0.0.9" />
        <TriageAnnotation captureKey="cap1" ip="10.0.0.9" />
      </>,
    );
    expect(container.querySelector('[data-component="TriageBadge"]')).toBeNull();

    fireEvent.click(screen.getByRole("button", { name: "Cleared" }));
    expect(screen.getByLabelText("Triage: Cleared")).toBeInTheDocument();
  });
});
