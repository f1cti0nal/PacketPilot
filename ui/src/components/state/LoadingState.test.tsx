import { describe, it, expect } from "vitest";
import { render, screen } from "../../test/render";
import { LoadingState } from "./LoadingState";

describe("LoadingState", () => {
  it("renders the default label in a polite status region", () => {
    render(<LoadingState />);
    const status = screen.getByRole("status");
    expect(status).toHaveAttribute("aria-live", "polite");
    expect(screen.getByText("Loading…")).toBeInTheDocument();
  });

  it("renders a custom label", () => {
    render(<LoadingState label="Loading summary…" />);
    expect(screen.getByText("Loading summary…")).toBeInTheDocument();
  });
});
