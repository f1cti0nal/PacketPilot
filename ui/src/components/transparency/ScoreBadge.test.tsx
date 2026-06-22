import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { ScoreBadge } from "./ScoreBadge";

describe("ScoreBadge", () => {
  it("renders the rounded score out of 100", () => {
    render(<ScoreBadge score={73} severity="high" />);
    expect(screen.getByText("73")).toBeInTheDocument();
    expect(screen.getByText("/100")).toBeInTheDocument();
  });

  it("clamps out-of-range scores to 0..100", () => {
    render(<ScoreBadge score={150} />);
    expect(screen.getByText("100")).toBeInTheDocument();
  });
});
