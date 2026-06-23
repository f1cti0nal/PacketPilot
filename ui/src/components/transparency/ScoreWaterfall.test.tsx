import { describe, it, expect } from "vitest";
import { render, screen } from "../../test/render";
import { ScoreWaterfall } from "./ScoreWaterfall";

const evidence = [
  "category c2 (+45)",
  "ioc: endpoint ip on threat feed (+35)",
  "all-internal peers (-10)",
  "clamp: raw 105 -> 100",
];

describe("ScoreWaterfall", () => {
  it("renders a row per additive term, the final score, and the clamp note", () => {
    render(<ScoreWaterfall evidence={evidence} score={100} severity="critical" />);
    expect(screen.getByText("category c2")).toBeInTheDocument();
    expect(screen.getByText("ioc: endpoint ip on threat feed")).toBeInTheDocument();
    expect(screen.getByText(/\+45/)).toBeInTheDocument();
    expect(screen.getByText(/-10|−10/)).toBeInTheDocument(); // ascii or unicode minus
    expect(screen.getAllByText(/Score/i).length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText(/100/).length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText(/clamp: raw 105/)).toBeInTheDocument();
  });

  it("renders nothing when there are no terms and no notes", () => {
    const { container } = render(<ScoreWaterfall evidence={[]} score={0} severity="info" />);
    expect(container).toBeEmptyDOMElement();
  });
});
