import { describe, it, expect } from "vitest";
import { render, screen } from "../test/render";
import { ScoreRing, SeverityRing, BeaconRadar } from "./instruments";
import { makeOutput } from "../test/fixtures";

describe("instruments smoke tests", () => {
  it("ScoreRing renders an SVG and shows the score", () => {
    const { container } = render(<ScoreRing score={89} severity="critical" />);
    expect(container.querySelector("svg")).not.toBeNull();
    expect(screen.getByText("89")).toBeInTheDocument();
  });

  it("SeverityRing renders an SVG", () => {
    const counts = makeOutput().summary.severity_counts!;
    const { container } = render(<SeverityRing counts={counts} />);
    expect(container.querySelector("svg")).not.toBeNull();
  });

  it("BeaconRadar renders without throwing", () => {
    const { container } = render(<BeaconRadar />);
    expect(container.querySelector("svg")).not.toBeNull();
  });
});
