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

  it("BeaconRadar defaults to a 4.2s sweep when no interval is provided", () => {
    const { container } = render(<BeaconRadar />);
    const sweep = container.querySelector(".radar-sweep") as HTMLElement;
    expect(sweep.style.animation).toContain("4.2s");
  });

  it("BeaconRadar sweep mirrors the beacon interval when provided", () => {
    const { container } = render(<BeaconRadar intervalSeconds={5} />);
    const sweep = container.querySelector(".radar-sweep") as HTMLElement;
    expect(sweep.style.animation).toContain("radar-spin 5s");
  });

  it("BeaconRadar clamps the sweep period into the readable 2-10s band", () => {
    const fast = render(<BeaconRadar intervalSeconds={0.4} />);
    expect(
      (fast.container.querySelector(".radar-sweep") as HTMLElement).style.animation,
    ).toContain("radar-spin 2s");
    const slow = render(<BeaconRadar intervalSeconds={3600} />);
    expect(
      (slow.container.querySelector(".radar-sweep") as HTMLElement).style.animation,
    ).toContain("radar-spin 10s");
  });
});
