import { describe, it, expect } from "vitest";
import { render, screen } from "../test/render";
import { ActivityHeatmap } from "./ActivityHeatmap";
import { makeOutput } from "../test/fixtures";

describe("ActivityHeatmap", () => {
  const output = makeOutput();
  const hist = output.summary.time_histogram;
  const findings = output.summary.findings!;

  it("with a data_exfil finding: caption reads 'exfil burst'", () => {
    render(<ActivityHeatmap histogram={hist} bucketSecs={120} findings={findings} />);
    // The axis line text reads "bright column = exfil burst"
    expect(screen.getByText(/exfil burst/i)).toBeInTheDocument();
  });

  it("without a data_exfil finding: caption reads 'peak volume'", () => {
    render(<ActivityHeatmap histogram={hist} bucketSecs={120} findings={[]} />);
    expect(screen.getByText(/peak volume/i)).toBeInTheDocument();
  });

  it("renders a cell for each histogram bucket (12 buckets in the fixture)", () => {
    const { container } = render(
      <ActivityHeatmap histogram={hist} bucketSecs={120} findings={findings} />,
    );
    // The ribbon div has gap-px and one flex-1 child per bucket
    const ribbon = container.querySelector('[role="img"]');
    expect(ribbon).not.toBeNull();
    // Each bucket is a div.relative.flex-1 child of the ribbon
    const cells = ribbon!.querySelectorAll(":scope > div");
    expect(cells).toHaveLength(hist.length);
  });

  it("renders empty state when histogram is empty", () => {
    render(<ActivityHeatmap histogram={[]} bucketSecs={120} findings={[]} />);
    expect(screen.getByText(/No timeline data/i)).toBeInTheDocument();
  });
});
