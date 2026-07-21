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
    // The ribbon div has gap-px and one flex-1 child per bucket (select it by its own aria-label
    // so the forecast-band overlay — also role="img" — isn't matched instead).
    const ribbon = container.querySelector('[aria-label^="Activity"]');
    expect(ribbon).not.toBeNull();
    // Each bucket is a div.relative.flex-1 child of the ribbon
    const cells = ribbon!.querySelectorAll(":scope > div");
    expect(cells).toHaveLength(hist.length);
  });

  it("renders the forecast-band overlay for a multi-bucket capture", () => {
    render(<ActivityHeatmap histogram={hist} bucketSecs={120} findings={findings} />);
    expect(screen.getByLabelText(/Traffic forecast band/i)).toBeInTheDocument();
    expect(screen.getByText(/forecast band/i)).toBeInTheDocument();
  });

  it("marks forecast-anomaly bins when a traffic_anomaly finding covers a bucket", () => {
    // Place a traffic_anomaly window over the first bucket's second.
    const b0 = hist[0].epoch_sec;
    const anomaly = {
      ...findings[0],
      kind: "traffic_anomaly" as const,
      first_seen_ns: b0 * 1e9,
      last_seen_ns: (b0 + 120) * 1e9,
    };
    render(<ActivityHeatmap histogram={hist} bucketSecs={120} findings={[anomaly]} />);
    expect(screen.getByText(/forecast anomaly/i)).toBeInTheDocument();
  });

  it("renders empty state when histogram is empty", () => {
    render(<ActivityHeatmap histogram={[]} bucketSecs={120} findings={[]} />);
    expect(screen.getByText(/No timeline data/i)).toBeInTheDocument();
  });
});
