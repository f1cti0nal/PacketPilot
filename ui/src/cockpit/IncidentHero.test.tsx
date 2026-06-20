import { describe, it, expect, vi } from "vitest";
import { render, screen, userEvent } from "../test/render";
import { IncidentHero } from "./IncidentHero";
import { makeOutput } from "../test/fixtures";

describe("IncidentHero", () => {
  const incident = makeOutput().summary.incidents![0];

  it("renders the host, score, kill-chain stage, beacon lock, and MITRE tag", () => {
    render(<IncidentHero incident={incident} primary onPivot={() => {}} onOpen={() => {}} />);
    // host
    expect(screen.getByText("10.13.37.7")).toBeInTheDocument();
    // score ring shows "89"
    expect(screen.getByText("89")).toBeInTheDocument();
    // one kill-chain stage label
    expect(screen.getByText("Discovery")).toBeInTheDocument();
    // beacon section label
    expect(screen.getByText(/Beacon lock/i)).toBeInTheDocument();
    // MITRE tag
    expect(screen.getByText("T1046")).toBeInTheDocument();
  });

  it("calls onPivot when the pivot button is clicked", async () => {
    const u = userEvent.setup();
    const onPivot = vi.fn();
    render(<IncidentHero incident={incident} primary onPivot={onPivot} onOpen={() => {}} />);
    const pivotBtn = screen.getByRole("button", { name: /Pivot to host/i });
    await u.click(pivotBtn);
    expect(onPivot).toHaveBeenCalledWith("10.13.37.7");
  });

  it("calls onOpen when an evidence finding button is clicked", async () => {
    const u = userEvent.setup();
    const onOpen = vi.fn();
    render(<IncidentHero incident={incident} primary onPivot={() => {}} onOpen={onOpen} />);
    const evidenceBtn = screen.getAllByRole("button", { name: /Open details/i })[0];
    await u.click(evidenceBtn);
    expect(onOpen).toHaveBeenCalled();
  });
});
