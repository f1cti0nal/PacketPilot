import { describe, it, expect, vi } from "vitest";
import userEvent from "@testing-library/user-event";
import { render, screen, within } from "../test/render";
import { TimelineView } from "./TimelineView";
import { makeOutput } from "../test/fixtures";

describe("TimelineView", () => {
  const out = () => makeOutput().summary;

  it("tells the top alert's story in order, every row with its capture filter", () => {
    const s = out();
    render(<TimelineView timelines={s.timelines!} alerts={s.alerts} />);
    expect(screen.getByRole("heading", { name: /Cross-host attack chain/ })).toBeInTheDocument();
    const rows = screen.getAllByTestId("timeline-row");
    expect(rows.map((r) => r.dataset.kind)).toEqual(["detection", "dns_answer", "pivot", "detection"]);
    expect(within(rows[3]).getByText("host 10.66.0.1 and host 45.77.13.37 and port 443")).toBeInTheDocument();
    expect(within(rows[2]).getByText(/Lateral hop 10.13.37.7 → 10.66.0.1/)).toBeInTheDocument();
    expect(within(rows[1]).getByText("+9.00s")).toBeInTheDocument();
  });

  it("carves a row's packets in one click and disables carving without a source", async () => {
    const u = userEvent.setup();
    const onCarve = vi.fn();
    const s = out();
    const { rerender } = render(<TimelineView timelines={s.timelines!} canCarve onCarve={onCarve} />);
    await u.click(screen.getAllByRole("button", { name: /carve packets for detection on 10.66.0.1/i })[0]);
    expect(onCarve).toHaveBeenCalledWith(s.timelines![0].events[3]);

    rerender(<TimelineView timelines={s.timelines!} canCarve={false} onCarve={onCarve} />);
    expect(screen.getAllByRole("button", { name: /carve packets/i })[0]).toBeDisabled();
  });

  it("jumps to a row host's flows", async () => {
    const u = userEvent.setup();
    const onJump = vi.fn();
    render(<TimelineView timelines={out().timelines!} onJumpToFlows={onJump} />);
    await u.click(screen.getAllByRole("button", { name: "Open flows for 10.13.37.7" })[0]);
    expect(onJump).toHaveBeenCalledWith("10.13.37.7");
  });

  it("narrows to a host and back", async () => {
    const u = userEvent.setup();
    render(<TimelineView timelines={out().timelines!} />);
    const group = screen.getByRole("group", { name: "Filter by host" });
    await u.click(within(group).getByRole("button", { name: "10.13.37.7" }));
    expect(screen.getAllByTestId("timeline-row")).toHaveLength(2);
    await u.click(screen.getByRole("button", { name: "Show all hosts" }));
    expect(screen.getAllByTestId("timeline-row")).toHaveLength(4);
  });

  it("switches alerts with the picker and honours the focused alert", async () => {
    const u = userEvent.setup();
    const onFocus = vi.fn();
    const s = out();
    const { rerender } = render(<TimelineView timelines={s.timelines!} alerts={s.alerts} onFocus={onFocus} />);
    await u.selectOptions(screen.getByLabelText("Alert"), "alert:00c0ffee00c0ffee");
    expect(onFocus).toHaveBeenCalledWith("alert:00c0ffee00c0ffee");
    rerender(<TimelineView timelines={s.timelines!} alerts={s.alerts} focusId="alert:00c0ffee00c0ffee" />);
    expect(screen.getByRole("heading", { name: /Weak TLS posture/ })).toBeInTheDocument();
    expect(screen.getAllByText("untimed").length).toBeGreaterThan(0);
  });

  it("copies and exports the shown timeline", async () => {
    const u = userEvent.setup();
    const onCopy = vi.fn();
    const onExport = vi.fn();
    const s = out();
    render(<TimelineView timelines={s.timelines!} onCopy={onCopy} onExport={onExport} notice="Copied to clipboard" />);
    await u.click(screen.getByRole("button", { name: /copy markdown/i }));
    expect(onCopy).toHaveBeenCalledWith(s.timelines![0], "markdown");
    await u.click(screen.getByRole("button", { name: /\.csv/ }));
    expect(onExport).toHaveBeenCalledWith(s.timelines![0], "csv");
    expect(screen.getByRole("status")).toHaveTextContent("Copied to clipboard");
  });

  it("shows an empty state when there are no alerts", () => {
    render(<TimelineView timelines={[]} />);
    expect(screen.getByText(/No incident timeline yet/)).toBeInTheDocument();
  });
});
