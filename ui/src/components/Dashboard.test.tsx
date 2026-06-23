import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, userEvent, fireEvent, act } from "../test/render";
import { Dashboard } from "./Dashboard";
import { makeOutput } from "../test/fixtures";
import { carveSubPcap } from "../lib/packets";

vi.mock("../lib/packets", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../lib/packets")>();
  return {
    ...actual,
    carveSubPcap: vi.fn(async () => ({ ok: true, message: "Carved 3 packets" })),
  };
});

describe("Dashboard", () => {
  it("smoke: renders hero host, threat watchlist, activity heatmap, and category matrix", () => {
    render(
      <Dashboard
        output={makeOutput()}
        selectedIncident={null}
        onSelectIncident={vi.fn()}
      />,
    );
    // Hero host appears in both the hero card and the watchlist (≥2 occurrences)
    expect(screen.getAllByText("10.13.37.7").length).toBeGreaterThanOrEqual(2);
    // Threat watchlist card
    expect(screen.getByText("Threat watchlist")).toBeInTheDocument();
    // ActivityHeatmap renders its card title
    expect(screen.getByText("Activity")).toBeInTheDocument();
    // CategoryMatrix renders its card
    expect(screen.getByText(/Category threat matrix/i)).toBeInTheDocument();
  });

  it("renders incident flyout dialog when selectedIncident is set", () => {
    const incident = makeOutput().summary.incidents![0];
    render(
      <Dashboard
        output={makeOutput()}
        selectedIncident={incident}
        onSelectIncident={vi.fn()}
      />,
    );
    expect(
      screen.getByRole("dialog", {
        name: /Incident detail for 10\.13\.37\.7/i,
      }),
    ).toBeInTheDocument();
  });

  it("flyout is absent when selectedIncident is null", () => {
    render(
      <Dashboard
        output={makeOutput()}
        selectedIncident={null}
        onSelectIncident={vi.fn()}
      />,
    );
    expect(
      screen.queryByRole("dialog", { name: /Incident detail/i }),
    ).toBeNull();
  });

  it("clicking a watchlist host with a known incident calls onSelectIncident", async () => {
    const u = userEvent.setup();
    const onSelectIncident = vi.fn();
    render(
      <Dashboard
        output={makeOutput()}
        selectedIncident={null}
        onSelectIncident={onSelectIncident}
      />,
    );
    // The watchlist card has a button for 10.13.37.7 (known incident host)
    const btn = screen.getByRole("button", { name: /10\.13\.37\.7.*critical/i });
    await u.click(btn);
    expect(onSelectIncident).toHaveBeenCalledWith(
      expect.objectContaining({ host: "10.13.37.7" }),
    );
  });

  it("clicking a category in CategoryMatrix calls onJumpToFlows with category", async () => {
    const u = userEvent.setup();
    const onJumpToFlows = vi.fn();
    render(
      <Dashboard
        output={makeOutput()}
        selectedIncident={null}
        onSelectIncident={vi.fn()}
        onJumpToFlows={onJumpToFlows}
      />,
    );
    // CategoryMatrix renders category labels as clickable rows; "web" category present in fixture
    const webRow = screen.getAllByRole("button", { name: /web/i })[0];
    await u.click(webRow);
    expect(onJumpToFlows).toHaveBeenCalledWith(
      expect.objectContaining({ category: expect.stringContaining("web") }),
    );
  });
});

describe("Dashboard host carve", () => {
  beforeEach(() => {
    vi.mocked(carveSubPcap).mockClear();
  });

  it("carve button is disabled when no source is retained", () => {
    render(
      <Dashboard
        output={makeOutput()}
        activeSource={null}
        selectedIncident={null}
        onSelectIncident={vi.fn()}
      />,
    );
    expect(
      screen.getByRole("button", { name: /Carve 10\.13\.37\.7 host/i }),
    ).toBeDisabled();
  });

  it("clicking the carve button calls carveSubPcap with the host ip + whole-capture window", async () => {
    render(
      <Dashboard
        output={makeOutput()}
        activeSource={{ kind: "bytes", bytes: new ArrayBuffer(8) }}
        selectedIncident={null}
        onSelectIncident={vi.fn()}
      />,
    );
    await act(async () => {
      fireEvent.click(
        screen.getByRole("button", { name: /Carve 10\.13\.37\.7 host/i }),
      );
    });
    expect(carveSubPcap).toHaveBeenCalledWith(
      expect.objectContaining({ host: "10.13.37.7", start_ns: 0, end_ns: 9e18 }),
      expect.objectContaining({ kind: "bytes" }),
      expect.stringContaining("10.13.37.7"),
    );
  });

  it("the carve click does not trigger the card's onSelect pivot", async () => {
    const onSelectIncident = vi.fn();
    render(
      <Dashboard
        output={makeOutput()}
        activeSource={{ kind: "bytes", bytes: new ArrayBuffer(8) }}
        selectedIncident={null}
        onSelectIncident={onSelectIncident}
      />,
    );
    await act(async () => {
      fireEvent.click(
        screen.getByRole("button", { name: /Carve 10\.13\.37\.7 host/i }),
      );
    });
    expect(onSelectIncident).not.toHaveBeenCalled();
  });
});
