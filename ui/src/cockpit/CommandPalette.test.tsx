import { describe, it, expect, vi } from "vitest";
import { render, screen, userEvent } from "../test/render";
import { CommandPalette, type PaletteAction } from "./CommandPalette";
import { makeOutput } from "../test/fixtures";

const threats = makeOutput().summary.ip_threats!;
const actions = (run = vi.fn()): PaletteAction[] => [
  { id: "go-flows", label: "Go to Flows", run },
  { id: "load", label: "Load capture", run },
];

describe("CommandPalette", () => {
  it("does not render when closed", () => {
    render(<CommandPalette open={false} onClose={() => {}} actions={actions()} threats={threats} onSelectHost={() => {}} />);
    expect(screen.queryByLabelText("Command palette query")).toBeNull();
  });
  it("filters actions by fuzzy query", async () => {
    const u = userEvent.setup();
    render(<CommandPalette open onClose={() => {}} actions={actions()} threats={[]} onSelectHost={() => {}} />);
    await u.type(screen.getByLabelText("Command palette query"), "flows");
    expect(screen.getByText("Go to Flows")).toBeInTheDocument();
    expect(screen.queryByText("Load capture")).toBeNull();
  });
  it("Enter runs the highlighted action and closes", async () => {
    const u = userEvent.setup(); const run = vi.fn(); const onClose = vi.fn();
    render(<CommandPalette open onClose={onClose} actions={actions(run)} threats={[]} onSelectHost={() => {}} />);
    await u.type(screen.getByLabelText("Command palette query"), "flows");
    await u.keyboard("{Enter}");
    expect(run).toHaveBeenCalled(); expect(onClose).toHaveBeenCalled();
  });
  it("host query → onSelectHost", async () => {
    const u = userEvent.setup(); const onSelectHost = vi.fn();
    render(<CommandPalette open onClose={() => {}} actions={actions()} threats={threats} onSelectHost={onSelectHost} />);
    await u.type(screen.getByLabelText("Command palette query"), "45.77");
    await u.keyboard("{Enter}");
    expect(onSelectHost).toHaveBeenCalledWith("45.77.13.37");
  });
  it("Escape closes", async () => {
    const u = userEvent.setup(); const onClose = vi.fn();
    render(<CommandPalette open onClose={onClose} actions={actions()} threats={[]} onSelectHost={() => {}} />);
    await u.keyboard("{Escape}");
    expect(onClose).toHaveBeenCalled();
  });
});
