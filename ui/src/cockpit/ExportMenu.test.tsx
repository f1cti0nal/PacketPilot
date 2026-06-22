import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ExportMenu } from "./ExportMenu";

describe("ExportMenu", () => {
  it("opens on click and runs the chosen action", async () => {
    const user = userEvent.setup();
    const run = vi.fn();
    render(<ExportMenu actions={[{ id: "csv", label: "Export CSV", run }]} />);
    await user.click(screen.getByRole("button", { name: /export/i }));
    await user.click(screen.getByText("Export CSV"));
    expect(run).toHaveBeenCalled();
  });

  it("disables the trigger when disabled", () => {
    render(<ExportMenu actions={[]} disabled />);
    expect(screen.getByRole("button", { name: /export/i })).toBeDisabled();
  });
});
