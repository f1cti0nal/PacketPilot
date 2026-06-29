import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { IocDialog } from "./IocDialog";

describe("IocDialog", () => {
  it("disables Match until indicators are entered, previews the count, then matches and closes", () => {
    const onMatch = vi.fn();
    const onClose = vi.fn();
    render(<IocDialog onMatch={onMatch} onClose={onClose} />);

    expect(screen.getByRole("button", { name: "Match" })).toBeDisabled();

    fireEvent.change(screen.getByLabelText("IOC list"), {
      target: { value: "45.77.13.37\nevil.example.com" },
    });

    // live breakdown reflects the parsed indicators
    expect(screen.getByText(/1 IP · 1 domain · 0 hash/)).toBeInTheDocument();

    const match = screen.getByRole("button", { name: "Match 2" });
    expect(match).toBeEnabled();
    fireEvent.click(match);

    expect(onMatch).toHaveBeenCalledWith("45.77.13.37\nevil.example.com");
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("Cancel closes without matching", () => {
    const onMatch = vi.fn();
    const onClose = vi.fn();
    render(<IocDialog onMatch={onMatch} onClose={onClose} />);
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(onClose).toHaveBeenCalled();
    expect(onMatch).not.toHaveBeenCalled();
  });

  it("Ctrl+Enter in the textarea submits the list", () => {
    const onMatch = vi.fn();
    const onClose = vi.fn();
    render(<IocDialog onMatch={onMatch} onClose={onClose} />);
    const ta = screen.getByLabelText("IOC list");
    fireEvent.change(ta, { target: { value: "1.2.3.4" } });
    fireEvent.keyDown(ta, { key: "Enter", ctrlKey: true });
    expect(onMatch).toHaveBeenCalledWith("1.2.3.4");
    expect(onClose).toHaveBeenCalled();
  });
});
