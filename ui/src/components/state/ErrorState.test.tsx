import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent } from "../../test/render";
import { ErrorState } from "./ErrorState";

describe("ErrorState", () => {
  it("renders the message inside an alert region", () => {
    render(<ErrorState message="network error" />);
    expect(screen.getByRole("alert")).toBeInTheDocument();
    expect(screen.getByText("network error")).toBeInTheDocument();
  });

  it("renders no retry button without onRetry", () => {
    render(<ErrorState message="x" />);
    expect(screen.queryByRole("button", { name: /try again/i })).toBeNull();
  });

  it("renders the retry button and fires onRetry when clicked", () => {
    const onRetry = vi.fn();
    render(<ErrorState message="x" onRetry={onRetry} />);
    fireEvent.click(screen.getByRole("button", { name: /try again/i }));
    expect(onRetry).toHaveBeenCalledTimes(1);
  });
});
