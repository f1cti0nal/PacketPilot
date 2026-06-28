import { afterEach, describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AnnouncementBanner } from "./AnnouncementBanner";

afterEach(() => sessionStorage.clear());

describe("AnnouncementBanner", () => {
  it("renders nothing when banner is null or text empty", () => {
    const { container, rerender } = render(<AnnouncementBanner banner={null} />);
    expect(container).toBeEmptyDOMElement();
    rerender(<AnnouncementBanner banner={{ text: "  ", severity: "info", dismissible: true }} />);
    expect(container).toBeEmptyDOMElement();
  });
  it("renders the text and can be dismissed", async () => {
    render(<AnnouncementBanner banner={{ text: "Maintenance soon", severity: "warning", dismissible: true }} />);
    expect(screen.getByText("Maintenance soon")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /dismiss/i }));
    expect(screen.queryByText("Maintenance soon")).not.toBeInTheDocument();
  });
  it("hides the dismiss control when not dismissible", () => {
    render(<AnnouncementBanner banner={{ text: "Notice", severity: "info", dismissible: false }} />);
    expect(screen.queryByRole("button", { name: /dismiss/i })).not.toBeInTheDocument();
  });
});
