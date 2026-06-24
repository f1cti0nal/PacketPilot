import { describe, it, expect } from "vitest";
import { render, screen } from "../test/render";
import { DownloadsCard } from "./DownloadsCard";

describe("DownloadsCard", () => {
  it("renders client ← server rows with the file class and count", () => {
    render(
      <DownloadsCard
        downloads={[
          { client: "10.0.0.9", server: "93.184.216.34", kind: "executable", count: 3 },
          { client: "10.0.0.5", server: "1.2.3.4", kind: "script", count: 1 },
        ]}
      />,
    );
    expect(screen.getByText("Downloads")).toBeInTheDocument();
    expect(screen.getByText("executable")).toBeInTheDocument();
    expect(screen.getByText("10.0.0.9")).toBeInTheDocument();
    expect(screen.getByText("93.184.216.34")).toBeInTheDocument();
    expect(screen.getByText("×3")).toBeInTheDocument();
  });

  it("renders nothing when no downloads were seen", () => {
    render(<DownloadsCard downloads={[]} />);
    expect(screen.queryByText("Downloads")).toBeNull();
  });
});
