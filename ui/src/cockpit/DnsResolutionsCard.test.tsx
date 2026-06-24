import { describe, it, expect } from "vitest";
import { render, screen } from "../test/render";
import { DnsResolutionsCard } from "./DnsResolutionsCard";

describe("DnsResolutionsCard", () => {
  it("renders resolved IP -> domain mappings", () => {
    render(
      <DnsResolutionsCard
        resolved={[
          { ip: "93.184.216.34", domain: "evil.example", resolutions: 3 },
          { ip: "1.1.1.1", domain: "good.example", resolutions: 1 },
        ]}
      />,
    );
    expect(screen.getByText("Passive DNS")).toBeInTheDocument();
    expect(screen.getByText("93.184.216.34")).toBeInTheDocument();
    expect(screen.getByText("evil.example")).toBeInTheDocument();
    expect(screen.getByText("good.example")).toBeInTheDocument();
  });

  it("renders nothing when no DNS answers were seen", () => {
    render(<DnsResolutionsCard resolved={[]} />);
    expect(screen.queryByText("Passive DNS")).toBeNull();
  });
});
