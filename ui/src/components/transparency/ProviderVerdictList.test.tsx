import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { ProviderVerdictList } from "./ProviderVerdictList";
import type { ReputationVerdict } from "../../types";

const v = (over: Partial<ReputationVerdict>): ReputationVerdict => ({
  source: "abuseipdb", status: "unknown", malicious: false, score: null,
  tags: [], link: null, fetched_at: 1000, ...over,
});

describe("ProviderVerdictList", () => {
  it("renders nothing when there are no verdicts", () => {
    const { container } = render(<ProviderVerdictList verdicts={[]} />);
    expect(container).toBeEmptyDOMElement();
  });

  it("lists every provider, worst status first", () => {
    render(
      <ProviderVerdictList
        now={1000}
        verdicts={[
          v({ source: "greynoise", status: "benign", score: 0 }),
          v({ source: "abuseipdb", status: "malicious", score: 90 }),
        ]}
      />,
    );
    const sources = screen.getAllByText(/greynoise|abuseipdb/).map((n) => n.textContent);
    expect(sources[0]).toBe("abuseipdb"); // malicious sorts first
    expect(screen.getByText("90%")).toBeInTheDocument();
  });

  it("shows an em dash when the score is null and a report link when present", () => {
    render(
      <ProviderVerdictList
        now={1000}
        verdicts={[v({ status: "unknown", score: null, link: "https://example.com/r" })]}
      />,
    );
    expect(screen.getByText("—")).toBeInTheDocument();
    const link = screen.getByRole("link", { name: /report/i });
    expect(link).toHaveAttribute("href", "https://example.com/r");
  });

  it("renders a coarse freshness from fetched_at vs now", () => {
    render(<ProviderVerdictList now={1000 + 3600 * 2} verdicts={[v({ fetched_at: 1000 })]} />);
    expect(screen.getByText("2h ago")).toBeInTheDocument();
  });
});
