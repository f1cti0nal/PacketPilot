import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { ReputationChip } from "./ReputationChip";
import type { ReputationVerdict } from "../types";

const v = (source: string, status: ReputationVerdict["status"], score: number | null): ReputationVerdict =>
  ({ source, status, malicious: status === "malicious", score, tags: [], link: null, fetched_at: 0 });

describe("ReputationChip", () => {
  it("shows the worst verdict with provider count", () => {
    render(<ReputationChip reputation={[v("abuseipdb", "malicious", 96), v("greynoise", "benign", 5)]} />);
    expect(screen.getByText(/malicious/i)).toBeInTheDocument();
    expect(screen.getByText(/abuseipdb/i)).toBeInTheDocument();
  });

  it("renders nothing when no verdicts", () => {
    const { container } = render(<ReputationChip reputation={[]} />);
    expect(container).toBeEmptyDOMElement();
  });
});
