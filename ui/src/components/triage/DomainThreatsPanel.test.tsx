import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { DomainThreatsPanel } from "./DomainThreatsPanel";
import type { DomainThreat } from "../../types";

const dom = (o: Partial<DomainThreat>): DomainThreat => ({ host: "a.example", flows: 1, bytes: 1, ...o });

describe("DomainThreatsPanel", () => {
  it("renders nothing when there are no domains", () => {
    const { container } = render(<DomainThreatsPanel domains={[]} />);
    expect(container).toBeEmptyDOMElement();
  });
  it("renders domain hosts and flags malicious ones only", () => {
    render(<DomainThreatsPanel domains={[
      dom({ host: "evil.example", reputation: [{ source: "virustotal", status: "malicious", malicious: true, score: 90, tags: [], link: null, fetched_at: 0 }] }),
      dom({ host: "quota.example", reputation: [{ source: "virustotal", status: "unavailable", malicious: false, score: null, tags: ["quota"], link: null, fetched_at: 0 }] }),
      dom({ host: "plain.example" }),
    ]} />);
    expect(screen.getByText("evil.example")).toBeInTheDocument();
    expect(screen.getByText("plain.example")).toBeInTheDocument();
    // exactly one "malicious" flag (the unavailable/quota domain is NOT flagged)
    expect(screen.getAllByLabelText("malicious").length).toBe(1);
  });
});
