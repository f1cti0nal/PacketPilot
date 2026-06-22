import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { ThreatsPanel } from "./ThreatsPanel";
import type { IpThreat } from "../../types";

const threat: IpThreat = {
  ip: "9.9.9.9", ip_class: "public", severity: "high", score: 80, flows: 3, bytes: 1000,
  ioc: false, tags: ["reputation", "public"], attack: [],
  evidence: ["reputation: abuseipdb malicious 78% (+25)"],
  reputation: [
    { source: "abuseipdb", status: "malicious", malicious: true, score: 78, tags: ["c2"], link: null, fetched_at: 1000 },
  ],
};

describe("ThreatsPanel reputation transparency", () => {
  it("shows the per-provider reputation breakdown and tags on the card", () => {
    render(<ThreatsPanel threats={[threat]} />);
    expect(screen.getByText("abuseipdb")).toBeInTheDocument();
    expect(screen.getByText("78%")).toBeInTheDocument();
  });

  it("renders threat tags", () => {
    render(<ThreatsPanel threats={[threat]} />);
    // "reputation" appears as both a tag chip and an EvidenceList group label — use getAllByText
    expect(screen.getAllByText("reputation").length).toBeGreaterThanOrEqual(1);
    // "public" is in the tags block; it also appears as ip_class text — match the tag chip specifically
    const tagChips = document.querySelectorAll(".t-tag");
    const tagTexts = Array.from(tagChips).map((el) => el.textContent);
    expect(tagTexts).toContain("reputation");
    expect(tagTexts).toContain("public");
  });

  it("renders grouped evidence via EvidenceList", () => {
    render(<ThreatsPanel threats={[threat]} />);
    // EvidenceList groups by prefix: the item text after "reputation:" is rendered
    expect(screen.getByText("abuseipdb malicious 78% (+25)")).toBeInTheDocument();
  });

  it("renders empty state when no threats", () => {
    render(<ThreatsPanel threats={[]} />);
    expect(screen.getByText("No scored threats")).toBeInTheDocument();
  });
});
