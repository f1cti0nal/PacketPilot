import { describe, it, expect } from "vitest";
import { render, screen } from "../../test/render";
import { ScoreWaterfall } from "./ScoreWaterfall";

const evidence = [
  "category c2 (+45)",
  "ioc: endpoint ip on threat feed (+35)",
  "all-internal peers (-10)",
  "clamp: raw 105 -> 100",
];

describe("ScoreWaterfall", () => {
  it("renders a row per additive term, the authoritative final score, and the clamp note", () => {
    render(<ScoreWaterfall evidence={evidence} score={100} severity="critical" />);
    expect(screen.getByText("category c2")).toBeInTheDocument();
    expect(screen.getByText("ioc: endpoint ip on threat feed")).toBeInTheDocument();
    // positive term raises the threat → colored with the *defined* critical token,
    // not the undefined bare --color-critical (which would render invisible).
    const plus = screen.getByText("+45");
    expect(plus.getAttribute("style")).toContain("--color-sev-critical");
    expect(plus.getAttribute("style")).not.toContain("--color-critical)");
    expect(screen.getByText(/-10|−10/)).toBeInTheDocument(); // ascii or unicode minus
    // the final row shows the authoritative score (score prop), not the sum of terms
    expect(screen.getByText("100/100")).toBeInTheDocument();
    expect(screen.getByText(/clamp: raw 105/)).toBeInTheDocument();
  });

  it("renders nothing when there are no terms and no notes", () => {
    const { container } = render(<ScoreWaterfall evidence={[]} score={0} severity="info" />);
    expect(container).toBeEmptyDOMElement();
  });

  it("prefers typed scoreTerms over parsing the evidence strings", () => {
    // scoreTerms present → those bars render; the evidence has DIFFERENT (±N) so we can tell which was used
    render(<ScoreWaterfall evidence={["category c2 (+99)", "clamp: raw 105 -> 100"]} scoreTerms={[{ label: "category c2", points: 45 }]} score={100} severity="critical" />);
    expect(screen.getByText("category c2")).toBeInTheDocument();
    expect(screen.getByText(/\+45/)).toBeInTheDocument();      // from the typed term
    expect(screen.queryByText(/\+99/)).toBeNull();             // NOT parsed from evidence
    expect(screen.getByText(/clamp: raw 105/)).toBeInTheDocument(); // notes still from evidence
  });

  it("falls back to parsing evidence when scoreTerms is absent/empty", () => {
    render(<ScoreWaterfall evidence={["category c2 (+45)"]} score={45} severity="high" />);
    expect(screen.getByText(/\+45/)).toBeInTheDocument();      // parsed
  });
});
