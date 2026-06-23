import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { DetailFlyout } from "./DetailFlyout";
import type { Incident } from "../types";
import { makeOutput } from "../test/fixtures";

const incident: Incident = {
  host: "10.0.0.5", severity: "high", score: 75, title: "t", narrative: "n",
  stages: ["Command & Control"], attack: [],
  findings: [{
    kind: "beacon", severity: "high", score: 88, title: "beacon",
    src_ip: "10.0.0.5", dst_ip: "2.2.2.2", dst_port: 443, attack: [],
    evidence: ["c2: periodic beacon 60s"], interval_ns: 60_000_000_000, jitter_cv: 0.1, contacts: 20,
  }],
};

describe("DetailFlyout finding score", () => {
  it("renders the finding score badge", () => {
    render(<DetailFlyout incident={incident} onClose={() => {}} />);
    expect(screen.getByText("88")).toBeInTheDocument();
  });
});

describe("DetailFlyout score waterfall", () => {
  it("renders the score waterfall when scoreEvidence is provided", () => {
    const inc = makeOutput().summary.incidents![0];
    render(
      <DetailFlyout
        incident={inc}
        onClose={() => {}}
        onJumpToFlows={() => {}}
        scoreEvidence={["category c2 (+45)", "ioc: endpoint ip on threat feed (+35)"]}
        hostScore={90}
      />,
    );
    expect(screen.getByText(/Score breakdown/i)).toBeInTheDocument();
    expect(screen.getByText("category c2")).toBeInTheDocument();
  });

  it("omits the score waterfall when scoreEvidence is absent", () => {
    const inc = makeOutput().summary.incidents![0];
    render(<DetailFlyout incident={inc} onClose={() => {}} onJumpToFlows={() => {}} />);
    expect(screen.queryByText(/Score breakdown/i)).toBeNull();
  });
});
