import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { FindingMetrics } from "./FindingMetrics";
import type { Finding } from "../../types";

const f = (over: Partial<Finding>): Finding => ({
  kind: "beacon", severity: "high", score: 70, title: "t", src_ip: "1.1.1.1",
  dst_ip: "2.2.2.2", dst_port: 443, attack: [], evidence: [],
  interval_ns: null, jitter_cv: null, contacts: null, ...over,
});

describe("FindingMetrics", () => {
  it("always renders the score badge", () => {
    render(<FindingMetrics finding={f({ score: 82 })} />);
    expect(screen.getByText("82")).toBeInTheDocument();
  });

  it("renders only the metrics that are present", () => {
    render(<FindingMetrics finding={f({ interval_ns: 60_000_000_000, jitter_cv: 0.12, contacts: null })} />);
    expect(screen.getByText("period")).toBeInTheDocument();
    expect(screen.getByText("jitter")).toBeInTheDocument();
    expect(screen.queryByText("contacts")).not.toBeInTheDocument();
  });
});
