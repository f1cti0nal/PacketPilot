import { describe, it, expect } from "vitest";
import { render, screen } from "../test/render";
import { AttackMatrixCard } from "./AttackMatrixCard";
import type { Finding, Severity } from "../types";

const f = (severity: Severity, attack: string[]): Finding => ({
  kind: "port_scan",
  severity,
  score: 50,
  title: "t",
  src_ip: "10.0.0.1",
  dst_ip: null,
  dst_port: null,
  attack,
  evidence: [],
  interval_ns: null,
  jitter_cv: null,
  contacts: null,
});

describe("AttackMatrixCard", () => {
  it("renders covered techniques with names and MITRE links", () => {
    render(<AttackMatrixCard findings={[f("high", ["T1046"]), f("critical", ["T1133"])]} />);
    expect(screen.getByText("MITRE ATT&CK coverage")).toBeInTheDocument();
    expect(screen.getByText("T1046")).toBeInTheDocument();
    expect(screen.getByText("Network Service Discovery")).toBeInTheDocument();
    expect(screen.getByText("External Remote Services")).toBeInTheDocument();
    const link = screen.getByRole("link", { name: /T1133/ });
    expect(link).toHaveAttribute("href", "https://attack.mitre.org/techniques/T1133/");
    expect(link).toHaveAttribute("target", "_blank");
  });

  it("renders nothing when no finding carries a technique", () => {
    const { container } = render(<AttackMatrixCard findings={[f("high", [])]} />);
    expect(container).toBeEmptyDOMElement();
  });
});
