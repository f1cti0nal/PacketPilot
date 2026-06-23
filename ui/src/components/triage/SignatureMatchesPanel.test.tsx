import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent } from "../../test/render";
import { SignatureMatchesPanel } from "./SignatureMatchesPanel";
import type { Finding } from "../../types";

const ruleMatch = (over: Partial<Finding> = {}): Finding => ({
  kind: "rule_match",
  severity: "high",
  score: 70,
  title: "C2 beacon pattern",
  src_ip: "10.0.0.5",
  dst_ip: "203.0.113.9",
  dst_port: 443,
  attack: ["T1071"],
  evidence: ["rule sid:1001", "matched content (3 bytes)"],
  interval_ns: null,
  jitter_cv: null,
  contacts: null,
  ...over,
});

const beacon = (): Finding => ({ ...ruleMatch(), kind: "beacon", title: "beaconing", evidence: [] });

describe("SignatureMatchesPanel", () => {
  it("renders a row per rule_match with msg, sid, src→dst:port, and MITRE", () => {
    render(<SignatureMatchesPanel findings={[ruleMatch(), beacon()]} />);
    expect(screen.getByText("C2 beacon pattern")).toBeInTheDocument();
    expect(screen.getByText(/1001/)).toBeInTheDocument();          // the sid
    expect(screen.getByText(/10\.0\.0\.5/)).toBeInTheDocument();   // src
    expect(screen.getByText(/203\.0\.113\.9/)).toBeInTheDocument();// dst
    expect(screen.getByText("T1071")).toBeInTheDocument();         // MITRE chip
    // a non-rule finding is NOT listed
    expect(screen.queryByText("beaconing")).toBeNull();
  });

  it("renders nothing when there are no rule_match findings", () => {
    const { container } = render(<SignatureMatchesPanel findings={[beacon()]} />);
    expect(container).toBeEmptyDOMElement();
  });

  it("renders a rule_match without a sid (evidence lacks one) and does not throw", () => {
    render(<SignatureMatchesPanel findings={[ruleMatch({ evidence: ["matched content (3 bytes)"] })]} />);
    expect(screen.getByText("C2 beacon pattern")).toBeInTheDocument();
  });

  it("a row click pivots to the matched destination via onJump", () => {
    const onJump = vi.fn();
    render(<SignatureMatchesPanel findings={[ruleMatch()]} onJump={onJump} />);
    fireEvent.click(screen.getByRole("button", { name: /View flows for 203\.0\.113\.9/i }));
    expect(onJump).toHaveBeenCalledWith("203.0.113.9"); // dst_ip
  });

  it("falls back to src_ip when dst_ip is null", () => {
    const onJump = vi.fn();
    render(<SignatureMatchesPanel findings={[ruleMatch({ dst_ip: null, dst_port: null })]} onJump={onJump} />);
    fireEvent.click(screen.getByRole("button", { name: /View flows for 10\.0\.0\.5/i }));
    expect(onJump).toHaveBeenCalledWith("10.0.0.5"); // src_ip
  });

  it("renders static (non-button) rows when onJump is absent", () => {
    render(<SignatureMatchesPanel findings={[ruleMatch()]} />);
    expect(screen.getByText("C2 beacon pattern")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /View flows for/i })).toBeNull();
  });
});
