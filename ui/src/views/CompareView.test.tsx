import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { CompareView } from "./CompareView";
import type { RecentEntry, Summary, IpThreat, Incident, SeverityCounts } from "../types";

const sev = (o: Partial<SeverityCounts> = {}): SeverityCounts => ({ critical: 0, high: 0, medium: 0, low: 0, info: 0, ...o });
const threat = (o: Partial<IpThreat>): IpThreat =>
  ({ ip: "1.1.1.1", ip_class: "public", severity: "low", score: 10, flows: 1, bytes: 1,
     ioc: false, tags: [], attack: [], evidence: [], ...o } as IpThreat);
const incident = (o: Partial<Incident>): Incident =>
  ({ host: "h1", severity: "low", score: 10, title: "t", narrative: "n", stages: [], attack: [], findings: [], ...o } as Incident);
const ent = (id: string, s: Partial<Summary>): RecentEntry =>
  ({ id, name: id, analyzedAt: id === "a" ? 100 : 200, sizeBytes: 1, engineVersion: "x", origin: "browser",
     flowCount: 1, flowsCached: false,
     summary: { summary: { ip_threats: [], incidents: [], severity_counts: sev(), ...s } } } as unknown as RecentEntry);

describe("CompareView", () => {
  it("shows a graceful message when a capture is missing", () => {
    render(<CompareView before={undefined} after={ent("b", {})} onSwap={() => {}} />);
    expect(screen.getByText(/no longer cached/i)).toBeInTheDocument();
  });

  it("renders added / removed / changed threats with field deltas", () => {
    const before = ent("a", { ip_threats: [threat({ ip: "1.1.1.1", score: 40 }), threat({ ip: "2.2.2.2" })] });
    const after = ent("b", { ip_threats: [threat({ ip: "1.1.1.1", score: 85, severity: "critical" }), threat({ ip: "9.9.9.9" })] });
    render(<CompareView before={before} after={after} onSwap={() => {}} />);
    expect(screen.getByText("9.9.9.9")).toBeInTheDocument(); // added
    expect(screen.getByText("2.2.2.2")).toBeInTheDocument(); // removed
    expect(screen.getByText("1.1.1.1")).toBeInTheDocument(); // changed
    expect(screen.getByText(/40\s*→\s*85/)).toBeInTheDocument(); // score delta
  });

  it("shows the unrelated-captures banner when nothing is shared", () => {
    const before = ent("a", { ip_threats: [threat({ ip: "1.1.1.1" })] });
    const after = ent("b", { ip_threats: [threat({ ip: "9.9.9.9" })] });
    render(<CompareView before={before} after={after} onSwap={() => {}} />);
    expect(screen.getByText(/may be unrelated/i)).toBeInTheDocument();
  });

  it("dismisses the unrelated-captures banner when the dismiss button is clicked", async () => {
    const user = userEvent.setup();
    const before = ent("a", { ip_threats: [threat({ ip: "1.1.1.1" })] });
    const after = ent("b", { ip_threats: [threat({ ip: "9.9.9.9" })] });
    render(<CompareView before={before} after={after} onSwap={() => {}} />);
    expect(screen.getByText(/may be unrelated/i)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /dismiss/i }));
    expect(screen.queryByText(/may be unrelated/i)).not.toBeInTheDocument();
  });

  it("shows No differences for identical captures and supports swap", async () => {
    const user = userEvent.setup();
    const onSwap = vi.fn();
    const before = ent("a", { incidents: [incident({ host: "h1" })] });
    const after = ent("b", { incidents: [incident({ host: "h1" })] });
    render(<CompareView before={before} after={after} onSwap={onSwap} />);
    expect(screen.getByText(/no differences/i)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /swap/i }));
    expect(onSwap).toHaveBeenCalled();
  });

  it("does NOT show the unrelated-captures banner when shared > 0", () => {
    const sharedIp = "1.1.1.1";
    const before = ent("a", { ip_threats: [threat({ ip: sharedIp })] });
    const after = ent("b", { ip_threats: [threat({ ip: sharedIp }), threat({ ip: "9.9.9.9" })] });
    render(<CompareView before={before} after={after} onSwap={() => {}} />);
    expect(screen.queryByText(/may be unrelated/i)).not.toBeInTheDocument();
  });

  it("renders removed incidents", () => {
    const before = ent("a", { incidents: [incident({ host: "victim.local" })] });
    const after = ent("b", { incidents: [] });
    render(<CompareView before={before} after={after} onSwap={() => {}} />);
    expect(screen.getByText("victim.local")).toBeInTheDocument();
  });
});
