import { describe, it, expect, vi } from "vitest";
import { render, screen, userEvent, within } from "../test/render";
import { AlertsView } from "./AlertsView";
import { makeOutput } from "../test/fixtures";

const out = makeOutput();
const alerts = out.summary.alerts!;
const findings = out.summary.findings!;

describe("AlertsView", () => {
  it("renders the ranked cards in the given (engine) order without re-sorting", () => {
    render(<AlertsView alerts={alerts} findings={findings} />);
    const cards = screen.getAllByRole("button", { expanded: false });
    expect(cards).toHaveLength(alerts.length);
    expect(cards[0]).toHaveAccessibleName(`${alerts[0].title}, Act now`);
    expect(cards[1]).toHaveAccessibleName(`${alerts[1].title}, Review`);
  });

  it("shows a severity chip on every card, band and severity disagreeing included", () => {
    render(<AlertsView alerts={alerts} findings={findings} />);
    // rollup: band review (rank) + severity medium (judgment) — both visible on one card
    const rollup = screen.getByRole("button", { name: `${alerts[1].title}, Review` });
    expect(within(rollup).getByText("Review")).toBeInTheDocument();
    expect(within(rollup).getByText("Medium")).toBeInTheDocument();
  });

  it("shows an empty state when there are no alerts", () => {
    render(<AlertsView alerts={[]} findings={[]} />);
    expect(screen.getByText("No alerts")).toBeInTheDocument();
  });

  it("shows the derived verdict strip counts", () => {
    render(<AlertsView alerts={alerts} findings={findings} />);
    // 2 alerts covering 3 + 1 findings; one act_now, zero investigate.
    expect(screen.getByText("2 alerts from 4 findings — 1 act now, 0 investigate")).toBeInTheDocument();
  });

  it("collapsed card carries band, severity, priority, confidence, actor identity, and the action line", () => {
    render(<AlertsView alerts={alerts} findings={findings} />);
    const card = screen.getByRole("button", { name: `${alerts[0].title}, Act now` });
    expect(within(card).getByText("Act now")).toBeInTheDocument();
    // severity (judgment axis) rides beside the band chip (rank axis) — the UI shows both
    expect(within(card).getByText("Critical")).toBeInTheDocument();
    expect(within(card).getByText("92/100")).toBeInTheDocument();
    expect(within(card).getByText("conf 92%")).toBeInTheDocument();
    expect(within(card).getByText(/ACCT-LT-042/)).toBeInTheDocument();
    expect(within(card).getByText(/covers 3 findings/)).toBeInTheDocument();
    expect(within(card).getByText(/Isolate 10\.66\.0\.1/)).toBeInTheDocument();
    // context chips from the joined bundle
    expect(within(card).getByText("IOC")).toBeInTheDocument();
    expect(within(card).getByText("reputation")).toBeInTheDocument();
    expect(within(card).getByText("new host behavior")).toBeInTheDocument();
  });

  it("expanding a card reveals the priority ledger and the member finding rows", async () => {
    const u = userEvent.setup();
    render(<AlertsView alerts={alerts} findings={findings} />);
    const card = screen.getByRole("button", { name: `${alerts[0].title}, Act now` });
    await u.click(card);
    expect(card).toHaveAttribute("aria-expanded", "true");
    // ledger rows via formatTerm — one per term, byte-exact "(±N)" idiom
    expect(screen.getByText("base: attack-chain score (+87)")).toBeInTheDocument();
    expect(screen.getByText("novel: deviates from learned baseline (+5)")).toBeInTheDocument();
    // member rows resolved via finding_indices → findings[i]
    expect(screen.getByText("Host sweep: 10.13.37.7 probed 24 hosts on port 445")).toBeInTheDocument();
    expect(screen.getByText("C2 Beacon")).toBeInTheDocument();
    // context entries with their kind tags
    expect(screen.getByText("threat intel")).toBeInTheDocument();
    expect(screen.getByText(/matches the offline IOC feed/)).toBeInTheDocument();
  });

  it("member rows resolve the right finding title for each alert", async () => {
    const u = userEvent.setup();
    render(<AlertsView alerts={alerts} findings={findings} />);
    await u.click(screen.getByRole("button", { name: `${alerts[1].title}, Review` }));
    // The rollup covers finding index 3 — the weak-TLS row, not the chain members.
    expect(screen.getByText("Weak TLS: 10.0.0.9 negotiated TLS 1.0 with 10.0.0.42:8443")).toBeInTheDocument();
    expect(screen.queryByText("Host sweep: 10.13.37.7 probed 24 hosts on port 445")).toBeNull();
  });

  it("guards out-of-range finding indices without crashing", async () => {
    const u = userEvent.setup();
    const broken = [{ ...alerts[1], finding_indices: [99], finding_count: 1 }];
    render(<AlertsView alerts={broken} findings={findings} />);
    await u.click(screen.getByRole("button", { name: `${alerts[1].title}, Review` }));
    expect(screen.queryByText("Covered findings")).toBeNull();
  });

  it("the chain pivot fires onOpenChain with the alert's chain_id", async () => {
    const u = userEvent.setup();
    const onOpenChain = vi.fn();
    render(<AlertsView alerts={alerts} findings={findings} onOpenChain={onOpenChain} />);
    await u.click(screen.getByRole("button", { name: `${alerts[0].title}, Act now` }));
    await u.click(screen.getByRole("button", { name: /open chain/i }));
    expect(onOpenChain).toHaveBeenCalledWith("chain:00ff");
  });

  it("offers no chain pivot on a rollup alert (no chain_id)", async () => {
    const u = userEvent.setup();
    render(<AlertsView alerts={alerts} findings={findings} onOpenChain={vi.fn()} />);
    await u.click(screen.getByRole("button", { name: `${alerts[1].title}, Review` }));
    expect(screen.queryByRole("button", { name: /open chain/i })).toBeNull();
  });
});
