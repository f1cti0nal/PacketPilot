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

  it("an expanded card shows its hunt playbook and saves progress per alert", async () => {
    const u = userEvent.setup();
    const saveProgress = vi.fn();
    const loadRuns = vi.fn((a: (typeof alerts)[number]) =>
      Promise.resolve([
        {
          alert_id: a.id,
          alert_title: a.title,
          playbook_id: "c2-channel",
          title: "Command and control channel",
          summary: "",
          origin: "built-in",
          kinds: ["beacon" as const],
          steps: [{ id: "cadence", question: "Is the timing regular?", why: "Timers.", pivots: [] }],
        },
      ]),
    );
    render(
      <AlertsView
        alerts={alerts}
        findings={findings}
        hunt={{ loadRuns, loadProgress: () => ({ done: [], notes: {} }), saveProgress }}
      />,
    );
    expect(screen.queryByText("Hunt playbook")).toBeNull();
    await u.click(screen.getByRole("button", { name: `${alerts[0].title}, Act now` }));
    await screen.findByText("Command and control channel");
    expect(loadRuns).toHaveBeenCalledWith(alerts[0]);
    await u.click(screen.getByRole("checkbox", { name: "Done: Is the timing regular?" }));
    expect(saveProgress).toHaveBeenCalledWith(alerts[0].id, { done: ["c2-channel/cadence"], notes: {} });
  });

  it("manages the team playbook file", async () => {
    const u = userEvent.setup();
    const onImport = vi.fn();
    const onDownloadBuiltin = vi.fn();
    const onRemove = vi.fn();
    const { rerender } = render(
      <AlertsView alerts={alerts} findings={findings} playbooks={{ teamCount: null, onImport, onDownloadBuiltin, onRemove }} />,
    );
    await u.click(screen.getByRole("button", { name: "Hunt playbooks (built-in)" }));
    await u.click(screen.getByRole("button", { name: "Download built-ins" }));
    expect(onDownloadBuiltin).toHaveBeenCalled();
    expect(screen.queryByRole("button", { name: "Remove team file" })).toBeNull();
    const file = new File(['{"version":1,"playbooks":[]}'], "team.json", { type: "application/json" });
    await u.upload(screen.getByLabelText("Import team playbooks"), file);
    expect(onImport).toHaveBeenCalledWith(file);
    rerender(
      <AlertsView
        alerts={alerts}
        findings={findings}
        playbooks={{ teamCount: 2, notice: "Loaded 2 team playbooks", onImport, onDownloadBuiltin, onRemove }}
      />,
    );
    expect(screen.getByRole("button", { name: "Hunt playbooks (built-in + 2 from your team)" })).toBeInTheDocument();
    expect(screen.getByRole("status")).toHaveTextContent("Loaded 2 team playbooks");
    await u.click(screen.getByRole("button", { name: "Remove team file" }));
    expect(onRemove).toHaveBeenCalled();
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

  it("the timeline pivot fires onOpenTimeline with the alert id, on every alert", async () => {
    const u = userEvent.setup();
    const onOpenTimeline = vi.fn();
    render(<AlertsView alerts={alerts} findings={findings} onOpenTimeline={onOpenTimeline} />);
    await u.click(screen.getByRole("button", { name: `${alerts[1].title}, Review` }));
    await u.click(screen.getByRole("button", { name: /open timeline/i }));
    expect(onOpenTimeline).toHaveBeenCalledWith(alerts[1].id);
  });

  it("offers no chain pivot on a rollup alert (no chain_id)", async () => {
    const u = userEvent.setup();
    render(<AlertsView alerts={alerts} findings={findings} onOpenChain={vi.fn()} />);
    await u.click(screen.getByRole("button", { name: `${alerts[1].title}, Review` }));
    expect(screen.queryByRole("button", { name: /open chain/i })).toBeNull();
  });

  describe("teach it once", () => {
    const rule = {
      id: "sup:0000000000000001",
      kind: findings[0].kind,
      src: findings[0].src_ip,
      reason: "lab scanner",
      author: "john",
      expires: "2027-01-27",
    };

    it("Mark benign submits the scope and reason, then shows the outcome", async () => {
      const u = userEvent.setup();
      const onTeach = vi.fn().mockResolvedValue("Saved 1 rule (expires in 90 days).");
      render(<AlertsView alerts={alerts} findings={findings} onTeach={onTeach} />);
      await u.click(screen.getByRole("button", { name: `${alerts[0].title}, Act now` }));
      await u.click(screen.getByRole("button", { name: "Mark benign" }));
      const form = screen.getByRole("form", { name: "Mark benign" });
      const save = within(form).getByRole("button", { name: "Save rule" });
      expect(save).toBeDisabled();
      await u.click(within(form).getByLabelText(/This source host/));
      await u.type(within(form).getByLabelText("Why is this benign?"), "lab scanner");
      await u.click(save);
      expect(onTeach).toHaveBeenCalledWith(alerts[0].id, "source", "lab scanner");
      expect(await screen.findByText("Saved 1 rule (expires in 90 days).")).toBeInTheDocument();
    });

    it("lists suppressed and guardrail-kept findings with the rule that matched", async () => {
      const u = userEvent.setup();
      const onRemoveRule = vi.fn();
      render(
        <AlertsView
          alerts={alerts}
          findings={findings}
          suppressions={[
            { finding_index: 0, rule_id: rule.id, status: "suppressed" },
            { finding_index: 1, rule_id: rule.id, status: "blocked", reason: "threat_intel" },
          ]}
          appliedRules={[rule]}
          onRemoveRule={onRemoveRule}
        />,
      );
      expect(screen.getByText(/1 finding suppressed$/)).toBeInTheDocument();
      await u.click(screen.getByRole("button", { name: "Suppressed (1) · 1 kept by guardrails" }));
      expect(screen.getByText(/Hidden by rule: “lab scanner” \(john\)/)).toBeInTheDocument();
      expect(screen.getByText(/Still shown: a host matched the threat-intel feed/)).toBeInTheDocument();
      await u.click(screen.getByRole("button", { name: "Stop suppressing" }));
      expect(onRemoveRule).toHaveBeenCalledWith(rule);
    });

    it("keeps the view (not the empty state) when every finding was suppressed", () => {
      render(
        <AlertsView
          alerts={[]}
          findings={findings}
          suppressions={[{ finding_index: 0, rule_id: rule.id, status: "suppressed" }]}
          appliedRules={[rule]}
        />,
      );
      expect(screen.queryByText("No alerts")).not.toBeInTheDocument();
      expect(screen.getByText(/every finding was suppressed/)).toBeInTheDocument();
    });

    it("rules manager flags expired rules and deletes, imports and exports", async () => {
      const u = userEvent.setup();
      const onRemoveRule = vi.fn();
      const onImportRules = vi.fn();
      const onExportRules = vi.fn();
      const expired = { ...rule, id: "sup:0000000000000002", src: "10.9.9.9", expires: "2026-01-01" };
      render(
        <AlertsView
          alerts={alerts}
          findings={findings}
          storedRules={[rule, expired]}
          today="2026-10-29"
          onRemoveRule={onRemoveRule}
          onImportRules={onImportRules}
          onExportRules={onExportRules}
        />,
      );
      await u.click(screen.getByRole("button", { name: "Suppression rules (2)" }));
      expect(screen.getByText("expired")).toBeInTheDocument();
      expect(screen.getByText(/expired 2026-01-01/)).toBeInTheDocument();
      await u.click(screen.getByRole("button", { name: "Export" }));
      expect(onExportRules).toHaveBeenCalled();
      const file = new File(['{"rules":[]}'], "suppressions.json", { type: "application/json" });
      await u.upload(screen.getByLabelText("Import suppression rules"), file);
      expect(onImportRules).toHaveBeenCalledWith(file);
      await u.click(screen.getAllByRole("button", { name: /^Delete rule/ })[1]);
      expect(onRemoveRule).toHaveBeenCalledWith(expired);
    });

    it("keeps the rules manager reachable on a capture with no alerts", () => {
      render(<AlertsView alerts={[]} findings={[]} onImportRules={vi.fn()} storedRules={[rule]} />);
      expect(screen.getByText("No alerts")).toBeInTheDocument();
      expect(screen.getByRole("button", { name: "Suppression rules (1)" })).toBeInTheDocument();
    });
  });
});
