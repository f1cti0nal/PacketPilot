import { describe, expect, it, vi } from "vitest";
import { render, screen, userEvent, waitFor } from "../test/render";
import { HuntPanel } from "./HuntPanel";
import type { Alert, PlaybookRun } from "../types";
import { emptyProgress } from "../lib/playbooks";

const alert = { id: "alert:1", title: "Beacon" } as Alert;

const runs: PlaybookRun[] = [
  {
    alert_id: "alert:1",
    alert_title: "Beacon",
    playbook_id: "c2-channel",
    title: "Command and control channel",
    summary: "A host keeps calling out.",
    origin: "built-in",
    kinds: ["beacon"],
    steps: [
      {
        id: "cadence",
        question: "Is the timing machine-regular?",
        why: "Malware beacons on a timer.",
        normal: "Bursty contacts.",
        bad: "A steady interval.",
        pivots: [
          { label: "Every connection", target: "sql", value: "SELECT * FROM flow WHERE src_ip = '10.0.0.7'" },
          { label: "All flows to 45.77.13.37", target: "flows", value: "45.77.13.37" },
        ],
      },
      {
        id: "new",
        question: "Is this new to the network?",
        why: "New infrastructure is suspicious.",
        pivots: [],
        auto: { found: true, evidence: ["45.77.13.37 was never reached before"] },
      },
      {
        id: "reputation",
        question: "Is the peer already known bad?",
        why: "Intel decides urgency.",
        pivots: [],
        auto: { found: false, evidence: [] },
      },
    ],
  },
];

describe("HuntPanel", () => {
  it("lists steps, pivots, engine answers and tracks progress", async () => {
    const onProgress = vi.fn();
    const onPivot = vi.fn();
    const onExport = vi.fn();
    render(
      <HuntPanel
        alert={alert}
        loadRuns={() => Promise.resolve(runs)}
        initialProgress={emptyProgress()}
        onProgress={onProgress}
        onPivot={onPivot}
        onExport={onExport}
      />,
    );
    await screen.findByText("Command and control channel");
    expect(screen.getByText("0/3 done")).toBeInTheDocument();
    expect(screen.getByText("engine found")).toBeInTheDocument();

    const user = userEvent.setup();
    await user.click(screen.getByRole("checkbox", { name: "Done: Is the timing machine-regular?" }));
    expect(onProgress).toHaveBeenLastCalledWith({ done: ["c2-channel/cadence"], notes: {} });
    expect(screen.getByText("1/3 done")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /^Is the timing machine-regular\?/ }));
    expect(screen.getByText("Malware beacons on a timer.")).toBeInTheDocument();
    expect(screen.getByText("A steady interval.")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Run in Query" }));
    expect(onPivot).toHaveBeenCalledWith(runs[0].steps[0].pivots[0], alert);
    await user.click(screen.getByRole("button", { name: "Filter flows" }));
    expect(onPivot).toHaveBeenLastCalledWith(runs[0].steps[0].pivots[1], alert);

    await user.type(screen.getByRole("textbox", { name: "Note: Is the timing machine-regular?" }), "60s");
    expect(onProgress).toHaveBeenLastCalledWith({ done: ["c2-channel/cadence"], notes: { "c2-channel/cadence": "60s" } });

    await user.click(screen.getByRole("button", { name: "Is the peer already known bad?" }));
    expect(screen.getByText(/Nothing in this capture/)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /^Is this new to the network\?/ }));
    expect(screen.getByText("45.77.13.37 was never reached before")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Export checklist" }));
    expect(onExport).toHaveBeenCalledWith(runs, { done: ["c2-channel/cadence"], notes: { "c2-channel/cadence": "60s" } });
  });

  it("restores saved progress", async () => {
    render(
      <HuntPanel
        alert={alert}
        loadRuns={() => Promise.resolve(runs)}
        initialProgress={{ done: ["c2-channel/new"], notes: {} }}
        onProgress={() => {}}
      />,
    );
    await screen.findByText("1/3 done");
    expect(screen.getByRole("checkbox", { name: "Done: Is this new to the network?" })).toBeChecked();
    // No pivot handler: copy-only, no follow buttons.
    await userEvent.setup().click(screen.getByRole("button", { name: /^Is the timing machine-regular\?/ }));
    expect(screen.queryByRole("button", { name: "Run in Query" })).toBeNull();
    expect(screen.getByRole("button", { name: "Copy Every connection" })).toBeInTheDocument();
  });

  it("shows a load error and hides when there is nothing", async () => {
    const { unmount } = render(
      <HuntPanel
        alert={alert}
        loadRuns={() => Promise.reject(new Error("bad team file"))}
        initialProgress={emptyProgress()}
        onProgress={() => {}}
      />,
    );
    await screen.findByText(/bad team file/);
    unmount();
    render(
      <HuntPanel alert={alert} loadRuns={() => Promise.resolve([])} initialProgress={emptyProgress()} onProgress={() => {}} />,
    );
    await waitFor(() => expect(screen.queryByText("Hunt playbook")).toBeNull());
  });
});
