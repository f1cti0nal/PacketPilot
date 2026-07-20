import { describe, it, expect, vi } from "vitest";
import { render, screen, userEvent, within } from "../test/render";
import { FindingsView } from "./FindingsView";
import type { Finding } from "../types";

// Kind labels also appear in the Kind filter's <option>s, so scope row assertions to the table.
const table = () => screen.getByRole("table");

const f = (over: Partial<Finding> & Pick<Finding, "kind" | "severity" | "src_ip">): Finding => ({
  score: 50,
  title: `${over.kind} on ${over.src_ip}`,
  dst_ip: null,
  dst_port: null,
  attack: [],
  evidence: [],
  interval_ns: null,
  jitter_cv: null,
  contacts: null,
  ...over,
});

const FINDINGS: Finding[] = [
  f({ kind: "port_scan", severity: "high", src_ip: "10.0.0.7", score: 64, attack: ["T1046"] }),
  f({
    kind: "beacon",
    severity: "critical",
    src_ip: "10.0.0.9",
    dst_ip: "45.77.13.37",
    dst_port: 443,
    score: 88,
    attack: ["T1071"],
  }),
  f({ kind: "host_sweep", severity: "medium", src_ip: "10.0.0.7", score: 40, attack: ["T1046"] }),
];

const firstDataRow = () => screen.getAllByRole("row")[1]; // [0] is the header row

describe("FindingsView", () => {
  it("renders the findings worst-severity first by default", () => {
    render(<FindingsView findings={FINDINGS} />);
    expect(within(table()).getByText("Port Scan")).toBeInTheDocument();
    expect(within(table()).getByText("C2 Beacon")).toBeInTheDocument();
    expect(within(table()).getByText("Host Sweep")).toBeInTheDocument();
    expect(firstDataRow().textContent).toContain("C2 Beacon"); // critical first
  });

  it("filters by free text", async () => {
    const u = userEvent.setup();
    render(<FindingsView findings={FINDINGS} />);
    await u.type(screen.getByLabelText("Filter findings"), "beacon");
    expect(within(table()).getByText("C2 Beacon")).toBeInTheDocument();
    expect(within(table()).queryByText("Port Scan")).toBeNull();
  });

  it("filters by severity", async () => {
    const u = userEvent.setup();
    render(<FindingsView findings={FINDINGS} />);
    await u.selectOptions(screen.getByLabelText("Filter by severity"), "critical");
    expect(within(table()).getByText("C2 Beacon")).toBeInTheDocument();
    expect(within(table()).queryByText("Port Scan")).toBeNull();
  });

  it("sorts by a clicked column header", async () => {
    const u = userEvent.setup();
    render(<FindingsView findings={FINDINGS} />);
    await u.click(screen.getByText("Source")); // → ascending by src_ip
    expect(firstDataRow().textContent).toContain("10.0.0.7");
  });

  it("sorts via the keyboard: column headers are real buttons with aria-sort on the th", async () => {
    const u = userEvent.setup();
    render(<FindingsView findings={FINDINGS} />);
    const sourceButton = screen.getByRole("button", { name: "Source" });
    sourceButton.focus();
    await u.keyboard("{Enter}"); // → ascending by src_ip
    expect(firstDataRow().textContent).toContain("10.0.0.7");
    expect(sourceButton.closest("th")).toHaveAttribute("aria-sort", "ascending");
    expect(sourceButton).toHaveFocus(); // focus survives the sort re-render
  });

  it("clicking a row pivots to flows for its source host", async () => {
    const u = userEvent.setup();
    const onJump = vi.fn();
    render(<FindingsView findings={FINDINGS} onJumpToFlows={onJump} />);
    await u.click(within(table()).getByText("C2 Beacon"));
    expect(onJump).toHaveBeenCalledWith({ ip: "10.0.0.9" });
  });

  it("pivots to flows via the keyboard on a focused row", async () => {
    const u = userEvent.setup();
    const onJump = vi.fn();
    render(<FindingsView findings={FINDINGS} onJumpToFlows={onJump} />);
    const row = screen.getByRole("row", { name: /view flows for 10\.0\.0\.9/i });
    row.focus();
    await u.keyboard("{Enter}");
    expect(onJump).toHaveBeenCalledWith({ ip: "10.0.0.9" });
  });

  it("shows an empty state when there are no findings", () => {
    render(<FindingsView findings={[]} />);
    expect(screen.getByText("No behavioral findings")).toBeInTheDocument();
  });
});
