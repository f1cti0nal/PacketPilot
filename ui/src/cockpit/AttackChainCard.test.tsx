import { describe, it, expect, vi } from "vitest";
import { render, screen, userEvent } from "../test/render";
import { AttackChainCard } from "./AttackChainCard";
import { makeOutput } from "../test/fixtures";

describe("AttackChainCard", () => {
  const chains = () => makeOutput().summary.attack_chains!;

  it("renders the top chain title, MITRE tags, and one node per step", () => {
    render(<AttackChainCard chains={chains()} />);
    expect(screen.getByText(/Cross-host attack chain/)).toBeInTheDocument();
    expect(screen.getByText("T1046")).toBeInTheDocument();
    expect(screen.getAllByTestId("chain-node")).toHaveLength(4);
    // a tactic label rendered on a swimlane node
    expect(screen.getByText("Credential Access")).toBeInTheDocument();
  });

  it("renders nothing when there are no chains", () => {
    const { container } = render(<AttackChainCard chains={[]} />);
    expect(container).toBeEmptyDOMElement();
  });

  it("fires onOpenFinding with the step's finding index on node click", async () => {
    const u = userEvent.setup();
    const onOpen = vi.fn();
    render(<AttackChainCard chains={chains()} onOpenFinding={onOpen} />);
    const nodes = screen.getAllByTestId("chain-node");
    await u.click(nodes[1]); // second step -> finding_index 1
    expect(onOpen).toHaveBeenCalledWith(1);
  });
});
