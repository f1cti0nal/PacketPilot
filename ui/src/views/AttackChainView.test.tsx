import { describe, it, expect } from "vitest";
import { render, screen } from "../test/render";
import { AttackChainView } from "./AttackChainView";
import { makeOutput } from "../test/fixtures";

describe("AttackChainView", () => {
  const chains = () => makeOutput().summary.attack_chains!;

  it("renders each chain with its swimlane, technique names, and one pivot arrow", () => {
    const { container } = render(<AttackChainView chains={chains()} />);
    expect(screen.getByText(/Cross-host attack chain/)).toBeInTheDocument();
    expect(screen.getByText("Application Layer Protocol")).toBeInTheDocument();
    expect(screen.getAllByTestId("chain-node")).toHaveLength(4);
    // exactly one cross-host pivot connector in the swimlane
    expect(container.querySelectorAll('[data-kind="pivot"]')).toHaveLength(1);
  });

  it("shows an empty state when there are no chains", () => {
    render(<AttackChainView chains={[]} />);
    expect(screen.getByText(/No attack chains reconstructed/i)).toBeInTheDocument();
  });
});
