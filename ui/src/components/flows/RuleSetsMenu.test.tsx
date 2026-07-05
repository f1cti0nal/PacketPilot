import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, fireEvent } from "../../test/render";
import { RuleSetsMenu } from "./RuleSetsMenu";
import { saveRuleSet } from "../../lib/ruleSets";

describe("RuleSetsMenu", () => {
  beforeEach(() => localStorage.clear());

  it("applies a saved set via onApply", () => {
    saveRuleSet("c2.rules", "alert tcp any any -> any 443 (content:\"x\"; sid:1;)");
    const onApply = vi.fn();
    render(<RuleSetsMenu onLoadFile={vi.fn()} onApply={onApply} disabled={false} />);
    fireEvent.click(screen.getByText(/Rules/i)); // open
    fireEvent.click(screen.getByText("c2.rules"));
    expect(onApply).toHaveBeenCalledWith(expect.objectContaining({ name: "c2.rules" }));
  });

  it("calls onLoadFile from the load row", () => {
    const onLoadFile = vi.fn();
    render(<RuleSetsMenu onLoadFile={onLoadFile} onApply={vi.fn()} disabled={false} />);
    fireEvent.click(screen.getByText(/Rules/i));
    fireEvent.click(screen.getByText(/Load .rules file/i));
    expect(onLoadFile).toHaveBeenCalled();
  });

  it("disables actions + shows empty-state appropriately", () => {
    render(<RuleSetsMenu onLoadFile={vi.fn()} onApply={vi.fn()} disabled={true} />);
    fireEvent.click(screen.getByText(/Rules/i));
    expect(screen.getByText(/Load .rules file/i).closest("button")).toBeDisabled();
  });

  it("shows empty-state when no sets saved", () => {
    render(<RuleSetsMenu onLoadFile={vi.fn()} onApply={vi.fn()} disabled={false} />);
    fireEvent.click(screen.getByText(/Rules/i));
    expect(screen.getByText(/No saved rule sets yet/i)).toBeTruthy();
  });

  it("deletes a saved set via × button (works even when disabled)", () => {
    saveRuleSet("lateral.rules", "alert tcp any any -> any any (sid:2;)");
    render(<RuleSetsMenu onLoadFile={vi.fn()} onApply={vi.fn()} disabled={true} />);
    fireEvent.click(screen.getByText(/Rules/i));
    expect(screen.getByText("lateral.rules")).toBeTruthy();
    fireEvent.click(screen.getByRole("menuitem", { name: /Delete rule set lateral\.rules/i }));
    expect(screen.queryByText("lateral.rules")).toBeNull();
  });

  it("when canSave=false (free plan) it hides the saved library and shows a Pro upsell, but keeps Load .rules", () => {
    saveRuleSet("c2.rules", "alert tcp any any -> any 443 (sid:1;)");
    render(<RuleSetsMenu onLoadFile={vi.fn()} onApply={vi.fn()} disabled={false} canSave={false} />);
    fireEvent.click(screen.getByText(/Rules/i));
    // One-off load+apply stays available…
    expect(screen.getByText(/Load .rules file/i)).toBeTruthy();
    // …but the saved set is NOT offered, replaced by the Pro upsell.
    expect(screen.queryByText("c2.rules")).toBeNull();
    expect(screen.getByText(/Pro/i)).toBeTruthy();
  });
});
