import { describe, expect, it, vi } from "vitest";
import { render, screen } from "../test/render";
import { Dashboard } from "./Dashboard";
import { makeOutput } from "../test/fixtures";

vi.mock("../cockpit/AiSummaryCard", () => ({ AiSummaryCard: () => <div>AI_SUMMARY_STUB</div> }));

const base = { output: makeOutput(), selectedIncident: null, onSelectIncident: vi.fn() };

describe("Dashboard AI gate", () => {
  it("renders the AI summary when on (default)", () => {
    render(<Dashboard {...base} />);
    expect(screen.getByText("AI_SUMMARY_STUB")).toBeInTheDocument();
  });
  it("renders no AI summary when off", () => {
    render(<Dashboard {...base} aiGate="off" />);
    expect(screen.queryByText("AI_SUMMARY_STUB")).not.toBeInTheDocument();
  });
});
