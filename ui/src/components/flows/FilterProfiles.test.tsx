import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { FilterProfiles } from "./FilterProfiles";
import { saveProfile, listProfiles, type FlowFilter } from "../../lib/filterProfiles";

const cur: FlowFilter = { query: "1.2.3.4", category: "c2", severity: undefined, proto: undefined };

describe("FilterProfiles", () => {
  beforeEach(() => localStorage.clear());

  it("applies a saved profile via onApply", () => {
    saveProfile("C2", { query: "9.9.9.9", category: "c2" });
    const onApply = vi.fn();
    render(<FilterProfiles current={cur} hasActiveFilters onApply={onApply} />);
    fireEvent.click(screen.getByText("Profiles")); // open the menu
    fireEvent.click(screen.getByText("C2"));
    expect(onApply).toHaveBeenCalledWith(expect.objectContaining({ query: "9.9.9.9", category: "c2" }));
  });

  it("save-current persists the active filter", () => {
    render(<FilterProfiles current={cur} hasActiveFilters onApply={vi.fn()} />);
    fireEvent.click(screen.getByText("Profiles"));
    // Type name into the inline input, then click Save current
    const nameInput = screen.getByPlaceholderText("Profile name…");
    fireEvent.change(nameInput, { target: { value: "hunt" } });
    fireEvent.click(screen.getByText("Save current"));
    // The row "hunt" should now appear in the dropdown
    expect(screen.getByText("hunt")).toBeInTheDocument();
    // And localStorage should have persisted it
    const saved = listProfiles();
    expect(saved.some((p) => p.name === "hunt")).toBe(true);
    expect(saved.find((p) => p.name === "hunt")?.filter).toMatchObject({ query: "1.2.3.4", category: "c2" });
  });

  it("save-current is disabled with no active filters", () => {
    render(<FilterProfiles current={cur} hasActiveFilters={false} onApply={vi.fn()} />);
    fireEvent.click(screen.getByText("Profiles"));
    expect(screen.getByText(/save current/i).closest("button")).toBeDisabled();
  });

  it("deletes a profile via the × button", () => {
    saveProfile("ToDelete", { query: "1.1.1.1", category: "web" });
    render(<FilterProfiles current={cur} hasActiveFilters onApply={vi.fn()} />);
    fireEvent.click(screen.getByText("Profiles"));
    expect(screen.getByText("ToDelete")).toBeInTheDocument();
    const deleteBtn = screen.getByLabelText("Delete profile ToDelete");
    fireEvent.click(deleteBtn);
    expect(screen.queryByText("ToDelete")).not.toBeInTheDocument();
    expect(listProfiles().some((p) => p.name === "ToDelete")).toBe(false);
  });

  it("shows empty-state text when no profiles are saved", () => {
    render(<FilterProfiles current={cur} hasActiveFilters onApply={vi.fn()} />);
    fireEvent.click(screen.getByText("Profiles"));
    expect(screen.getByText(/No saved profiles yet/i)).toBeInTheDocument();
  });

  it("save button is also disabled when name is empty even with active filters", () => {
    render(<FilterProfiles current={cur} hasActiveFilters onApply={vi.fn()} />);
    fireEvent.click(screen.getByText("Profiles"));
    // Name is empty by default → disabled
    expect(screen.getByText(/save current/i).closest("button")).toBeDisabled();
  });

  it("calls onNotice after a successful import", async () => {
    const onNotice = vi.fn();
    const profileJson = JSON.stringify([
      { id: "fp_imported", name: "Imported", filter: { query: "5.5.5.5", category: "dns" } },
    ]);
    render(<FilterProfiles current={cur} hasActiveFilters onApply={vi.fn()} onNotice={onNotice} />);
    fireEvent.click(screen.getByText("Profiles"));

    // Simulate file input change with a Blob as the file
    const file = new File([profileJson], "profiles.json", { type: "application/json" });
    const fileInput = document.querySelector('input[type="file"]') as HTMLInputElement;
    Object.defineProperty(fileInput, "files", { value: [file] });

    // FileReader is not available in jsdom; mock it
    const origFR = globalThis.FileReader;
    const mockFR = {
      onload: null as ((ev: ProgressEvent<FileReader>) => void) | null,
      readAsText(_f: File) {
        // schedule synchronously via timeout
        Promise.resolve().then(() => {
          if (this.onload) this.onload({ target: { result: profileJson } } as unknown as ProgressEvent<FileReader>);
        });
      },
    };
    globalThis.FileReader = vi.fn(() => mockFR) as unknown as typeof FileReader;

    fireEvent.change(fileInput);

    // Wait for the async readAsText mock to resolve
    await new Promise((r) => setTimeout(r, 0));

    expect(onNotice).toHaveBeenCalledWith(expect.stringMatching(/imported/i));

    globalThis.FileReader = origFR;
  });
});
