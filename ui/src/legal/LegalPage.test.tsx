import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { LegalPage } from "./LegalPage";
import type { LegalContent } from "./types";

const content: LegalContent = {
  title: "Test Policy",
  subtitle: "a subtitle",
  updated: "June 29, 2026",
  lead: "the lead paragraph",
  sections: [
    { heading: "First section", blocks: [{ p: "a paragraph" }, { bullets: ["alpha", "beta"] }] },
  ],
  faq: [{ q: "Is it safe?", a: "Yes." }],
};

describe("LegalPage", () => {
  it("renders title, lead, section heading, paragraph, and bullets", () => {
    render(<LegalPage content={content} />);
    expect(screen.getByRole("heading", { level: 1, name: "Test Policy" })).toBeInTheDocument();
    expect(screen.getByText(/last updated june 29, 2026/i)).toBeInTheDocument();
    expect(screen.getByText("the lead paragraph")).toBeInTheDocument();
    expect(screen.getByRole("heading", { level: 2, name: "First section" })).toBeInTheDocument();
    expect(screen.getByText("a paragraph")).toBeInTheDocument();
    expect(screen.getByText("alpha")).toBeInTheDocument();
    expect(screen.getByText("beta")).toBeInTheDocument();
    expect(screen.getAllByRole("listitem")).toHaveLength(2);
  });

  it("renders the FAQ when present", () => {
    render(<LegalPage content={content} />);
    expect(screen.getByRole("heading", { name: /frequently asked/i })).toBeInTheDocument();
    expect(screen.getByRole("heading", { level: 3, name: "Is it safe?" })).toBeInTheDocument();
  });
});
