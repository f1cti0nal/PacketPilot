import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { Markdown } from "./markdown";

describe("Markdown", () => {
  it("renders bold/italic/code without leaving the raw markers", () => {
    const { container } = render(<Markdown text="A **bold** and *italic* and `code` word." />);
    expect(container.querySelector("strong")?.textContent).toBe("bold");
    expect(container.querySelector("em")?.textContent).toBe("italic");
    expect(container.querySelector("code")?.textContent).toBe("code");
    // The raw symbols must not appear in the visible text.
    expect(container.textContent).not.toMatch(/\*\*|`/);
  });

  it("renders headings as emphasized text (not a literal '#')", () => {
    const { container } = render(<Markdown text={"## Summary\n\nbody"} />);
    expect(screen.getByText("Summary")).toBeInTheDocument();
    expect(container.textContent).not.toContain("#");
  });

  it("renders unordered and ordered lists", () => {
    const { container } = render(<Markdown text={"- one\n- two\n\n1. first\n2. second"} />);
    expect(container.querySelectorAll("ul > li")).toHaveLength(2);
    expect(container.querySelectorAll("ol > li")).toHaveLength(2);
    expect(screen.getByText("one")).toBeInTheDocument();
    expect(screen.getByText("first")).toBeInTheDocument();
    // No leading "- " / "1." markers leak into the text.
    expect(container.textContent).not.toMatch(/^- |\d\.\s/);
  });

  it("groups blank-line-separated paragraphs", () => {
    const { container } = render(<Markdown text={"para one\n\npara two"} />);
    expect(container.querySelectorAll("p")).toHaveLength(2);
  });

  it("degrades gracefully on partial mid-stream markdown (unclosed bold)", () => {
    // An unclosed ** must render as literal text, not crash or hide content.
    render(<Markdown text="risk is **elevated" />);
    expect(screen.getByText(/risk is \*\*elevated/)).toBeInTheDocument();
  });

  it("does not render HTML from the model (XSS-safe)", () => {
    const { container } = render(<Markdown text={"<img src=x onerror=alert(1)> hi"} />);
    expect(container.querySelector("img")).toBeNull(); // rendered as text, not an element
    expect(container.textContent).toContain("<img src=x onerror=alert(1)>");
  });
});
