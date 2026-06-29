import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { render, screen } from "@testing-library/react";
import { ToolApp } from "./ToolApp";
import { SEO_PAGES } from "./registry";

const origUrl = window.location;
const setPath = (pathname: string) =>
  Object.defineProperty(window, "location", { writable: true, value: { ...origUrl, pathname } });

beforeEach(() => {
  setPath("/");
});
afterEach(() => {
  Object.defineProperty(window, "location", { writable: true, value: origUrl });
});

describe("ToolApp", () => {
  it("renders the page for a known slug and sets the document title", () => {
    const page = SEO_PAGES[0];
    setPath(`/${page.slug}`);
    render(<ToolApp />);
    expect(screen.getByRole("heading", { level: 1, name: page.h1 })).toBeInTheDocument();
    expect(document.title).toBe(page.metaTitle);
  });

  it("shows a not-found state for an unknown slug", () => {
    setPath("/totally-unknown");
    render(<ToolApp />);
    expect(screen.getByText(/doesn't exist/i)).toBeInTheDocument();
  });
});
