import { describe, it, expect, afterEach, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import { LegalApp } from "./LegalApp";
import { LEGAL_PAGES } from "./content";

const origUrl = window.location;
const setPath = (pathname: string) =>
  Object.defineProperty(window, "location", { writable: true, value: { ...origUrl, pathname } });

beforeEach(() => {
  setPath("/");
});
afterEach(() => {
  Object.defineProperty(window, "location", { writable: true, value: origUrl });
});

describe("LegalApp", () => {
  it.each(["/security", "/privacy", "/terms"] as const)("renders the %s page by pathname", (p) => {
    setPath(p);
    render(<LegalApp />);
    expect(screen.getByRole("heading", { level: 1, name: LEGAL_PAGES[p].title })).toBeInTheDocument();
  });

  it("shows a not-found state for an unknown legal path", () => {
    setPath("/nope");
    render(<LegalApp />);
    expect(screen.getByText(/doesn't exist/i)).toBeInTheDocument();
  });

  it("always offers a way back home and cross-links the legal pages", () => {
    setPath("/security");
    render(<LegalApp />);
    expect(screen.getByRole("link", { name: /back to home/i })).toHaveAttribute("href", "/");
    expect(screen.getByRole("link", { name: "Privacy" })).toHaveAttribute("href", "/privacy");
    expect(screen.getByRole("link", { name: "Terms" })).toHaveAttribute("href", "/terms");
  });
});
