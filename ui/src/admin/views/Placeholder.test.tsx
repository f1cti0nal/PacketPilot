import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { Placeholder } from "./Placeholder";
import { ADMIN_SECTIONS } from "../sections";

describe("admin sections + Placeholder", () => {
  it("defines the seven admin sections with unique ids", () => {
    const ids = ADMIN_SECTIONS.map((s) => s.id);
    expect(ids).toEqual(["dashboard", "users", "payments", "traffic", "features", "settings", "env"]);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("renders a coming-soon placeholder naming the section and phase", () => {
    render(<Placeholder title="Users" phase={5} />);
    expect(screen.getByText("Users")).toBeInTheDocument();
    expect(screen.getByText(/phase 5/i)).toBeInTheDocument();
  });
});
