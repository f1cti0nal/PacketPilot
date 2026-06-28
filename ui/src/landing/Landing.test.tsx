import { describe, expect, it, vi } from "vitest";
import { render } from "@testing-library/react";

const track = vi.fn();
vi.mock("../lib/analytics/track", () => ({ trackPageView: (p: string) => track(p) }));
vi.mock("./landing.html?raw", () => ({ default: "<div>landing</div>" }));

import { Landing } from "./Landing";

describe("Landing", () => {
  it("tracks the landing page view on mount", () => {
    render(<Landing />);
    expect(track).toHaveBeenCalledWith("/");
  });
});
