import { describe, expect, it, vi } from "vitest";
import { fireEvent, render } from "@testing-library/react";

const track = vi.fn();
vi.mock("../lib/analytics/track", () => ({ trackPageView: (p: string) => track(p) }));

// A miniature landing fragment carrying every data-hook the wiring effect
// targets, so each guarded block executes under jsdom (no IntersectionObserver,
// no matchMedia — the fallback paths run).
vi.mock("./landing.html?raw", () => ({
  default: `
  <div class="pp-landing pp-no-js">
    <button data-pp-nav-toggle aria-expanded="false"></button>
    <div data-pp-nav-menu><a href="#features">Features</a></div>
    <div class="pp-mockup-wrap"><div data-pp-tilt></div></div>
    <div class="pp-stats"><span data-pp-count="20">20+</span></div>
    <div data-pp-reveal>reveal me</div>
    <button data-pp-period="monthly" aria-pressed="true">Monthly</button>
    <button data-pp-period="annual" aria-pressed="false">Annual</button>
    <div class="pp-price-amt" data-pp-price="monthly">$19</div>
    <div class="pp-price-amt pp-price-annual" data-pp-price="annual">$190</div>
    <div class="pp-price-note" data-pp-price="monthly">Billed monthly</div>
    <div data-pp-carousel>
      <div data-pp-slide class="is-active">one</div>
      <div data-pp-slide>two</div>
      <button data-pp-prev></button>
      <button data-pp-next></button>
      <button data-pp-dot data-index="0" class="is-active"></button>
      <button data-pp-dot data-index="1"></button>
    </div>
    <div data-pp-tabs>
      <button data-pp-tab="drop" class="is-active" aria-selected="true">Drop</button>
      <button data-pp-tab="triage" aria-selected="false">Triage</button>
      <div data-pp-panel="drop">panel drop</div>
      <div data-pp-panel="triage" hidden>panel triage</div>
    </div>
  </div>`,
}));

import { Landing } from "./Landing";

describe("Landing", () => {
  it("tracks the landing page view on mount", () => {
    render(<Landing />);
    expect(track).toHaveBeenCalledWith("/");
  });

  it("marks the fragment as JS-active", () => {
    const { container } = render(<Landing />);
    const root = container.querySelector(".pp-landing");
    expect(root?.classList.contains("pp-js")).toBe(true);
    expect(root?.classList.contains("pp-no-js")).toBe(false);
  });

  it("reveals [data-pp-reveal] immediately without IntersectionObserver", () => {
    vi.stubGlobal("IntersectionObserver", undefined);
    try {
      const { container } = render(<Landing />);
      const el = container.querySelector("[data-pp-reveal]");
      expect(el?.classList.contains("pp-in")).toBe(true);
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("switches workflow panels on tab click", () => {
    const { container } = render(<Landing />);
    const triageTab = container.querySelector<HTMLElement>('[data-pp-tab="triage"]')!;
    fireEvent.click(triageTab);
    expect(triageTab.getAttribute("aria-selected")).toBe("true");
    expect(
      container.querySelector<HTMLElement>('[data-pp-panel="triage"]')!.hidden,
    ).toBe(false);
    expect(
      container.querySelector<HTMLElement>('[data-pp-panel="drop"]')!.hidden,
    ).toBe(true);
  });

  it("moves tab selection with arrow keys", () => {
    const { container } = render(<Landing />);
    const dropTab = container.querySelector<HTMLElement>('[data-pp-tab="drop"]')!;
    fireEvent.keyDown(dropTab, { key: "ArrowRight" });
    expect(
      container
        .querySelector<HTMLElement>('[data-pp-tab="triage"]')!
        .getAttribute("aria-selected"),
    ).toBe("true");
  });

  it("switches pricing rows on billing-period toggle", () => {
    const { container } = render(<Landing />);
    const annualBtn = container.querySelector<HTMLElement>('[data-pp-period="annual"]')!;
    fireEvent.click(annualBtn);
    expect(annualBtn.getAttribute("aria-pressed")).toBe("true");
    const annualPrice = container.querySelector<HTMLElement>(
      '.pp-price-amt[data-pp-price="annual"]',
    )!;
    const monthlyPrice = container.querySelector<HTMLElement>(
      '.pp-price-amt[data-pp-price="monthly"]',
    )!;
    expect(annualPrice.style.display).toBe("flex");
    expect(monthlyPrice.style.display).toBe("none");
  });

  it("advances the carousel with next and dot controls", () => {
    const { container } = render(<Landing />);
    const slides = Array.from(container.querySelectorAll<HTMLElement>("[data-pp-slide]"));
    fireEvent.click(container.querySelector<HTMLElement>("[data-pp-next]")!);
    expect(slides[1].classList.contains("is-active")).toBe(true);
    fireEvent.click(container.querySelector<HTMLElement>('[data-pp-dot][data-index="0"]')!);
    expect(slides[0].classList.contains("is-active")).toBe(true);
  });

  it("toggles the mobile nav menu", () => {
    const { container } = render(<Landing />);
    const toggle = container.querySelector<HTMLElement>("[data-pp-nav-toggle]")!;
    const menu = container.querySelector<HTMLElement>("[data-pp-nav-menu]")!;
    fireEvent.click(toggle);
    expect(toggle.getAttribute("aria-expanded")).toBe("true");
    expect(menu.classList.contains("is-open")).toBe(true);
    fireEvent.click(menu.querySelector("a")!);
    expect(toggle.getAttribute("aria-expanded")).toBe("false");
  });
});
