import { test, expect, type Page } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";

// Real-browser accessibility audit (axe-core in Chromium). Unlike the jsdom axe net
// (src/test/a11y.test.tsx), Chromium has a real layout + colour engine, so this also gates
// WCAG color-contrast (1.4.3) — including both themes and the theme-toggle case.
const WCAG = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"];

async function waitForDashboard(page: Page) {
  await expect(page.getByText("Packets").first()).toBeVisible({ timeout: 15_000 });
}

/** Let entrance animations (node-pop) settle to full opacity before scanning colours. */
async function settle(page: Page) {
  await page.waitForTimeout(1200);
}

/** Load the app already in `theme` (pre-paint), so sevColor() reads the right palette. */
async function freshLoad(page: Page, theme: "dark" | "light") {
  await page.addInitScript((t) => localStorage.setItem("packetpilot.theme.v1", t as string), theme);
  await page.goto("/app");
  await waitForDashboard(page);
  await settle(page);
}

async function audit(page: Page) {
  const r = await new AxeBuilder({ page }).withTags(WCAG).analyze();
  return r.violations;
}

function fmt(vs: Awaited<ReturnType<typeof audit>>) {
  return JSON.stringify(
    vs.map((v) => ({ id: v.id, impact: v.impact, nodes: v.nodes.length, sample: v.nodes[0]?.target })),
    null,
    2,
  );
}

test.describe("accessibility (axe, real browser) — WCAG A/AA incl. contrast", () => {
  test("dashboard — fresh dark load", async ({ page }) => {
    await freshLoad(page, "dark");
    const vs = await audit(page);
    expect(vs, fmt(vs)).toEqual([]);
  });

  test("dashboard — fresh light load", async ({ page }) => {
    await freshLoad(page, "light");
    const vs = await audit(page);
    expect(vs, fmt(vs)).toEqual([]);
  });

  test("dashboard — toggled light→dark stays AA (sevColor reactivity)", async ({ page }) => {
    await freshLoad(page, "light");
    await page.locator('[data-component="ThemeToggle"]').click();
    await settle(page);
    const vs = await audit(page);
    expect(vs, fmt(vs)).toEqual([]);
  });

  test("Flows view — dark", async ({ page }) => {
    await freshLoad(page, "dark");
    await page.getByRole("button", { name: "Flows", exact: true }).click();
    await expect(page.getByLabel("Filter flows")).toBeVisible();
    await settle(page);
    const vs = await audit(page);
    expect(vs, fmt(vs)).toEqual([]);
  });

  test("Flows view — light", async ({ page }) => {
    await freshLoad(page, "light");
    await page.getByRole("button", { name: "Flows", exact: true }).click();
    await expect(page.getByLabel("Filter flows")).toBeVisible();
    await settle(page);
    const vs = await audit(page);
    expect(vs, fmt(vs)).toEqual([]);
  });

  test("settings dialog", async ({ page }) => {
    await freshLoad(page, "dark");
    await page.getByRole("button", { name: "Settings" }).click();
    await expect(page.getByRole("dialog", { name: "Settings" })).toBeVisible();
    const vs = await audit(page);
    expect(vs, fmt(vs)).toEqual([]);
  });

  test("keyboard shortcuts overlay", async ({ page }) => {
    await freshLoad(page, "dark");
    await page.keyboard.press("Shift+Slash");
    await expect(page.getByRole("dialog", { name: "Keyboard shortcuts" })).toBeVisible();
    const vs = await audit(page);
    expect(vs, fmt(vs)).toEqual([]);
  });

  // The marketing landing page at "/" is a production surface — hold it to the same
  // WCAG AA contrast bar as the app. It is self-contained dark (ignores the theme toggle).
  test("landing page (/) — AA contrast", async ({ page }) => {
    await page.goto("/");
    await expect(page.locator(".pp-landing")).toBeVisible({ timeout: 15_000 });
    await settle(page);
    const vs = await audit(page);
    expect(vs, fmt(vs)).toEqual([]);
  });
});

test.describe("accessibility (axe) — mobile", () => {
  test.use({ viewport: { width: 390, height: 800 } });

  test("dashboard — mobile (dark + light)", async ({ page }) => {
    await freshLoad(page, "dark");
    expect(await audit(page), "mobile dark").toEqual([]);
    await page.locator('[data-component="ThemeToggle"]').click();
    await settle(page);
    expect(await audit(page), "mobile light").toEqual([]);
  });
});
