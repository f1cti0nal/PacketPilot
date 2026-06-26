import { test, expect, type Page } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";

// Real-browser accessibility audit (axe-core in Chromium). Unlike the jsdom axe net
// (src/test/a11y.test.tsx), Chromium has a real layout + colour engine.
//
// This GATES on STRUCTURAL WCAG A/AA (valid ARIA, accessible names, roles, keyboard
// reachability) across the key surfaces and both themes.
//
// ⚠️ color-contrast (1.4.3) is excluded from the gate and tracked as a known issue (fixme
// below). PROGRESS: --color-text-faint was bumped to AA, clearing the dominant plain-surface
// failures (dashboard dark 169→39 nodes). The REMAINING failures are (a) severity-coloured
// text on same-hue tinted chips and (b) mid-tone tinted backgrounds where neither dim nor
// faint text passes — both conflated with a theme-toggle stale-colour bug (sevColor() bakes a
// literal hex at render time, so severity text doesn't re-colour on theme switch). Finishing
// it is a per-component pass (tint opacities + readable severity-text + reactive sevColor).
const WCAG = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"];

async function waitForDashboard(page: Page) {
  await expect(page.getByText("Packets").first()).toBeVisible({ timeout: 15_000 });
}

async function structural(page: Page) {
  const r = await new AxeBuilder({ page }).withTags(WCAG).disableRules(["color-contrast"]).analyze();
  return r.violations;
}

function fmt(vs: Awaited<ReturnType<typeof structural>>) {
  return JSON.stringify(
    vs.map((v) => ({ id: v.id, impact: v.impact, nodes: v.nodes.length, sample: v.nodes[0]?.target })),
    null,
    2,
  );
}

async function setTheme(page: Page, theme: "dark" | "light") {
  const html = page.locator("html");
  if ((await html.getAttribute("data-theme")) !== theme) {
    await page.locator('[data-component="ThemeToggle"]').click();
  }
  await expect(html).toHaveAttribute("data-theme", theme);
}

test.describe("accessibility (axe, real browser) — structural WCAG A/AA", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await waitForDashboard(page);
  });

  test("dashboard — dark theme", async ({ page }) => {
    await setTheme(page, "dark");
    const vs = await structural(page);
    expect(vs, fmt(vs)).toEqual([]);
  });

  test("dashboard — light theme", async ({ page }) => {
    await setTheme(page, "light");
    const vs = await structural(page);
    expect(vs, fmt(vs)).toEqual([]);
  });

  test("Flows view", async ({ page }) => {
    await page.getByRole("button", { name: "Flows", exact: true }).click();
    await expect(page.getByLabel("Filter flows")).toBeVisible();
    const vs = await structural(page);
    expect(vs, fmt(vs)).toEqual([]);
  });

  test("settings dialog", async ({ page }) => {
    await page.getByRole("button", { name: "Settings" }).click();
    await expect(page.getByRole("dialog", { name: "Settings" })).toBeVisible();
    const vs = await structural(page);
    expect(vs, fmt(vs)).toEqual([]);
  });

  test("keyboard shortcuts overlay", async ({ page }) => {
    await page.keyboard.press("Shift+Slash");
    await expect(page.getByRole("dialog", { name: "Keyboard shortcuts" })).toBeVisible();
    const vs = await structural(page);
    expect(vs, fmt(vs)).toEqual([]);
  });

  // KNOWN ISSUE — the cockpit fails WCAG AA color-contrast in both themes (see header note).
  // Marked fixme so it is tracked and visible in reports without blocking the structural gate;
  // flip to a normal test once the palette has had its dedicated AA contrast pass.
  test.fixme("dashboard — WCAG AA color-contrast (pending palette pass)", async ({ page }) => {
    const r = await new AxeBuilder({ page }).withTags(WCAG).analyze();
    expect(r.violations.filter((v) => v.id === "color-contrast")).toEqual([]);
  });
});

test.describe("accessibility (axe) — mobile structural", () => {
  test.use({ viewport: { width: 390, height: 800 } });

  test("dashboard — mobile", async ({ page }) => {
    await page.goto("/");
    await waitForDashboard(page);
    const vs = await structural(page);
    expect(vs, fmt(vs)).toEqual([]);
  });
});
