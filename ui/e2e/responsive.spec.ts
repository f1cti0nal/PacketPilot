import { test, expect, type Page } from "@playwright/test";

// The tablet range (768–1024px) inherits the desktop layout. Guard against the
// command bar / heatmap regression where content overflowed the viewport and grew
// a horizontal scrollbar at the 768px md boundary.
const TABLET = [768, 834, 1024];

async function waitForDashboard(page: Page) {
  await expect(page.getByText("Packets").first()).toBeVisible({ timeout: 15_000 });
}

async function hasHorizontalScrollbar(page: Page) {
  return page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth + 1);
}

test.describe("responsive — tablet range has no horizontal scrollbar", () => {
  for (const w of TABLET) {
    test(`dashboard + Flows fit within ${w}px`, async ({ page }) => {
      await page.setViewportSize({ width: w, height: 1100 });
      await page.goto("/app");
      await waitForDashboard(page);
      expect(await hasHorizontalScrollbar(page), `dashboard @ ${w}px`).toBe(false);

      await page.getByRole("button", { name: "Flows", exact: true }).click();
      await expect(page.getByLabel("Filter flows")).toBeVisible();
      expect(await hasHorizontalScrollbar(page), `flows @ ${w}px`).toBe(false);
    });
  }

  test("768px uses the desktop layout (Views switcher), not the mobile bottom bar", async ({ page }) => {
    await page.setViewportSize({ width: 768, height: 1100 });
    await page.goto("/app");
    await waitForDashboard(page);
    // The inline Views switcher is desktop-only (mobile replaces it with the bottom tab bar).
    await expect(page.getByRole("navigation", { name: "Views" })).toBeVisible();
  });
});
