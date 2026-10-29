import { test, expect, type Page } from "@playwright/test";

/** The KPI cluster's "Packets" label only renders once the sample capture has loaded. */
async function waitForDashboard(page: Page) {
  const packets = page.getByText("Packets").first();
  const sample = page.getByRole("button", { name: /explore sample capture/i });
  await expect(packets.or(sample)).toBeVisible({ timeout: 15_000 });
  if (await sample.isVisible()) {
    await sample.click();
    await expect(packets).toBeVisible({ timeout: 15_000 });
  }
}

test.describe("Smart Alerting — the ranked triage queue", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/app");
    await waitForDashboard(page);
  });

  test("the Alerts tab renders the bundled sample's ranked queue", async ({ page }) => {
    await page.getByRole("button", { name: /^alerts/i }).first().click();
    const view = page.locator('[data-component="AlertsView"]');
    await expect(view).toBeVisible();
    // The bundled sample derives a non-empty queue (6 alerts from 12 findings).
    await expect(view.getByText(/from 12 findings/i)).toBeVisible();
    // The worst story leads with its band chip and a recommended action.
    await expect(view.getByText(/act now/i).first()).toBeVisible();
  });

  test("expanding an alert reveals the priority ledger and member findings", async ({
    page,
  }) => {
    await page.getByRole("button", { name: /^alerts/i }).first().click();
    const view = page.locator('[data-component="AlertsView"]');
    await expect(view).toBeVisible();
    const card = view.getByRole("button", { name: /act now/i }).first();
    await card.click();
    // The transparent ledger always opens with the base term.
    await expect(view.getByText(/base: /).first()).toBeVisible();
  });
});
