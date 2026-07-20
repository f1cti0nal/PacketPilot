import { expect, test, type Page } from "@playwright/test";

/**
 * Phase 2 e2e for the Query console (NLQ plan): sample capture → Query tab →
 * run bundled SQL against real DuckDB-Wasm → results grid; guard rejection;
 * "Open in Flows" cross-filter round-trip.
 */

async function openSampleCapture(page: Page) {
  await page.goto("/app");
  const packets = page.getByText("Packets").first();
  const sample = page.getByRole("button", { name: /explore sample capture/i });
  await expect(packets.or(sample)).toBeVisible({ timeout: 15_000 });
  if (await sample.isVisible()) {
    await sample.click();
    await expect(packets).toBeVisible({ timeout: 15_000 });
  }
}

async function openQueryTab(page: Page) {
  await page.getByRole("button", { name: "Query", exact: true }).click();
  await expect(page.locator('[data-component="QueryView"]')).toBeVisible();
  // The wasm engine boots lazily on first entry; wait for the ready status.
  await expect(page.getByText(/flows loaded · local only/)).toBeVisible({ timeout: 60_000 });
}

const editor = (page: Page) => page.getByLabel("SQL query");
const runButton = (page: Page) => page.getByRole("button", { name: /^Run$/ });

test.describe("Query console", () => {
  test("runs the bundled top-talkers query against the sample capture", async ({ page }) => {
    await openSampleCapture(page);
    await openQueryTab(page);

    // The editor is pre-seeded with the first bundled query (top talkers).
    await expect(editor(page)).toHaveValue(/Top talkers/i);
    await runButton(page).click();

    // Results header shows a row count; the grid renders data rows.
    await expect(page.getByText(/^\d[\d,.]* rows?$/).first()).toBeVisible({ timeout: 30_000 });
    const grid = page.locator('[data-component="ResultsGrid"]');
    await expect(grid).toBeVisible();
    await expect(grid.locator('[role="columnheader"]').first()).toHaveText("ip");
    expect(await grid.locator('[role="row"]').count()).toBeGreaterThan(1);
  });

  test("rejects non-SELECT statements with the guard error", async ({ page }) => {
    await openSampleCapture(page);
    await openQueryTab(page);

    await editor(page).fill("DROP TABLE flow");
    await runButton(page).click();
    await expect(page.getByRole("alert")).toContainText(/read-only|SELECT/);
  });

  test("Ctrl+Enter runs; Open in Flows cross-filters the flows table", async ({ page }) => {
    await openSampleCapture(page);
    await openQueryTab(page);

    await editor(page).fill("SELECT flow_id, src_ip, dst_ip FROM flow LIMIT 25");
    await editor(page).press("Control+Enter");
    await expect(page.getByText(/^25 rows$/)).toBeVisible({ timeout: 30_000 });

    await page.getByRole("button", { name: /open in flows/i }).click();

    // Lands on the Flows tab with the dismissible cross-filter chip applied.
    const chip = page.locator('[data-component="FlowIdFilterChip"]');
    await expect(chip).toBeVisible();
    await expect(chip).toContainText("25 flows");
    // The table itself is filtered to exactly those flows ("25 / N flows").
    await expect(page.getByText(/^25\s*\/\s*[\d,.]+\s*flows$/).first()).toBeVisible();

    // Dismissing the chip restores the unfiltered table.
    await chip.getByRole("button", { name: /clear query result filter/i }).click();
    await expect(chip).toHaveCount(0);
  });
});
