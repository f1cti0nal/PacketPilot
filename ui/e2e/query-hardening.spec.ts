import { expect, test, type Page } from "@playwright/test";

/**
 * Phase 4 failure drills for the Query console: a wasm-asset failure must land
 * in a visible, recoverable state (Retry reboots the engine), and a capture
 * switch must drop stale results and rebuild the flow table.
 */

const PCAP = "e2e/fixtures/cap.pcap";

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
}

const engineReady = (page: Page) =>
  expect(page.getByText(/flows loaded · local only/)).toBeVisible({ timeout: 60_000 });

async function runAndExpectRows(page: Page) {
  await page.getByRole("button", { name: /^Run$/ }).click();
  await expect(page.getByText(/^\d[\d,.]* rows?$/).first()).toBeVisible({ timeout: 30_000 });
}

/** Decline any stacked reputation-consent dialogs an uploaded capture may pop. */
async function dismissReputationConsents(page: Page) {
  const consent = page.getByRole("dialog", { name: /reputation consent/i });
  for (let i = 0; i < 3; i++) {
    const dismissed = await consent
      .last()
      .getByRole("button", { name: /cancel|not now|decline/i })
      .click({ timeout: 2000 })
      .then(() => true)
      .catch(() => false);
    if (!dismissed) break;
  }
}

test.describe("Query console — failure drills", () => {
  test("wasm asset failure shows a recoverable error; Retry boots the engine", async ({
    page,
  }) => {
    test.setTimeout(240_000);
    // Block the duckdb wasm before the first Query-tab visit. The dead fetch
    // wedges instantiation inside the worker, so the view's boot watchdog
    // (60s) must fail it into the visible error state instead of hanging.
    await page.route("**/*.wasm", (route) => route.abort());
    await openSampleCapture(page);
    await openQueryTab(page);
    await expect(page.getByText("Query engine unavailable")).toBeVisible({ timeout: 90_000 });
    await expect(page.getByRole("button", { name: "Retry" })).toBeVisible();
    // Run must be inert while the engine is down.
    await expect(page.getByRole("button", { name: /^Run$/ })).toBeDisabled();

    // Network restored → Retry reboots the worker and the console works.
    await page.unroute("**/*.wasm");
    await page.getByRole("button", { name: "Retry" }).click();
    await engineReady(page);
    await runAndExpectRows(page);
  });

  test("capture switch drops stale results and rebuilds the flow table", async ({ page }) => {
    test.setTimeout(240_000);
    await openSampleCapture(page);
    await openQueryTab(page);
    await engineReady(page);
    await runAndExpectRows(page);

    // Switch captures: upload the fixture pcap (analyzed in-browser by the wasm engine).
    await page.getByRole("button", { name: "Load capture", exact: true }).click();
    const dialog = page.getByRole("dialog", { name: "Load capture" });
    await dialog.locator('input[type="file"]').setInputFiles(PCAP);
    await expect(dialog).toBeHidden({ timeout: 30_000 });
    await dismissReputationConsents(page);

    await openQueryTab(page);
    // Stale results from the previous capture are gone…
    await expect(page.getByText("Run a query")).toBeVisible({ timeout: 15_000 });
    // …and the rebuilt table is queryable.
    await engineReady(page);
    await runAndExpectRows(page);
  });
});
