import { test, expect, type Page } from "@playwright/test";

const PCAP = "e2e/fixtures/cap.pcap";

async function uploadAndOpenFlows(page: Page) {
  await page.goto("/app");
  // Launch lands on the Home overview; uploading a capture works from there (the shell's "Load
  // capture" affordance is always present), so just wait for the shell to be ready.
  await expect(page.getByRole("button", { name: "Load capture", exact: true })).toBeVisible({ timeout: 15_000 });
  const dialog = page.getByRole("dialog", { name: "Load capture" });
  await page.getByRole("button", { name: "Load capture", exact: true }).click();
  await dialog.locator('input[type="file"]').setInputFiles(PCAP);
  await expect(dialog).toBeHidden({ timeout: 30_000 });
  await dismissReputationConsents(page);
  await page.getByRole("button", { name: "Flows", exact: true }).click();
  await expect(page.getByLabel("Filter flows")).toBeVisible();
}

/** Enrichment is opt-in for everyone: analyzing a capture with public IPs / SNI hostnames pops
 *  one-time reputation consent dialogs ("Reputation consent", "VirusTotal reputation consent" —
 *  full-screen overlays, possibly stacked). Decline each so later clicks aren't intercepted.
 *  Tolerant of captures/configs that don't trigger any. */
async function dismissReputationConsents(page: Page) {
  const consent = page.getByRole("dialog", { name: /reputation consent/i });
  for (let i = 0; i < 3; i++) {
    // Dismiss the TOP-MOST dialog first: when both the IP and VirusTotal consents stack they are
    // sibling full-screen overlays, so the DOM-later one (.last()) paints on top and the earlier
    // one (.first()) is covered — clicking the covered one fails the actionability hit-test.
    const dismissed = await consent
      .last()
      .getByRole("button", { name: "Cancel" })
      .click({ timeout: 3_000 })
      .then(() => true)
      .catch(() => false);
    if (!dismissed) break;
  }
  await expect(consent).toHaveCount(0);
}

test.describe("Flows — keyboard operability (WCAG 2.1.1)", () => {
  test("a flow row opens its detail via keyboard (focus + Enter)", async ({ page }) => {
    await uploadAndOpenFlows(page);
    const firstRow = page.locator('[role="row"][aria-rowindex="1"]');
    await expect(firstRow).toBeVisible();
    await firstRow.press("Enter");
    // Activation selects the row → the detail panel opens.
    await expect(page.locator('[role="row"][aria-selected="true"]')).toHaveCount(1);
  });

  test("a sortable column header toggles sort via keyboard (focus + Enter)", async ({ page }) => {
    await uploadAndOpenFlows(page);
    const header = page.locator('[role="columnheader"][tabindex="0"]').first();
    await expect(header).toBeVisible();
    const before = await header.getAttribute("aria-sort");
    await header.press("Enter");
    await expect(header).not.toHaveAttribute("aria-sort", before ?? "none");
  });
});

test.describe("Flows — mobile detail overlay", () => {
  test.use({ viewport: { width: 390, height: 800 } });

  test("opening a flow detail does not overflow the viewport on a phone", async ({ page }) => {
    await uploadAndOpenFlows(page);
    await page.locator('[role="row"][aria-rowindex="1"]').click();
    await expect(page.locator('[role="row"][aria-selected="true"]')).toHaveCount(1);
    // The detail is a full-screen overlay on mobile — no horizontal scrollbar.
    const overflow = await page.evaluate(
      () => document.documentElement.scrollWidth > document.documentElement.clientWidth + 1,
    );
    expect(overflow, "horizontal overflow with detail open @390px").toBe(false);
  });
});
