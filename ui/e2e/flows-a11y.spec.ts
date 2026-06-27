import { test, expect, type Page } from "@playwright/test";

const PCAP = "e2e/fixtures/cap.pcap";

async function uploadAndOpenFlows(page: Page) {
  await page.goto("/app");
  await expect(page.getByText("Packets").first()).toBeVisible({ timeout: 15_000 });
  const dialog = page.getByRole("dialog", { name: "Load capture" });
  await page.getByRole("button", { name: "Load capture" }).click();
  await dialog.locator('input[type="file"]').setInputFiles(PCAP);
  await expect(dialog).toBeHidden({ timeout: 30_000 });
  await page.getByRole("button", { name: "Flows", exact: true }).click();
  await expect(page.getByLabel("Filter flows")).toBeVisible();
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
