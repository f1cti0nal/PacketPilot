import { test, expect, type Page } from "@playwright/test";

// Core analysis flows — these exercise the WebAssembly engine (analyzeViaWasm, exportCsvWasm,
// packet extraction). They require src/wasm to be built and served in-tree: run
// `npm run build:wasm` before `npm run e2e` (same prerequisite as `npm run dev`). The bundled
// e2e/fixtures/cap.pcap is analyzed entirely in the browser.
const PCAP = "e2e/fixtures/cap.pcap";

async function waitForDashboard(page: Page) {
  // Launch lands on the Home overview; the dashboard loads via the opt-in bundled sample. After
  // navigation the app shows either the dashboard (capture active) or the Home hero (fresh launch).
  const packets = page.getByText("Packets").first();
  const sample = page.getByRole("button", { name: /explore sample capture/i });
  await expect(packets.or(sample)).toBeVisible({ timeout: 15_000 });
  if (await sample.isVisible()) {
    await sample.click();
    await expect(packets).toBeVisible({ timeout: 15_000 });
  }
}

/** Open the load dialog and analyze the bundled pcap in-browser via the WASM engine. */
async function uploadPcap(page: Page) {
  const dialog = page.getByRole("dialog", { name: "Load capture" });
  await page.getByRole("button", { name: "Load capture" }).click();
  await expect(dialog).toBeVisible();
  // Scope to the dialog's input — a hidden rules-import file input also exists in the DOM.
  await dialog.locator('input[type="file"]').setInputFiles(PCAP);
  // A successful analysis closes the dialog (a failure keeps it open with an error).
  await expect(page.getByRole("dialog", { name: "Load capture" })).toBeHidden({ timeout: 30_000 });
  // A capture with TLS SNI hostnames pops a one-time domain-reputation consent dialog
  // (full-screen overlay); decline it so later clicks aren't intercepted. Tolerant of
  // captures that don't trigger it.
  const consent = page.getByRole("dialog", { name: "Domain reputation consent" });
  await consent
    .getByRole("button", { name: "Cancel" })
    .click({ timeout: 5_000 })
    .catch(() => {});
  await expect(consent).toBeHidden();
}

test.describe("PacketPilot — core analysis flows", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/app");
    await waitForDashboard(page);
  });

  test("uploads a pcap, analyzes it in-browser (WASM), and swaps the active capture", async ({ page }) => {
    const errors: string[] = [];
    page.on("pageerror", (e) => errors.push(`${e.name}: ${e.message}`));

    await uploadPcap(page);

    await expect(page.getByText("cap.pcap")).toBeVisible();
    await expect(page.getByText("Packets").first()).toBeVisible(); // dashboard re-rendered
    expect(errors, errors.join("\n")).toEqual([]);
  });

  test("Flows: table renders, filters, and a row opens the flow detail", async ({ page }) => {
    await page.getByRole("button", { name: "Flows", exact: true }).click();
    const filter = page.getByLabel("Filter flows");
    await expect(filter).toBeVisible();

    const rows = page.getByRole("row");
    await expect(rows.nth(1)).toBeVisible(); // row 0 is the header
    const before = await rows.count();

    await filter.fill("zzz-no-such-flow");
    await expect(async () => expect(await rows.count()).toBeLessThan(before)).toPass();

    await filter.fill("");
    await rows.nth(1).click();
    await expect(page.getByRole("dialog", { name: /Flow .* detail/ })).toBeVisible();
  });

  test("Export downloads a CSV file", async ({ page }) => {
    await page.getByRole("button", { name: /export/i }).click();
    const [download] = await Promise.all([
      page.waitForEvent("download"),
      page.getByRole("menuitem", { name: /CSV.*download/i }).click(),
    ]);
    expect(download.suggestedFilename()).toMatch(/\.csv$/i);
  });

  test("after upload, a flow can be drilled into the packet inspector", async ({ page }) => {
    await uploadPcap(page);
    await page.getByRole("button", { name: "Flows", exact: true }).click();
    await page.getByRole("row").nth(1).click();
    await expect(page.getByRole("dialog", { name: /Flow .* detail/ })).toBeVisible();

    await page.getByRole("button", { name: /inspect packets/i }).click();
    await expect(page.getByRole("dialog", { name: /Packets for/i })).toBeVisible({ timeout: 15_000 });
  });
});
