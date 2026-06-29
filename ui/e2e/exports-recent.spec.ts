import { test, expect, type Page } from "@playwright/test";

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

async function uploadPcap(page: Page) {
  const dialog = page.getByRole("dialog", { name: "Load capture" });
  await page.getByRole("button", { name: "Load capture" }).click();
  await expect(dialog).toBeVisible();
  await dialog.locator('input[type="file"]').setInputFiles(PCAP);
  await expect(dialog).toBeHidden({ timeout: 30_000 });
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

// Every "download" export format goes through the WASM exporters + downloadText/downloadBinary.
const DOWNLOADS = [
  { item: /^HTML report$/, ext: /\.html$/i },
  { item: /CSV.*download/i, ext: /\.csv$/i },
  { item: /STIX.*download/i, ext: /\.json$/i },
  { item: /MISP.*download/i, ext: /\.json$/i },
  { item: /CEF.*download/i, ext: /\.(txt|cef)$/i },
  { item: /Sigma.*download/i, ext: /\.(ya?ml)$/i },
];

test.describe("PacketPilot — exports & recent", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/app");
    await waitForDashboard(page);
  });

  test("every export format triggers a download with the right extension", async ({ page }) => {
    for (const fmt of DOWNLOADS) {
      await page.getByRole("button", { name: /export/i }).click();
      const [download] = await Promise.all([
        page.waitForEvent("download"),
        page.getByRole("menuitem", { name: fmt.item }).click(),
      ]);
      expect(download.suggestedFilename(), `${fmt.item} → ${download.suggestedFilename()}`).toMatch(fmt.ext);
    }
  });

  test("an uploaded capture is recorded in Recent and can be reopened", async ({ page }) => {
    await uploadPcap(page);
    await expect(page.getByText("cap.pcap")).toBeVisible();

    await page.getByRole("button", { name: /Recent/ }).click();
    const recent = page.locator('[data-component="RecentView"]');
    await expect(recent.getByRole("button", { name: /Remove cap\.pcap/i })).toBeVisible();

    // Reopen it from Recent → back to the dashboard for that capture.
    await recent.getByText("cap.pcap").first().click();
    await waitForDashboard(page);
  });

  test("loading a Suricata .rules file applies it to an uploaded capture", async ({ page }) => {
    await uploadPcap(page); // retains the pcap bytes so rules can re-scan the packets
    await page.locator('input[accept=".rules,.txt"]').setInputFiles({
      name: "e2e.rules",
      mimeType: "text/plain",
      buffer: Buffer.from('alert tcp any any -> any any (msg:"e2e any tcp"; sid:1000001;)'),
    });
    // The status notice confirms the engine parsed + applied the rules.
    await expect(page.getByText(/Rules: \d+ loaded/)).toBeVisible({ timeout: 20_000 });
  });
});
