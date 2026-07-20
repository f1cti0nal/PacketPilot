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
  await dismissReputationConsents(page);
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

  test("Safe Share exports a sanitized capture plus its manifest", async ({ page }) => {
    await uploadPcap(page); // Safe Share needs the raw capture bytes
    await page.getByRole("button", { name: /export/i }).click();
    await page.getByRole("menuitem", { name: /Sanitized capture/i }).click();

    const dialog = page.getByRole("dialog", { name: "Export sanitized capture" });
    await expect(dialog).toBeVisible();
    // Defaults: scrub payloads + preserve subnet structure.
    await expect(dialog.getByText(/Scrub payloads/)).toBeVisible();

    const downloads: string[] = [];
    page.on("download", (d) => downloads.push(d.suggestedFilename()));
    await dialog.getByRole("button", { name: "Export" }).click();

    // The dialog flips to the run summary once the WASM pass finishes.
    await expect(dialog.getByText(/Done — [\d,]+ packets sanitized/)).toBeVisible({ timeout: 30_000 });
    await expect(dialog.getByText(/output sha256 [0-9a-f]{64}/)).toBeVisible();
    expect(downloads.some((n) => /-sanitized\.pcap$/i.test(n)), downloads.join(", ")).toBe(true);
    expect(downloads.some((n) => /\.manifest\.json$/i.test(n)), downloads.join(", ")).toBe(true);

    await dialog.getByRole("button", { name: "Close" }).click();
    await expect(dialog).toBeHidden();
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
