import { test, expect, type Page } from "@playwright/test";

/** The KPI cluster's "Packets" label only renders once the sample capture has loaded. */
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

test.describe("PacketPilot — desktop", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/app");
    await waitForDashboard(page);
  });

  test("loads the dashboard, threat rail, and brand chrome", async ({ page }) => {
    await expect(page.getByText("PacketPilot").first()).toBeVisible();
    await expect(page.getByText("Packets").first()).toBeVisible();
    await expect(page.getByRole("complementary")).toBeVisible(); // threat rail
  });

  test("light/dark theme toggle flips data-theme and round-trips", async ({ page }) => {
    const html = page.locator("html");
    const before = (await html.getAttribute("data-theme")) ?? "dark";
    await page.locator('[data-component="ThemeToggle"]').click();
    await expect(html).not.toHaveAttribute("data-theme", before);
    await page.locator('[data-component="ThemeToggle"]').click();
    await expect(html).toHaveAttribute("data-theme", before);
  });

  test("density toggle flips data-density and round-trips", async ({ page }) => {
    const html = page.locator("html");
    await page.locator('[data-component="DensityToggle"]').click();
    await expect(html).toHaveAttribute("data-density", "compact");
    await page.locator('[data-component="DensityToggle"]').click();
    await expect(html).toHaveAttribute("data-density", "comfortable");
  });

  test("navigates Dashboard → Flows → Recent → Dashboard", async ({ page }) => {
    await page.getByRole("button", { name: "Flows", exact: true }).click();
    await expect(page.getByLabel("Filter flows")).toBeVisible();
    await page.getByRole("button", { name: "Recent", exact: true }).click();
    await page.getByRole("button", { name: "Dashboard", exact: true }).click();
    await expect(page.getByText("Packets").first()).toBeVisible();
  });

  test("command palette opens with Ctrl+K, filters, and closes on Escape", async ({ page }) => {
    await page.keyboard.press("Control+k");
    const input = page.getByLabel("Command palette query");
    await expect(input).toBeVisible();
    await input.fill("flows");
    await expect(page.getByText("Go to Flows")).toBeVisible();
    await page.keyboard.press("Escape");
    await expect(input).toBeHidden();
  });

  test("? opens the keyboard shortcuts overlay; Escape closes it", async ({ page }) => {
    await page.keyboard.press("Shift+Slash");
    await expect(page.getByRole("dialog", { name: "Keyboard shortcuts" })).toBeVisible();
    await page.keyboard.press("Escape");
    await expect(page.getByRole("dialog", { name: "Keyboard shortcuts" })).toBeHidden();
  });

  test("digit key 2 jumps to Flows", async ({ page }) => {
    await page.keyboard.press("2");
    await expect(page.getByLabel("Filter flows")).toBeVisible();
  });

  test("settings dialog opens and closes on Escape", async ({ page }) => {
    await page.getByRole("button", { name: "Settings" }).click();
    await expect(page.getByRole("dialog", { name: "Settings" })).toBeVisible();
    await page.keyboard.press("Escape");
    await expect(page.getByRole("dialog", { name: "Settings" })).toBeHidden();
  });

  test("export menu lists formats", async ({ page }) => {
    await page.getByRole("button", { name: /export/i }).click();
    await expect(page.getByRole("menuitem", { name: "HTML report" })).toBeVisible();
  });

  test("no uncaught exceptions during a load + interaction flow", async ({ page }) => {
    const errors: string[] = [];
    page.on("pageerror", (e) => errors.push(`${e.name}: ${e.message}`));
    await page.goto("/app");
    await waitForDashboard(page);
    await page.getByRole("button", { name: "Flows", exact: true }).click();
    await expect(page.getByLabel("Filter flows")).toBeVisible();
    expect(errors, errors.join("\n")).toEqual([]);
  });
});

test.describe("PacketPilot — mobile", () => {
  test.use({ viewport: { width: 390, height: 800 } });

  test("uses the bottom tab bar and opens the threat drawer", async ({ page }) => {
    await page.goto("/app");
    await waitForDashboard(page);
    await expect(page.getByRole("navigation", { name: "Primary" })).toBeVisible();
    await expect(page.getByRole("complementary")).toHaveCount(0); // no always-on rail
    await page.getByRole("button", { name: /Threat watchlist/ }).click();
    await expect(page.getByRole("dialog", { name: "Threats" })).toBeVisible();
  });
});
