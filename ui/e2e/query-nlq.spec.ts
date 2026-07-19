import { expect, test, type Page } from "@playwright/test";

/**
 * Phase 3 e2e for the natural-language layer, with the ai-proxy edge function
 * and the public-settings RPC mocked at the network layer (no real provider).
 *
 * Requires VITE_SUPABASE_URL / VITE_SUPABASE_ANON_KEY in the runner env (the
 * Playwright webServer inherits them, which makes the app's supabase client
 * configured so the AI gate + proxy URL exist). Without them the NL row is
 * hidden by design, so these tests skip — matching CI, which exercises the AI
 * surfaces at the unit level only.
 */
const AI_ENV = Boolean(process.env.VITE_SUPABASE_URL && process.env.VITE_SUPABASE_ANON_KEY);
test.skip(!AI_ENV, "needs VITE_SUPABASE_URL/VITE_SUPABASE_ANON_KEY (NL row hidden otherwise)");

/** OpenAI-style SSE body carrying `text` in small deltas. */
function sse(text: string): string {
  const chunks = text.match(/[\s\S]{1,40}/g) ?? [];
  return (
    chunks
      .map((c) => `data: ${JSON.stringify({ choices: [{ delta: { content: c } }] })}\n\n`)
      .join("") + "data: [DONE]\n\n"
  );
}

/** Mock the Supabase surface: settings RPC (AI on), ai-proxy (canned replies), abort the rest. */
async function mockAi(page: Page, replies: string[]): Promise<{ calls: () => number }> {
  let calls = 0;
  const base = process.env.VITE_SUPABASE_URL!;
  // LIFO routing: register the catch-all first so the specific mocks win.
  await page.route(`${base}/**`, (route) => route.abort());
  await page.route("**/rest/v1/rpc/get_public_settings", (route) =>
    route.fulfill({
      json: { ai_config: { enabled: true, provider: "anthropic", model: "test-model" } },
    }),
  );
  await page.route("**/functions/v1/ai-proxy", (route) => {
    const reply = replies[Math.min(calls, replies.length - 1)];
    calls += 1;
    return route.fulfill({ status: 200, contentType: "text/event-stream", body: sse(reply) });
  });
  return { calls: () => calls };
}

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
  await expect(page.getByText(/flows loaded · local only/)).toBeVisible({ timeout: 60_000 });
}

/** Type a question and generate; a fresh browser context always shows the consent dialog. */
async function generate(page: Page, question: string) {
  await page.getByLabel("Ask in plain English").fill(question);
  await page.getByRole("button", { name: "Generate SQL" }).click();
  const consent = page.getByRole("dialog", { name: "AI consent" });
  await expect(consent).toBeVisible();
  await expect(consent).toContainText("questions you type");
  await consent.getByRole("button", { name: "Proceed" }).click();
}

const editor = (page: Page) => page.getByLabel("SQL query");

test.describe("Query console — natural language", () => {
  test("question → consent → generated SQL streams into the editor → Run", async ({ page }) => {
    await mockAi(page, [
      "-- intent: count flows per category\nSELECT category, COUNT(*) AS flows FROM flow GROUP BY category ORDER BY flows DESC",
    ]);
    await openSampleCapture(page);
    await openQueryTab(page);

    await generate(page, "how many flows per category?");
    await expect(editor(page)).toHaveValue(/count flows per category/);
    await expect(page.locator('[data-component="QueryIntent"]')).toHaveText(
      "Intent: count flows per category",
    );

    await page.getByRole("button", { name: /^Run$/ }).click();
    await expect(page.getByText(/^\d[\d,.]* rows?$/).first()).toBeVisible({ timeout: 30_000 });
    const grid = page.locator('[data-component="ResultsGrid"]');
    await expect(grid.locator('[role="columnheader"]').first()).toHaveText("category");
  });

  test("a failing generated query gets exactly one automatic repair round", async ({ page }) => {
    const proxy = await mockAi(page, [
      // First reply references a column that doesn't exist → DuckDB error on Run.
      "-- intent: total bytes per category\nSELECT category, SUM(bytes_total) AS bytes FROM flow GROUP BY category",
      // Repair reply is valid.
      "-- intent: total bytes per category\nSELECT category, SUM(bytes_c2s + bytes_s2c) AS bytes FROM flow GROUP BY category ORDER BY bytes DESC",
    ]);
    await openSampleCapture(page);
    await openQueryTab(page);

    await generate(page, "total bytes per category");
    await expect(editor(page)).toHaveValue(/bytes_total/);

    await page.getByRole("button", { name: /^Run$/ }).click();
    // The repair round replaces the SQL and re-runs it automatically.
    await expect(editor(page)).toHaveValue(/bytes_c2s \+ bytes_s2c/, { timeout: 30_000 });
    await expect(page.getByText(/^\d[\d,.]* rows?$/).first()).toBeVisible({ timeout: 30_000 });
    expect(proxy.calls()).toBe(2);
  });

  test("an unanswerable question surfaces the model's error, keeping the editor intact", async ({
    page,
  }) => {
    await mockAi(page, ["-- error: payload contents are not in the flow table"]);
    await openSampleCapture(page);
    await openQueryTab(page);

    const before = await editor(page).inputValue();
    await generate(page, "what did the malware download?");
    await expect(page.getByRole("alert")).toContainText("payload contents are not in the flow table");
    await expect(editor(page)).toHaveValue(before);
  });
});
