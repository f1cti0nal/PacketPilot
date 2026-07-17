import { chromium } from "playwright";
import { mkdirSync } from "node:fs";

const OUT =
  "C:/Users/ravid/AppData/Local/Temp/claude/D--Project-PacketPilot/4639d116-131a-4c65-a342-7d27288ce653/scratchpad/appshots";
mkdirSync(OUT, { recursive: true });
const base = "http://localhost:5230";
const browser = await chromium.launch();

async function session({ theme, viewport, density, mobile }) {
  const ctx = await browser.newContext({
    viewport,
    deviceScaleFactor: 2,
    colorScheme: theme,
    isMobile: !!mobile,
  });
  const page = await ctx.newPage();
  await page.addInitScript(
    ([t, d]) => {
      localStorage.setItem("packetpilot.theme.v1", t);
      if (d) localStorage.setItem("packetpilot.density.v1", d);
    },
    [theme, density ?? ""],
  );
  return { ctx, page };
}

const clickNav = async (page, name) => {
  const btn = page.getByRole("button", { name, exact: false }).first();
  const link = page.getByRole("link", { name, exact: false }).first();
  if (await btn.isVisible().catch(() => false)) await btn.click();
  else if (await link.isVisible().catch(() => false)) await link.click();
  await page.waitForTimeout(1300);
};

// ── Dark desktop: all tabs ──
{
  const { ctx, page } = await session({ theme: "dark", viewport: { width: 1440, height: 900 } });
  await page.goto(base + "/app?sample=1", { waitUntil: "networkidle" });
  await page.waitForTimeout(6000);
  await page.screenshot({ path: OUT + "/d01-dashboard.png" });
  for (const [name, file] of [
    ["Flows", "d02-flows"],
    ["Findings", "d03-findings"],
    ["Threats", "d04-threats"],
    ["Recent", "d05-recent"],
  ]) {
    await clickNav(page, name);
    await page.screenshot({ path: OUT + "/" + file + ".png" });
  }
  await page.goto(base + "/app", { waitUntil: "networkidle" });
  await page.waitForTimeout(2000);
  await page.screenshot({ path: OUT + "/d06-home.png" });
  await ctx.close();
}

// ── Light desktop: dashboard fresh load ──
{
  const { ctx, page } = await session({ theme: "light", viewport: { width: 1440, height: 900 } });
  await page.goto(base + "/app?sample=1", { waitUntil: "networkidle" });
  await page.waitForTimeout(6000);
  await page.screenshot({ path: OUT + "/l01-dashboard.png" });
  await clickNav(page, "Flows");
  await page.screenshot({ path: OUT + "/l02-flows.png" });
  await ctx.close();
}

// ── Mobile dark ──
{
  const { ctx, page } = await session({
    theme: "dark",
    viewport: { width: 375, height: 812 },
    mobile: true,
  });
  await page.goto(base + "/app?sample=1", { waitUntil: "networkidle" });
  await page.waitForTimeout(6000);
  await page.screenshot({ path: OUT + "/m01-dashboard.png" });
  await ctx.close();
}

// ── Compact density dark ──
{
  const { ctx, page } = await session({
    theme: "dark",
    viewport: { width: 1440, height: 900 },
    density: "compact",
  });
  await page.goto(base + "/app?sample=1", { waitUntil: "networkidle" });
  await page.waitForTimeout(6000);
  await page.screenshot({ path: OUT + "/c01-dashboard.png" });
  await ctx.close();
}

await browser.close();
console.log("done");
