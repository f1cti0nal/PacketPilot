import { test, expect } from "@playwright/test";

// Admin-subdomain isolation (resolveRouteFor): every path on an `admin.` host serves the
// admin console; other hosts keep pathname routing. `admin.localhost` resolves to 127.0.0.1
// in Chromium and Vite allows `*.localhost` Host headers by default, so this exercises the
// exact host-based branch that admin.packetpilot.app hits in production.
const PORT = 5199;
const ADMIN_ORIGIN = `http://admin.localhost:${PORT}`;

test("admin host serves the admin console at /", async ({ page }) => {
  await page.goto(`${ADMIN_ORIGIN}/`);
  await expect(page.getByRole("heading", { name: "PacketPilot Admin" })).toBeVisible();
});

test("admin host serves the admin console on any path", async ({ page }) => {
  await page.goto(`${ADMIN_ORIGIN}/app/anything?x=1`);
  await expect(page.getByRole("heading", { name: "PacketPilot Admin" })).toBeVisible();
});

test("non-admin host still routes by pathname", async ({ page }) => {
  // Landing page on the bare host…
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "PacketPilot Admin" })).not.toBeVisible();
  // …and /admin still reaches the console there (no lockout until the redirect flip).
  await page.goto("/admin");
  await expect(page.getByRole("heading", { name: "PacketPilot Admin" })).toBeVisible();
});
