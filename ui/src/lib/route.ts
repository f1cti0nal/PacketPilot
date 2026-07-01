import { TOOL_PATHS } from "../seo/slugs";

export type Route = "landing" | "app" | "admin" | "account" | "legal" | "pricing" | "tool" | "auth";

/** Static legal/trust pages, served by the same SPA bundle (see main.tsx). */
const LEGAL_PATHS = new Set(["/security", "/privacy", "/terms"]);

/** Dedicated auth endpoints, each its own path so sign-in traffic is easy to monitor and
 *  link to. AuthApp reads the exact pathname to pick login/signup/logout. */
const AUTH_PATHS = new Set(["/login", "/signup", "/logout"]);

/** Minimal pathname routing shared by main.tsx. Trailing slashes are ignored.
 *  Note "/administrator" must NOT match admin — only "/admin" and "/admin/...";
 *  likewise "/accounts" must NOT match account. */
export function resolveRoute(pathname: string): Route {
  const path = pathname.replace(/\/+$/, "");
  if (path === "/admin" || path.startsWith("/admin/")) return "admin";
  if (path === "/account" || path.startsWith("/account/")) return "account";
  if (AUTH_PATHS.has(path)) return "auth";
  if (LEGAL_PATHS.has(path)) return "legal";
  if (path === "/pricing") return "pricing";
  if (TOOL_PATHS.has(path)) return "tool";
  if (path === "/app" || path.startsWith("/app/")) return "app";
  return "landing";
}
