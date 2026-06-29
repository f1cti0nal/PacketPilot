export type Route = "landing" | "app" | "admin" | "account" | "legal";

/** Static legal/trust pages, served by the same SPA bundle (see main.tsx). */
const LEGAL_PATHS = new Set(["/security", "/privacy", "/terms"]);

/** Minimal pathname routing shared by main.tsx. Trailing slashes are ignored.
 *  Note "/administrator" must NOT match admin — only "/admin" and "/admin/...";
 *  likewise "/accounts" must NOT match account. */
export function resolveRoute(pathname: string): Route {
  const path = pathname.replace(/\/+$/, "");
  if (path === "/admin" || path.startsWith("/admin/")) return "admin";
  if (path === "/account" || path.startsWith("/account/")) return "account";
  if (LEGAL_PATHS.has(path)) return "legal";
  if (path === "/app" || path.startsWith("/app/")) return "app";
  return "landing";
}
