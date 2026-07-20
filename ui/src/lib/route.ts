import { TOOL_PATHS } from "../seo/slugs";

export type Route = "landing" | "app" | "admin" | "legal" | "tool" | "blog";

/** Static legal/trust pages, served by the same SPA bundle (see main.tsx). */
const LEGAL_PATHS = new Set(["/security", "/privacy", "/terms"]);

/** Minimal pathname routing shared by main.tsx. Trailing slashes are ignored.
 *  Note "/administrator" must NOT match admin — only "/admin" and "/admin/...". */
export function resolveRoute(pathname: string): Route {
  const path = pathname.replace(/\/+$/, "");
  if (path === "/admin" || path.startsWith("/admin/")) return "admin";
  if (LEGAL_PATHS.has(path)) return "legal";
  if (path === "/blog" || path.startsWith("/blog/")) return "blog";
  if (TOOL_PATHS.has(path)) return "tool";
  if (path === "/app" || path.startsWith("/app/")) return "app";
  return "landing";
}

/** The admin console is isolated on an `admin.` subdomain. On that host every path serves the
 *  admin app; only there. */
export function isAdminHost(hostname: string): boolean {
  return /^admin\./i.test(hostname);
}

/** Route for the current host + path: the admin subdomain always renders admin; every other
 *  host routes by pathname. */
export function resolveRouteFor(hostname: string, pathname: string): Route {
  return isAdminHost(hostname) ? "admin" : resolveRoute(pathname);
}
