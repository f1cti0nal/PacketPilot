export type Route = "landing" | "app" | "admin";

/** Minimal pathname routing shared by main.tsx. Trailing slashes are ignored.
 *  Note "/administrator" must NOT match admin — only "/admin" and "/admin/...". */
export function resolveRoute(pathname: string): Route {
  const path = pathname.replace(/\/+$/, "");
  if (path === "/admin" || path.startsWith("/admin/")) return "admin";
  if (path === "/app" || path.startsWith("/app/")) return "app";
  return "landing";
}
