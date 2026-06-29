import { useEffect } from "react";
import { ArrowLeft, Radar } from "lucide-react";
import { ThemeToggle } from "../cockpit/ThemeToggle";
import { ToolPage } from "./ToolPage";
import { seoBySlug } from "./registry";

/** Public SEO marketing route shell. Per-route <title>/meta are baked into static HTML at build
 *  time (scripts/gen-seo-html.mjs); this also sets them client-side for dev + SPA navigation. */
export function ToolApp() {
  const slug = window.location.pathname.replace(/^\/+/, "").replace(/\/+$/, "");
  const page = seoBySlug[slug];

  useEffect(() => {
    if (!page) return;
    document.title = page.metaTitle;
    let m = document.querySelector('meta[name="description"]');
    if (!m) {
      m = document.createElement("meta");
      m.setAttribute("name", "description");
      document.head.appendChild(m);
    }
    m.setAttribute("content", page.metaDescription);
  }, [page]);

  return (
    <div className="min-h-screen bg-[var(--color-bg)] text-[var(--color-text)]">
      <header className="flex h-14 items-center gap-3 border-b border-[var(--color-border)] bg-[var(--color-surface)] px-4">
        <a href="/" aria-label="Back to home" className="flex items-center gap-2 text-[var(--color-text-dim)] hover:text-[var(--color-text)]">
          <ArrowLeft size={16} aria-hidden />
          <span
            className="flex h-7 w-7 items-center justify-center rounded-[var(--r-tile)]"
            style={{ background: "color-mix(in srgb, var(--color-accent) 16%, transparent)" }}
          >
            <Radar size={16} style={{ color: "var(--color-accent)" }} aria-hidden />
          </span>
          <span className="font-display text-[15px] font-medium tracking-tight">PacketPilot</span>
        </a>
        <div className="ml-auto flex items-center gap-3">
          <a href="/pricing" className="text-xs text-[var(--color-text-dim)] hover:text-[var(--color-text)]">Pricing</a>
          <ThemeToggle />
        </div>
      </header>

      {page ? (
        <ToolPage page={page} />
      ) : (
        <div className="mx-auto max-w-3xl px-4 py-20 text-center">
          <p className="text-[var(--color-text-dim)]">That page doesn't exist.</p>
          <a href="/app" className="mt-2 inline-block text-sm text-[var(--color-accent-strong)]">Open the app</a>
        </div>
      )}

      <footer className="border-t border-[var(--color-border)] px-4 py-6 text-center">
        <nav className="flex flex-wrap justify-center gap-4 t-tag text-[var(--color-text-faint)]">
          <a href="/app" className="hover:text-[var(--color-text-dim)]">Launch app</a>
          <a href="/pricing" className="hover:text-[var(--color-text-dim)]">Pricing</a>
          <a href="/security" className="hover:text-[var(--color-text-dim)]">Security</a>
          <a href="/privacy" className="hover:text-[var(--color-text-dim)]">Privacy</a>
        </nav>
      </footer>
    </div>
  );
}

export default ToolApp;
