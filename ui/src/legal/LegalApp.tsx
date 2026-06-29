import { ArrowLeft, Radar } from "lucide-react";
import { ThemeToggle } from "../cockpit/ThemeToggle";
import { LegalPage } from "./LegalPage";
import { LEGAL_PAGES } from "./content";

/** Standalone shell for the static legal/trust routes (/security, /privacy, /terms). */
export function LegalApp() {
  const path = (window.location.pathname.replace(/\/+$/, "") || "/") as keyof typeof LEGAL_PAGES;
  const content = LEGAL_PAGES[path];

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
        <div className="ml-auto">
          <ThemeToggle />
        </div>
      </header>

      {content ? (
        <LegalPage content={content} />
      ) : (
        <div className="mx-auto max-w-3xl px-4 py-20 text-center">
          <p className="text-[var(--color-text-dim)]">That page doesn't exist.</p>
          <a href="/" className="mt-2 inline-block text-sm text-[var(--color-accent-strong)]">
            Back to home
          </a>
        </div>
      )}

      <footer className="border-t border-[var(--color-border)] px-4 py-6 text-center">
        <nav className="flex justify-center gap-4 t-tag text-[var(--color-text-faint)]">
          <a href="/security" className="hover:text-[var(--color-text-dim)]">Security</a>
          <a href="/privacy" className="hover:text-[var(--color-text-dim)]">Privacy</a>
          <a href="/terms" className="hover:text-[var(--color-text-dim)]">Terms</a>
          <a href="/app" className="hover:text-[var(--color-text-dim)]">Launch app</a>
        </nav>
        <p className="mt-2 t-tag text-[var(--color-text-faint)]">© 2026 PacketPilot · Runs locally — your captures stay yours</p>
      </footer>
    </div>
  );
}

export default LegalApp;
