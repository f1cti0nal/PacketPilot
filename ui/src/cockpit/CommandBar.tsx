// Fixed 56px top bar for the content column: capture identity + live status pill on the
// left, capture actions on the right. Primary navigation lives in
// the left SideNav (desktop) or the BottomTabBar (mobile) — not here. On mobile, where there
// is no SideNav, this bar also carries the clickable brand so "return to overview" stays
// reachable.
import type { ReactNode } from "react";
import {
  Radar,
  Upload,
  Loader2,
  Command as CommandIcon,
  CheckCircle2,
  Sparkles,
} from "lucide-react";
import { shortHash } from "../lib/format";
import { BTN_GHOST_ICON, BTN_OUTLINE } from "./primitives";
import { ExportMenu } from "./ExportMenu";
import type { ExportAction } from "./ExportMenu";
import { ThemeToggle } from "./ThemeToggle";
import { DensityToggle } from "./DensityToggle";

export function CommandBar({
  captureName,
  sha256,
  onGoHome,
  showBrand = false,
  captureStatus = "ready",
  captureError,
  onRequestLoad,
  exportActions,
  exporting = false,
  exportHint,
  onOpenPalette,
  onOpenAiChat,
  rulesMenu,
}: {
  captureName: string;
  sha256?: string;
  /** Return to the Home overview (unloads the active capture). Makes the mobile brand clickable. */
  onGoHome?: () => void;
  /** Render the clickable brand on the left. On for mobile (no SideNav), off on desktop. */
  showBrand?: boolean;
  captureStatus?: "idle" | "loading" | "ready" | "error";
  captureError?: string;
  onRequestLoad?: () => void;
  exportActions?: ExportAction[];
  exporting?: boolean;
  exportHint?: string;
  onOpenPalette?: () => void;
  onOpenAiChat?: () => void;
  /** Slot for the RuleSetsMenu dropdown (or any rules affordance). */
  rulesMenu?: ReactNode;
}) {
  return (
    <header className="relative z-30 flex h-14 shrink-0 items-center gap-3 border-b border-[var(--color-border)] bg-[var(--color-surface)] px-3">
      {/* Brand (mobile only — desktop shows it in the SideNav). */}
      {showBrand &&
        (onGoHome ? (
          <button
            type="button"
            onClick={onGoHome}
            aria-label="Go to overview"
            className="flex items-center gap-2 rounded-[var(--r-tile)] transition-opacity hover:opacity-80"
          >
            <BrandMark />
          </button>
        ) : (
          <BrandMark />
        ))}

      {/* Capture identity. Deferred to lg: at the md boundary the identity + action cluster
          together overflowed the bar. The capture name/status is secondary — the dashboard
          already shows the capture context. */}
      <div className="hidden min-w-0 items-center gap-2.5 lg:flex">
        {captureStatus === "loading" && (
          <>
            <Loader2 size={13} className="animate-spin text-[var(--color-text-faint)]" aria-hidden />
            <span className="font-mono-num truncate text-xs text-[var(--color-text-dim)]">Loading…</span>
          </>
        )}
        {captureStatus === "ready" && (
          <>
            <span className="font-mono-num truncate text-xs text-[var(--color-text-dim)]" title={captureName}>
              {captureName}
            </span>
            {sha256 && (
              <span className="font-mono-num hidden text-xs text-[var(--color-text-faint)] lg:inline" title={sha256}>
                {shortHash(sha256, 8, 6)}
              </span>
            )}
            <span className="inline-flex items-center rounded-full border border-[color:color-mix(in_srgb,var(--color-accent)_40%,transparent)] bg-[color:color-mix(in_srgb,var(--color-accent)_10%,transparent)] px-2 py-0.5">
              <span className="t-tag font-medium uppercase text-[var(--color-accent)]">Analyzed</span>
            </span>
          </>
        )}
        {captureStatus === "error" && (
          <span className="font-mono-num truncate text-xs text-[var(--color-text-faint)]">
            {captureError ?? "Error loading capture"}
          </span>
        )}
        {captureStatus === "idle" && (
          <span className="font-mono-num truncate text-xs text-[var(--color-text-faint)]">No capture</span>
        )}
      </div>

      {/* Right: capture actions. */}
      <div className="ml-auto flex items-center gap-2">
        <ActionButton
          icon={<Upload size={14} />}
          label="Load capture"
          onClick={onRequestLoad}
          disabled={!onRequestLoad}
        />
        <ExportMenu actions={exportActions ?? []} disabled={(exportActions?.length ?? 0) === 0} busy={exporting} />
        {/* Always-present polite live region so export success/failure is announced on
            every viewport (SR-only below lg, visible chip at lg+). Conditionally rendering
            it would miss the announcement, and `hidden` made a failed export silent. */}
        <span
          role="status"
          aria-live="polite"
          className="sr-only items-center gap-1 text-xs text-[var(--color-text-dim)] lg:not-sr-only lg:inline-flex"
        >
          {exportHint ? (
            <>
              <CheckCircle2 size={12} aria-hidden className="hidden text-[var(--color-accent)] lg:inline-block" />
              {exportHint}
            </>
          ) : null}
        </span>
        <button
          type="button"
          aria-label="Command palette"
          onClick={onOpenPalette}
          disabled={!onOpenPalette}
          className="hidden items-center gap-1.5 rounded-[var(--r-tile)] border border-[var(--color-border)] bg-transparent px-2 py-1.5 text-[var(--color-text-faint)] transition-colors hover:border-[var(--color-border-strong)] hover:text-[var(--color-text-dim)] disabled:cursor-default disabled:opacity-50 lg:inline-flex"
        >
          <CommandIcon size={13} />
          <span className="t-tag">K</span>
        </button>
        {onOpenAiChat && (
          <button
            type="button"
            aria-label="Ask AI"
            onClick={onOpenAiChat}
            className={BTN_GHOST_ICON}
          >
            <Sparkles size={14} />
          </button>
        )}
        {/* Density is a dashboard power-tweak — hide it (and Rules) until lg so the action
            cluster fits the tablet range with the larger type scale; both return at lg+.
            (Still reachable via the ⌘K palette.) */}
        <span className="hidden lg:contents"><DensityToggle /></span>
        <ThemeToggle />
        {rulesMenu && <span className="hidden lg:contents">{rulesMenu}</span>}
      </div>
    </header>
  );
}

/** The glyph + wordmark lockup used by the mobile brand. */
function BrandMark() {
  return (
    <>
      <span
        className="flex h-7 w-7 items-center justify-center rounded-[var(--r-tile)]"
        style={{ background: "color-mix(in srgb, var(--color-accent) 16%, transparent)" }}
      >
        <Radar size={17} style={{ color: "var(--color-accent)" }} aria-hidden />
      </span>
      <span className="hidden font-display text-[15px] font-medium tracking-tight sm:inline">PacketPilot</span>
    </>
  );
}

function ActionButton({
  icon,
  label,
  onClick,
  disabled,
}: {
  icon: React.ReactNode;
  label: string;
  onClick?: () => void;
  disabled?: boolean;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      aria-label={label}
      className={BTN_OUTLINE}
    >
      {icon}
      <span className="hidden lg:inline">{label}</span>
    </button>
  );
}

export default CommandBar;
