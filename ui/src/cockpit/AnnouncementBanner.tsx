import { useState } from "react";
import { X } from "lucide-react";
import type { AnnouncementBanner as Banner } from "../lib/settings/publicSettings";

const SEV_COLOR: Record<string, string> = {
  info: "var(--color-accent)",
  warning: "var(--color-sev-medium)",
  critical: "var(--color-sev-critical)",
};

function dismissKey(text: string): string {
  let h = 0;
  for (let i = 0; i < text.length; i++) h = (h * 31 + text.charCodeAt(i)) | 0;
  return `pp_banner_dismiss_${h}`;
}

export function AnnouncementBanner({ banner }: { banner: Banner | null }) {
  const [dismissed, setDismissed] = useState(false);
  if (!banner || !banner.text.trim() || dismissed) return null;
  let already = false;
  try {
    already = sessionStorage.getItem(dismissKey(banner.text)) === "1";
  } catch {
    already = false;
  }
  if (already) return null;
  const color = SEV_COLOR[banner.severity] ?? "var(--color-accent)";
  return (
    <div role="status" className="flex items-center gap-3 px-4 py-2 text-sm" style={{ background: color, color: "var(--color-on-accent)" }}>
      <span className="flex-1">{banner.text}</span>
      {banner.dismissible && (
        <button
          type="button"
          aria-label="Dismiss announcement"
          onClick={() => {
            try {
              sessionStorage.setItem(dismissKey(banner.text), "1");
            } catch {
              /* ignore */
            }
            setDismissed(true);
          }}
          className="opacity-80 hover:opacity-100"
        >
          <X size={16} aria-hidden />
        </button>
      )}
    </div>
  );
}

export default AnnouncementBanner;
