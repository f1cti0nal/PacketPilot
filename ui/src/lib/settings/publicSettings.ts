export interface AnnouncementBanner {
  text: string;
  severity: "info" | "warning" | "critical";
  dismissible: boolean;
}
export interface PublicSettings {
  announcement_banner: AnnouncementBanner | null;
}
export const SETTINGS_DEFAULTS: PublicSettings = { announcement_banner: null };

const SEVERITIES: AnnouncementBanner["severity"][] = ["info", "warning", "critical"];

export function parsePublicSettings(raw: unknown): PublicSettings {
  const obj = raw && typeof raw === "object" ? (raw as Record<string, unknown>) : {};
  const b = obj.announcement_banner;
  let banner: AnnouncementBanner | null = null;
  if (b && typeof b === "object") {
    const bb = b as Record<string, unknown>;
    const text = typeof bb.text === "string" ? bb.text : "";
    if (text.trim()) {
      const severity = SEVERITIES.includes(bb.severity as AnnouncementBanner["severity"])
        ? (bb.severity as AnnouncementBanner["severity"])
        : "info";
      banner = { text, severity, dismissible: bb.dismissible !== false };
    }
  }
  return { announcement_banner: banner };
}
