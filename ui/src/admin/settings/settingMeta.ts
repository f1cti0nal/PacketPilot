export type SettingKind = "banner" | "ai" | "json";

/** Known keys get a typed editor; everything else uses the validated raw-JSON editor. */
export function settingKind(key: string): SettingKind {
  if (key === "announcement_banner") return "banner";
  if (key === "ai_config") return "ai";
  return "json";
}
