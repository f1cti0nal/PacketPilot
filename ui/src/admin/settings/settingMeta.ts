export type SettingKind = "banner" | "json";

/** Known keys get a typed editor; everything else uses the validated raw-JSON editor. */
export function settingKind(key: string): SettingKind {
  return key === "announcement_banner" ? "banner" : "json";
}
