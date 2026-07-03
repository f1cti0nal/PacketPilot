import { LayoutDashboard, Users, CreditCard, Activity, ToggleRight, Settings, KeyRound, type LucideIcon } from "lucide-react";

export type AdminGroup = "Overview" | "Configuration";

export interface AdminSection {
  id: string;
  label: string;
  icon: LucideIcon;
  phase: number;
  group: AdminGroup;
  /** One-line description shown as the top-bar subtitle for the section. */
  desc: string;
}

export const ADMIN_SECTIONS = [
  { id: "dashboard", label: "Dashboard", icon: LayoutDashboard, phase: 4, group: "Overview", desc: "Key metrics across your workspace" },
  { id: "users", label: "Users", icon: Users, phase: 5, group: "Overview", desc: "Manage accounts, plans and roles" },
  { id: "payments", label: "Payments", icon: CreditCard, phase: 6, group: "Overview", desc: "Subscriptions and revenue from Stripe" },
  { id: "traffic", label: "Live Traffic", icon: Activity, phase: 7, group: "Overview", desc: "Live visits and page activity" },
  { id: "features", label: "App Features", icon: ToggleRight, phase: 8, group: "Configuration", desc: "Toggle features and plan gates" },
  { id: "settings", label: "Settings", icon: Settings, phase: 9, group: "Configuration", desc: "App configuration and content" },
  { id: "env", label: "Environment", icon: KeyRound, phase: 9, group: "Configuration", desc: "Environment variables and secrets" },
] as const satisfies readonly AdminSection[];

export type AdminSectionId = (typeof ADMIN_SECTIONS)[number]["id"];

export const ADMIN_GROUPS: AdminGroup[] = ["Overview", "Configuration"];

export function sectionById(id: string): (typeof ADMIN_SECTIONS)[number] | undefined {
  return ADMIN_SECTIONS.find((s) => s.id === id);
}
