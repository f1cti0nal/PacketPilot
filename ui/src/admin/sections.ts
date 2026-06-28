import { LayoutDashboard, Users, CreditCard, Activity, ToggleRight, Settings, KeyRound, type LucideIcon } from "lucide-react";

export interface AdminSection {
  id: string;
  label: string;
  icon: LucideIcon;
  phase: number;
}

export const ADMIN_SECTIONS = [
  { id: "dashboard", label: "Dashboard", icon: LayoutDashboard, phase: 4 },
  { id: "users", label: "Users", icon: Users, phase: 5 },
  { id: "payments", label: "Payments", icon: CreditCard, phase: 6 },
  { id: "traffic", label: "Live Traffic", icon: Activity, phase: 7 },
  { id: "features", label: "App Features", icon: ToggleRight, phase: 8 },
  { id: "settings", label: "Settings", icon: Settings, phase: 9 },
  { id: "env", label: "Environment", icon: KeyRound, phase: 9 },
] as const satisfies readonly AdminSection[];

export type AdminSectionId = (typeof ADMIN_SECTIONS)[number]["id"];

export function sectionById(id: string): (typeof ADMIN_SECTIONS)[number] | undefined {
  return ADMIN_SECTIONS.find((s) => s.id === id);
}
