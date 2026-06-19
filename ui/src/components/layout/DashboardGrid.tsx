import type { ReactNode } from "react";

export interface DashboardGridProps {
  children: ReactNode;
}

export function DashboardGrid({ children }: DashboardGridProps) {
  return <div data-component="DashboardGrid">{children}</div>;
}

export default DashboardGrid;
