import type { ReactNode } from "react";

export interface PanelProps {
  title: string;
  subtitle?: string;
  toolbar?: ReactNode;
  className?: string;
  children: ReactNode;
}

export function Panel({ title, children }: PanelProps) {
  return (
    <div data-component="Panel">
      <div>{title}</div>
      {children}
    </div>
  );
}

export default Panel;
