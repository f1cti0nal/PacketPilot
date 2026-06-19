import type { Severity } from "../../types";

export interface ChipProps {
  severity?: Severity;
  proto?: string;
  label: string;
  count?: number;
  selected?: boolean;
  onClick?: () => void;
}

export function Chip({ label }: ChipProps) {
  return <span data-component="Chip">{label}</span>;
}

export default Chip;
