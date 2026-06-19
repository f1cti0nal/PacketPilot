export interface StatTileProps {
  label: string;
  value: string;
  hint?: string;
  intent?: "default" | "warn" | "danger";
}

export function StatTile({ label, value }: StatTileProps) {
  return (
    <div data-component="StatTile">
      <span>{label}</span>
      <span>{value}</span>
    </div>
  );
}

export default StatTile;
