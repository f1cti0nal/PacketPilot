import { Card } from "../../cockpit/primitives";

/** On-brand "coming soon" panel for sections not yet built. */
export function Placeholder({ title, phase }: { title: string; phase: number }) {
  return (
    <Card title={title}>
      <p className="text-sm text-[var(--color-text-dim)]">
        This section is coming in Phase {phase}.
      </p>
    </Card>
  );
}

export default Placeholder;
