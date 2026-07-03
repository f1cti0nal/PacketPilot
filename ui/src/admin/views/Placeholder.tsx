import { AdminCard } from "../ui/kit";

/** On-brand "coming soon" panel for sections not yet built. */
export function Placeholder({ title, phase }: { title: string; phase: number }) {
  return (
    <AdminCard title={title}>
      <p className="text-sm text-[var(--color-text-dim)]">This section is coming in Phase {phase}.</p>
    </AdminCard>
  );
}

export default Placeholder;
