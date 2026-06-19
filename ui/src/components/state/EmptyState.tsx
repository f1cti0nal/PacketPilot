export interface EmptyStateProps {
  title: string;
  hint?: string;
}

export function EmptyState({ title }: EmptyStateProps) {
  return <div data-component="EmptyState">{title}</div>;
}

export default EmptyState;
