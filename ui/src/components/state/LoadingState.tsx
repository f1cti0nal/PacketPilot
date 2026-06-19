export interface LoadingStateProps {
  label?: string; // default "Loading…"
}

export function LoadingState({ label = "Loading…" }: LoadingStateProps) {
  return <div data-component="LoadingState">{label}</div>;
}

export default LoadingState;
