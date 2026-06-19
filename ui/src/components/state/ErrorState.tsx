export interface ErrorStateProps {
  message: string;
  onRetry?: () => void;
}

export function ErrorState({ message }: ErrorStateProps) {
  return <div data-component="ErrorState">{message}</div>;
}

export default ErrorState;
