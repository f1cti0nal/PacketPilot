import { Component, type ErrorInfo, type ReactNode } from "react";
import { ErrorState } from "./ErrorState";

interface Props {
  children: ReactNode;
  /** When this value changes, a previously-caught error is cleared (e.g. the active
   *  capture id) so loading a new capture recovers from a prior render crash. */
  resetKey?: unknown;
  /** Optional override for the message shown when a child throws. */
  fallbackMessage?: string;
}

interface State {
  error: Error | null;
}

/**
 * Catches render-time throws in its subtree and shows ErrorState instead of letting
 * the exception unwind to the React root and blank the whole app. The dashboard fans
 * runtime engine/cache JSON out to ~20 widgets, so any unexpected field shape or
 * version-skew kind would otherwise white-screen the page.
 */
export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidUpdate(prev: Props) {
    if (prev.resetKey !== this.props.resetKey && this.state.error) {
      this.setState({ error: null });
    }
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    // Surface for diagnostics; the UI already degrades to ErrorState.
    console.error("UI render error:", error, info.componentStack);
  }

  render() {
    if (this.state.error) {
      return (
        <ErrorState
          message={
            this.props.fallbackMessage ??
            `Something went wrong rendering this view: ${this.state.error.message}`
          }
          onRetry={() => this.setState({ error: null })}
        />
      );
    }
    return this.props.children;
  }
}

export default ErrorBoundary;
