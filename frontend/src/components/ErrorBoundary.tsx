import { Component, type ErrorInfo, type ReactNode } from 'react';

interface Props {
  children: ReactNode;
  name?: string;
  fallback?: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
  errorInfo: ErrorInfo | null;
}

export class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = { hasError: false, error: null, errorInfo: null };
  }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error, errorInfo: null };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    // Security: suppress stack traces in production, log only in dev
    if (import.meta.env.DEV) {
      console.error('ErrorBoundary caught:', error, '\nComponent stack:', errorInfo.componentStack);
    }
    this.setState({ errorInfo });
  }

  handleReset = () => {
    this.setState({ hasError: false, error: null, errorInfo: null });
  };

  handleGoHome = () => {
    window.location.href = '/';
  };

  render() {
    if (this.state.hasError) {
      if (this.props.fallback) {
        return this.props.fallback;
      }

      return (
        <div className="card error-boundary" role="alert" aria-live="assertive">
          <div className="error-boundary-icon">
            <span aria-hidden="true">⚠️</span>
          </div>
          <h3 className="error-title">Something went wrong</h3>
          <p className="error-message">
            {this.state.error?.message || 'An unexpected error occurred.'}
          </p>
          {/* Security: suppress technical details and stack traces in production */}
          {import.meta.env.DEV && this.state.errorInfo && (
            <details className="error-details">
              <summary>Technical details</summary>
              <pre className="error-stack">{this.state.errorInfo.componentStack}</pre>
            </details>
          )}
          <div className="error-boundary-actions">
            <button className="btn btn-primary" onClick={this.handleReset} aria-label="Try again">
              Try Again
            </button>
            <a href="/" className="btn btn-secondary" onClick={(e) => { e.preventDefault(); this.handleReset(); window.history.pushState({}, '', '/'); window.dispatchEvent(new PopStateEvent('popstate')); }} aria-label="Go to dashboard">
              Go Home
            </a>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
