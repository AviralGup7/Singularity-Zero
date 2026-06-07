import { Component, type ErrorInfo, type ReactNode } from 'react';
import { errorTracker } from '@/utils/errorTracker';

interface Props {
  children: ReactNode;
  name?: string;
  fallback?: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
  errorInfo: ErrorInfo | null;
  retryCount: number;
  crashId: string;
}

export class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = { hasError: false, error: null, errorInfo: null, retryCount: 0, crashId: '' };
  }

  static getDerivedStateFromError(error: Error): Partial<State> {
    const crashId = `ERR-${Date.now().toString(36).toUpperCase()}`;
    return { hasError: true, error, errorInfo: null, crashId };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    // Security: suppress stack traces in production, log only in dev
    if (import.meta.env.DEV) {
      errorTracker.track(error, { component: this.props.name, metadata: { componentStack: errorInfo.componentStack } });
      console.error('ErrorBoundary caught:', error, '\nComponent stack:', errorInfo.componentStack);
    }
    this.setState({ errorInfo });
  }

  handleReset = () => {
    this.setState(prev => ({ hasError: false, error: null, errorInfo: null, retryCount: prev.retryCount + 1, crashId: '' }));
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
          <p style={{ fontSize: '11px', color: 'var(--text-tertiary)', fontFamily: 'var(--font-mono)', marginTop: '8px' }}>
            Crash ID: {this.state.crashId}{this.state.retryCount > 0 ? ` · Retry #${this.state.retryCount}` : ''}
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
