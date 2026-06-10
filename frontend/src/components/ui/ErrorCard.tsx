import { errorTracker } from '@/utils/errorTracker';

interface ErrorCardProps {
  title?: string;
  message: string;
  crashId?: string;
  onRetry?: () => void;
  className?: string;
}

export function ErrorCard({
  title = 'Something went wrong',
  message,
  crashId,
  onRetry,
  className = '',
}: ErrorCardProps) {
  const handleRetry = () => {
    errorTracker.track(new Error('User retry from ErrorCard'), {
      component: 'ErrorCard',
      action: 'retry',
    });
    onRetry?.();
  };

  return (
    <div
      className={`card error-card p-6 text-center ${className}`}
      role="alert"
      aria-live="assertive"
    >
      <div className="text-3xl mb-3" aria-hidden="true">⚠️</div>
      <h3 className="text-lg font-bold text-[var(--text-primary)] mb-2">{title}</h3>
      <p className="text-sm text-[var(--text-secondary)] mb-3 max-w-md mx-auto">{message}</p>
      {crashId && (
        <p className="text-[11px] font-mono text-[var(--text-tertiary)] mb-4">
          Crash ID: {crashId}
        </p>
      )}
      <div className="flex gap-2 justify-center">
        {onRetry && (
          <button className="btn btn-primary text-sm" onClick={handleRetry} aria-label="Try again">
            Try Again
          </button>
        )}
        <a href="/" className="btn btn-secondary text-sm" aria-label="Go to dashboard">
          Go to Dashboard
        </a>
      </div>
    </div>
  );
}

interface InlineErrorProps {
  message: string;
  onRetry?: () => void;
  className?: string;
}

export function InlineError({ message, onRetry, className = '' }: InlineErrorProps) {
  return (
    <div
      className={`flex items-center gap-3 p-3 rounded-lg border border-[var(--line)] bg-[var(--panel)] ${className}`}
      role="alert"
    >
      <span className="text-sm text-[var(--text-secondary)] flex-1">{message}</span>
      {onRetry && (
        <button
          className="btn btn-secondary btn-sm text-xs"
          onClick={onRetry}
          aria-label="Retry"
        >
          Retry
        </button>
      )}
    </div>
  );
}
