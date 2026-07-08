import { motion } from 'framer-motion';
import { AlertOctagon, RefreshCw, ArrowLeft } from 'lucide-react';
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
    <motion.div
      initial={{ opacity: 0, scale: 0.96 }}
      animate={{ opacity: 1, scale: 1 }}
      transition={{ duration: 0.35, ease: [0.16, 1, 0.3, 1] }}
      className={`rounded-xl border border-[var(--bad)]/30 bg-gradient-to-br from-[var(--bad)]/[0.06] to-transparent p-8 text-center shadow-[var(--glow-bad)] ${className}`}
      role="alert"
      aria-live="assertive"
    >
      <div className="h-14 w-14 rounded-2xl bg-[var(--bad)]/10 border border-[var(--bad)]/20 flex items-center justify-center mx-auto mb-4">
        <AlertOctagon size={24} className="text-[var(--bad)]" aria-hidden="true" />
      </div>
      <h3 className="text-base font-semibold text-[var(--text-primary)] mb-2">{title}</h3>
      <p className="text-sm text-[var(--text-secondary)] mb-4 max-w-md mx-auto leading-relaxed">{message}</p>
      {crashId && (
        <p className="text-[11px] font-mono text-[var(--text-tertiary)] mb-5 px-3 py-1.5 rounded-md bg-[var(--surface)]/50 inline-block border border-[var(--border)]">
          Crash ID: {crashId}
        </p>
      )}
      <div className="flex gap-3 justify-center">
        {onRetry && (
          <button
            className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-[var(--accent)] text-white text-sm font-medium hover:bg-[var(--accent-hover)] transition-all duration-200 shadow-[0_4px_12px_-2px_var(--accent-soft)] hover:shadow-[0_6px_20px_-2px_var(--accent-soft)] hover:-translate-y-0.5"
            onClick={handleRetry}
            aria-label="Try again"
          >
            <RefreshCw size={14} aria-hidden="true" />
            Try Again
          </button>
        )}
        <a
          href="/"
          className="inline-flex items-center gap-2 px-4 py-2 rounded-lg border border-[var(--border)] text-[var(--text-secondary)] text-sm font-medium hover:bg-[var(--surface-hover)] hover:text-[var(--text-primary)] transition-all duration-200 hover:-translate-y-0.5"
          aria-label="Go to dashboard"
        >
          <ArrowLeft size={14} aria-hidden="true" />
          Dashboard
        </a>
      </div>
    </motion.div>
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
