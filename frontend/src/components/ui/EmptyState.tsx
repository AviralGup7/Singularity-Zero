import { motion } from 'framer-motion';
import { cn } from '@/lib/utils';
import { Link } from 'react-router-dom';
import { Inbox, AlertTriangle, AlertOctagon, CheckCircle2 } from 'lucide-react';
import type { ReactNode } from 'react';

type EmptyStateVariant = 'default' | 'error' | 'warning' | 'success';

const variantStyles: Record<EmptyStateVariant, { container: string; iconBg: string; iconColor: string }> = {
  default: { container: '', iconBg: 'bg-[var(--accent-soft)] border-[var(--accent)]/10', iconColor: 'text-[var(--accent)]' },
  error: { container: 'border-[var(--bad)]/20', iconBg: 'bg-[var(--bad)]/10 border-[var(--bad)]/20', iconColor: 'text-[var(--bad)]' },
  warning: { container: 'border-[var(--warn)]/20', iconBg: 'bg-[var(--warn)]/10 border-[var(--warn)]/20', iconColor: 'text-[var(--warn)]' },
  success: { container: 'border-[var(--ok)]/20', iconBg: 'bg-[var(--ok)]/10 border-[var(--ok)]/20', iconColor: 'text-[var(--ok)]' },
};

const variantIcons: Record<EmptyStateVariant, ReactNode> = {
  default: <Inbox size={24} strokeWidth={1.5} />,
  error: <AlertOctagon size={24} strokeWidth={1.5} />,
  warning: <AlertTriangle size={24} strokeWidth={1.5} />,
  success: <CheckCircle2 size={24} strokeWidth={1.5} />,
};

export interface EmptyStateProps {
  title: string;
  description: string;
  ctaLabel?: string;
  ctaHref?: string;
  onCtaClick?: () => void;
  icon?: React.ReactNode;
  /** Visual variant: default, error, warning, success. */
  variant?: EmptyStateVariant;
  /** Render a custom action slot instead of the default CTA button. */
  action?: ReactNode;
  className?: string;
}

export function EmptyState({
  title,
  description,
  ctaLabel,
  ctaHref,
  onCtaClick,
  icon,
  variant = 'default',
  action,
  className,
}: EmptyStateProps) {
  const styles = variantStyles[variant];
  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4, ease: [0.16, 1, 0.3, 1] }}
      className={cn(
        'flex flex-col items-center justify-center gap-4 p-10 text-center',
        'rounded-xl border border-[var(--glass-border)] bg-[var(--glass-bg)]',
        'backdrop-blur-[var(--glass-blur)] shadow-[var(--glass-shadow)]',
        styles.container,
        className
      )}
      role="status"
    >
      <div className={cn('flex h-14 w-14 shrink-0 items-center justify-center rounded-2xl border', styles.iconBg, styles.iconColor)} aria-hidden="true">
        {icon ?? variantIcons[variant]}
      </div>
      <div className="space-y-1.5">
        <h3 className="text-base font-semibold text-[var(--text-primary)]">{title}</h3>
        <p className="text-sm text-[var(--text-secondary)] max-w-xs mx-auto leading-relaxed">{description}</p>
      </div>
      {action ?? ((ctaLabel && (ctaHref || onCtaClick)) && (
        <div className="pt-2">
          {ctaHref ? (
            <Link
              to={ctaHref}
              className="inline-flex items-center gap-2 px-5 py-2.5 rounded-lg bg-[var(--accent)] text-white text-sm font-medium hover:bg-[var(--accent-hover)] transition-all duration-200 shadow-[0_4px_12px_-2px_var(--accent-soft)] hover:shadow-[0_6px_20px_-2px_var(--accent-soft)] hover:-translate-y-0.5"
            >
              {ctaLabel}
            </Link>
          ) : (
            <button
              className="inline-flex items-center gap-2 px-5 py-2.5 rounded-lg bg-[var(--accent)] text-white text-sm font-medium hover:bg-[var(--accent-hover)] transition-all duration-200 shadow-[0_4px_12px_-2px_var(--accent-soft)] hover:shadow-[0_6px_20px_-2px_var(--accent-soft)] hover:-translate-y-0.5"
              onClick={onCtaClick}
            >
              {ctaLabel}
            </button>
          )}
        </div>
      ))}
    </motion.div>
  );
}
