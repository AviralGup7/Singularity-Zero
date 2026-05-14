import { cn } from '@/lib/utils';
import { Link } from 'react-router-dom';

export interface EmptyStateProps {
  title: string;
  description: string;
  ctaLabel?: string;
  ctaHref?: string;
  onCtaClick?: () => void;
  icon?: string;
  className?: string;
}

export function EmptyState({
  title,
  description,
  ctaLabel,
  ctaHref,
  onCtaClick,
  icon,
  className,
}: EmptyStateProps) {
  return (
    <div
      className={cn(
        'flex flex-col items-center justify-center gap-3 p-8 text-center border border-dashed border-[var(--line)] bg-[var(--panel)]',
        className
      )}
      role="status"
    >
      {icon && (
        <div className="text-4xl opacity-60" aria-hidden="true">
          {icon}
        </div>
      )}
      <h3 className="font-mono text-[length:var(--text-lg)] font-bold text-[var(--text)]">{title}</h3>
      <p className="text-[var(--muted)] text-[length:var(--text-sm)] max-w-sm">{description}</p>
      {ctaLabel && ctaHref && (
        <Link to={ctaHref} className="px-4 py-2 bg-[var(--accent)] text-[var(--bg)] font-mono text-[length:var(--text-sm)] font-bold uppercase tracking-wider border border-[var(--accent)] hover:bg-[var(--accent-hover)] transition-colors">
          {ctaLabel}
        </Link>
      )}
      {ctaLabel && onCtaClick && (
        <button
          className="px-4 py-2 bg-[var(--accent)] text-[var(--bg)] font-mono text-[length:var(--text-sm)] font-bold uppercase tracking-wider border border-[var(--accent)] hover:bg-[var(--accent-hover)] transition-colors"
          onClick={onCtaClick}
        >
          {ctaLabel}
        </button>
      )}
    </div>
  );
}
