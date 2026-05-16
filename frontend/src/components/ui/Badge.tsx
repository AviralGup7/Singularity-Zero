import { cn } from '@/lib/utils';

export type BadgeVariant = 'critical' | 'high' | 'medium' | 'low' | 'info' | 'status';
export type StatusVariant = 'running' | 'completed' | 'failed' | 'stopped' | 'queued';

export interface BadgeProps {
  variant?: BadgeVariant;
  status?: StatusVariant;
  children: React.ReactNode;
  className?: string;
}

const statusClasses: Record<StatusVariant, string> = {
   
  running: 'bg-[var(--ok)]/20 text-[var(--ok)] border-[var(--ok)]/40',
   
  completed: 'bg-[var(--accent)]/20 text-[var(--accent)] border-[var(--accent)]/40',
   
  failed: 'bg-[var(--bad)]/20 text-[var(--bad)] border-[var(--bad)]/40',
   
  stopped: 'bg-[var(--warn)]/20 text-[var(--warn)] border-[var(--warn)]/40',
   
  queued: 'bg-[var(--muted)]/20 text-[var(--muted)] border-[var(--muted)]/40',
};

const severityBadgeClasses: Record<Exclude<BadgeVariant, 'status'>, string> = {
   
  critical: 'bg-[var(--severity-critical)]/20 text-[var(--severity-critical)] border-[var(--severity-critical)]/40',
   
  high: 'bg-[var(--severity-high)]/20 text-[var(--severity-high)] border-[var(--severity-high)]/40',
   
  medium: 'bg-[var(--severity-medium)]/20 text-[var(--severity-medium)] border-[var(--severity-medium)]/40',
   
  low: 'bg-[var(--severity-low)]/20 text-[var(--severity-low)] border-[var(--severity-low)]/40',
   
  info: 'bg-[var(--muted)]/20 text-[var(--muted)] border-[var(--muted)]/40',
};

export function Badge({ variant = 'info', status, children, className }: BadgeProps) {
  const isStatus = variant === 'status' && status;
  const classes = isStatus
    ? statusClasses[status]
   
    : severityBadgeClasses[variant as Exclude<BadgeVariant, 'status'>];

  const ariaLabel = isStatus
    ? `Status: ${status}`
    : `${variant} severity`;

  return (
    <span
      className={cn(
   
        'inline-flex items-center gap-1 px-2 py-0.5 text-[length:var(--text-xs)] font-mono font-bold uppercase tracking-wider border rounded-sm',
        classes,
        className
      )}
      role="status"
      aria-label={ariaLabel}
    >
      {children}
    </span>
  );
}
