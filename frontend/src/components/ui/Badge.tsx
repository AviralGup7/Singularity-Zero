import { cn } from '@/lib/utils';

export type BadgeVariant = 'critical' | 'high' | 'medium' | 'low' | 'info' | 'status';
export type StatusVariant = 'running' | 'completed' | 'failed' | 'stopped' | 'queued';

export interface BadgeProps {
  variant?: BadgeVariant;
  status?: StatusVariant;
  children: React.ReactNode;
  className?: string;
}

export function Badge({ variant = 'info', status, children, className }: BadgeProps) {
  const ariaLabel = variant === 'status' && status
    ? `Status: ${status}`
    : `${variant} severity`;

  return (
    <span
      className={cn(
        'inline-flex items-center gap-1 px-2 py-0.5 text-xs font-mono font-bold uppercase tracking-wider border rounded-sm',
        variant === 'status' && status && {
          running: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/40',
          completed: 'bg-primary/20 text-primary border-primary/40',
          failed: 'bg-rose-500/20 text-rose-400 border-rose-500/40',
          stopped: 'bg-amber-500/20 text-amber-400 border-amber-500/40',
          queued: 'bg-muted/20 text-muted-foreground border-muted/40',
        }[status],
        variant !== 'status' && {
          critical: 'bg-rose-500/20 text-rose-500 border-rose-500/40',
          high: 'bg-orange-500/20 text-orange-500 border-orange-500/40',
          medium: 'bg-amber-500/20 text-amber-500 border-amber-500/40',
          low: 'bg-blue-500/20 text-blue-500 border-blue-500/40',
          info: 'bg-muted/20 text-muted-foreground border-muted/40',
        }[variant],
        className
      )}
      role="status"
      aria-label={ariaLabel}
    >
      {children}
    </span>
  );
}
