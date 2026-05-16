import { cn } from '@/lib/utils';

export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface SeverityBadgeProps {
  severity: SeverityLevel;
  count?: number;
  className?: string;
  showIcon?: boolean;
}

const severityIcons: Record<SeverityLevel, string> = {
  critical: '⛔',
  high: '🔺',
  medium: '⚠️',
  low: 'ℹ️',
  info: 'ℹ️',
};

const severityLabels: Record<SeverityLevel, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Info',
};

const severityClasses: Record<SeverityLevel, string> = {
   
  critical: 'bg-[var(--severity-critical)]/20 text-[var(--severity-critical)] border-[var(--severity-critical)]/40',
   
  high: 'bg-[var(--severity-high)]/20 text-[var(--severity-high)] border-[var(--severity-high)]/40',
   
  medium: 'bg-[var(--severity-medium)]/20 text-[var(--severity-medium)] border-[var(--severity-medium)]/40',
   
  low: 'bg-[var(--severity-low)]/20 text-[var(--severity-low)] border-[var(--severity-low)]/40',
   
  info: 'bg-[var(--muted)]/20 text-[var(--muted)] border-[var(--muted)]/40',
};

export function SeverityBadge({ severity, count, className, showIcon = true }: SeverityBadgeProps) {
  if (count !== undefined && count === 0) return null;

  return (
    <span
      className={cn(
   
        'inline-flex items-center gap-1 px-2 py-0.5 text-[length:var(--text-xs)] font-mono font-bold uppercase tracking-wider border rounded-sm',
  // eslint-disable-next-line security/detect-object-injection
        severityClasses[severity],
        className
      )}
      role="status"
  // eslint-disable-next-line security/detect-object-injection
      aria-label={`${severityLabels[severity]} severity${count !== undefined ? `: ${count} findings` : ''}`}
    >
  // eslint-disable-next-line security/detect-object-injection
      {showIcon && <span aria-hidden="true" className="severity-icon-marker">{severityIcons[severity]}</span>}
      <span className="severity-text-label">{severity}</span>
      {count !== undefined && <span className="ml-1" aria-label={`${count} findings`}>{count}</span>}
    </span>
  );
}
