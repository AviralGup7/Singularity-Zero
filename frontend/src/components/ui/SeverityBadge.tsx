import { AlertOctagon, AlertTriangle, ChevronUp, Info, Minus } from 'lucide-react';
import { cn } from '@/lib/utils';

export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface SeverityBadgeProps {
  severity: SeverityLevel;
  count?: number;
  className?: string;
  showIcon?: boolean;
}

const severityIconClass: Record<SeverityLevel, string> = {
  critical: 'text-[var(--severity-critical)]',
  high: 'text-[var(--severity-high)]',
  medium: 'text-[var(--severity-medium)]',
  low: 'text-[var(--severity-low)]',
  info: 'text-[var(--muted)]',
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

function SeverityIcon({ severity }: { severity: SeverityLevel }) {
  // eslint-disable-next-line security/detect-object-injection
  const className = cn('severity-icon-marker', severityIconClass[severity]);
  const size = 12;
  const strokeWidth = 2.5;
  switch (severity) {
    case 'critical':
      return <AlertOctagon aria-hidden="true" className={className} size={size} strokeWidth={strokeWidth} />;
    case 'high':
      return <ChevronUp aria-hidden="true" className={className} size={size} strokeWidth={strokeWidth} />;
    case 'medium':
      return <AlertTriangle aria-hidden="true" className={className} size={size} strokeWidth={strokeWidth} />;
    case 'low':
      return <Minus aria-hidden="true" className={className} size={size} strokeWidth={strokeWidth} />;
    case 'info':
    default:
      return <Info aria-hidden="true" className={className} size={size} strokeWidth={strokeWidth} />;
  }
}

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
      {showIcon && <SeverityIcon severity={severity} />}
      <span className="severity-text-label">{severity}</span>
      {count !== undefined && <span className="ml-1" aria-label={`${count} findings`}>{count}</span>}
    </span>
  );
}
