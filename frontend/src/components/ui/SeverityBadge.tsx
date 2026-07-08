import { AlertOctagon, AlertTriangle, ChevronUp, Info, Minus } from 'lucide-react';
import { cn } from '@/lib/utils';
import { StatusBadge } from '@/components/common/StatusBadge';

export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface SeverityBadgeProps {
  severity: SeverityLevel;
  count?: number;
  className?: string;
  showIcon?: boolean;
}

const severityColors: Record<SeverityLevel, 'critical' | 'high' | 'medium' | 'low' | 'info'> = {
  critical: 'critical',
  high: 'high',
  medium: 'medium',
  low: 'low',
  info: 'info',
};

function SeverityIcon({ severity }: { severity: SeverityLevel }) {
  const size = 12;
  const strokeWidth = 2.5;
  switch (severity) {
    case 'critical':
      return <AlertOctagon aria-hidden="true" size={size} strokeWidth={strokeWidth} />;
    case 'high':
      return <ChevronUp aria-hidden="true" size={size} strokeWidth={strokeWidth} />;
    case 'medium':
      return <AlertTriangle aria-hidden="true" size={size} strokeWidth={strokeWidth} />;
    case 'low':
      return <Minus aria-hidden="true" size={size} strokeWidth={strokeWidth} />;
    case 'info':
    default:
      return <Info aria-hidden="true" size={size} strokeWidth={strokeWidth} />;
  }
}

export function SeverityBadge({ severity, count, className, showIcon = true }: SeverityBadgeProps) {
  if (count !== undefined && count === 0) return null;

  return (
    <StatusBadge
      status={severityColors[severity]}
      showDot={false}
      className={cn('rounded-sm', className)}
    >
      {showIcon && <SeverityIcon severity={severity} />}
      <span>{severity}</span>
      {count !== undefined && <span className="ml-1">{count}</span>}
    </StatusBadge>
  );
}
