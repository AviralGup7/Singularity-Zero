import { cn } from '@/lib/utils';

export interface ProgressBarProps {
  value: number;
  max?: number;
  label?: string;
  showPercentage?: boolean;
  variant?: 'default' | 'glow' | 'success' | 'warning' | 'danger';
  size?: 'sm' | 'md' | 'lg';
  className?: string;
}

export function ProgressBar({
  value,
  max = 100,
  label,
  showPercentage = true,
  variant = 'default',
  size = 'md',
  className,
}: ProgressBarProps) {
  const percentage = Math.min(100, Math.max(0, Math.round((value / max) * 100)));

  const sizeClasses = {
    sm: 'h-1.5',
    md: 'h-2.5',
    lg: 'h-4',
  };

  const variantClasses = {
    default: 'bg-accent',
    glow: 'bg-accent shadow-glow-accent-md',
    success: 'bg-ok',
    warning: 'bg-warn',
    danger: 'bg-bad',
  };

  return (
    <div className={cn("w-full space-y-1.5", className)} role="group" aria-label={label || 'Progress'}>
      {(label || showPercentage) && (
        <div className="flex justify-between text-xs font-medium text-muted-foreground">
          {label && <span id={`progress-label-${label}`}>{label}</span>}
          {showPercentage && <span aria-hidden="true">{percentage}%</span>}
        </div>
      )}
      <div
        className={cn("w-full bg-muted rounded-full overflow-hidden", sizeClasses[size])}
        role="progressbar"
        aria-valuenow={percentage}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-label={label ? `${label}: ${percentage}%` : `${percentage}% complete`}
      >
        <div
          className={cn(
            "h-full transition-all duration-500 ease-out rounded-full",
            variantClasses[variant],
            percentage > 0 && "motion-safe:animate-[shimmer_2s_infinite]"
          )}
          style={{ width: `${percentage}%` }}
        />
      </div>
    </div>
  );
}
