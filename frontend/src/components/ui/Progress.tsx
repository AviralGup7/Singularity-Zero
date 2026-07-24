import { forwardRef } from 'react';
import { cn } from '@/lib/utils';
import * as ProgressPrimitive from '@radix-ui/react-progress';

export interface ProgressProps {
  value?: number;
  max?: number;
  variant?: 'default' | 'running' | 'completed' | 'failed' | 'glow' | 'success' | 'warning' | 'danger';
  size?: 'sm' | 'md' | 'lg';
  showLabel?: boolean;
  className?: string;
}

const variantColor: Record<string, string> = {
  default: 'bg-primary',
  running: 'bg-primary animate-pulse',
  completed: 'bg-emerald-500',
  failed: 'bg-rose-500',
  glow: 'bg-accent shadow-glow-accent-md',
  success: 'bg-ok',
  warning: 'bg-warn',
  danger: 'bg-bad',
};

const sizeHeight: Record<string, string> = {
  sm: 'h-1',
  md: 'h-2',
  lg: 'h-3',
};

const Progress = forwardRef<React.ElementRef<typeof ProgressPrimitive.Root>, ProgressProps>(
  ({ className, value = 0, max = 100, variant = 'default', size = 'md', showLabel = false, ...props }, ref) => {
    const percent = Math.min(100, Math.max(0, (value / max) * 100));
    return (
      <div className={cn('w-full', className)}>
        <ProgressPrimitive.Root
          ref={ref}
          className={cn('relative w-full overflow-hidden rounded-full bg-muted', sizeHeight[size])}
          value={percent}
          {...props}
        >
          <ProgressPrimitive.Indicator
            className={cn('h-full w-full flex-1 transition-all duration-300 rounded-full', variantColor[variant])}
            style={{ transform: `translateX(-${100 - percent}%)` }}
          />
        </ProgressPrimitive.Root>
        {showLabel && (
          <span className="mt-1 block text-right text-xs text-muted-foreground">
            {Math.round(percent)}%
          </span>
        )}
      </div>
    );
  },
);
Progress.displayName = ProgressPrimitive.Root.displayName;

export { Progress };
