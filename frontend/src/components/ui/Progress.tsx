import * as React from 'react';
import * as ProgressPrimitive from '@radix-ui/react-progress';
import { cn } from '../../lib/utils';

export interface ProgressProps {
  value?: number;
  max?: number;
  variant?: 'default' | 'running' | 'completed' | 'failed';
  size?: 'sm' | 'md' | 'lg';
  showLabel?: boolean;
  className?: string;
}

const Progress = React.forwardRef<
  React.ElementRef<typeof ProgressPrimitive.Root>,
  ProgressProps
>(({ className, value = 0, max = 100, variant = 'default', size = 'md', showLabel = false, ...props }, ref) => {
  const percent = Math.min(100, Math.max(0, (value / max) * 100));
  const height = size === 'sm' ? 'h-1' : size === 'lg' ? 'h-3' : 'h-2';

  const colors = {
    default: 'bg-[var(--accent)]',
    running: 'bg-[var(--accent)] animate-pulse',
    completed: 'bg-[var(--ok)]',
    failed: 'bg-[var(--bad)]',
  } as const;

  return (
    <div className={cn('w-full', className)}>
      <ProgressPrimitive.Root
        ref={ref}
        className={cn('relative w-full overflow-hidden rounded-full bg-[var(--panel)]', height)}
        value={percent}
        {...props}
      >
        <ProgressPrimitive.Indicator
          className={cn('h-full w-full flex-1 transition-all duration-300', colors[variant])}
          style={{ transform: `translateX(-${100 - percent}%)` }}
        />
      </ProgressPrimitive.Root>
      {showLabel && (
        <span className="mt-1 block text-right text-xs text-[var(--muted)]">
          {Math.round(percent)}%
        </span>
      )}
    </div>
  );
});
Progress.displayName = ProgressPrimitive.Root.displayName;

export { Progress };
