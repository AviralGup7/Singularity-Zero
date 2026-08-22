import { forwardRef } from 'react';
import { cn } from '@/lib/utils';
import { ProgressBar } from '@/components/common/ProgressBar';
import { clampPercent } from '@/utils/findingTime';

export type GlowProgressVariant = 'default' | 'success' | 'warning' | 'danger' | 'cyber';
export type GlowProgressSize = 'sm' | 'md' | 'lg';

export interface GlowProgressProps {
  value: number;
  variant?: GlowProgressVariant;
  size?: GlowProgressSize;
  animated?: boolean;
  showLabel?: boolean;
  className?: string;
}

const variantToProgress: Record<GlowProgressVariant, 'default' | 'glow' | 'success' | 'warning' | 'danger'> = {
  default: 'glow',
  success: 'success',
  warning: 'warning',
  danger: 'danger',
  cyber: 'glow',
};

export const GlowProgress = forwardRef<HTMLDivElement, GlowProgressProps>(
  ({ value, variant = 'default', size = 'md', showLabel = false, className }, ref) => {
    return (
      <div ref={ref} className={cn('flex items-center gap-3', className)}>
        <ProgressBar
          value={clampPercent(value)}
          variant={variantToProgress[variant]}
          size={size}
          showPercentage={showLabel}
          className="flex-1"
        />
      </div>
    );
  },
);

GlowProgress.displayName = 'GlowProgress';
