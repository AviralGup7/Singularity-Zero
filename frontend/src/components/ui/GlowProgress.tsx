import { forwardRef } from 'react';
import { motion } from 'framer-motion';
import { cn } from '@/lib/utils';

/* ── Types ─────────────────────────────────────────────────────── */

export type GlowProgressVariant = 'default' | 'success' | 'warning' | 'danger' | 'cyber';
export type GlowProgressSize = 'sm' | 'md' | 'lg';

export interface GlowProgressProps {
  /** Progress value 0-100 */
  value: number;
  /** Color variant */
  variant?: GlowProgressVariant;
  /** Track height */
  size?: GlowProgressSize;
  /** Enable spring animation & shimmer overlay */
  animated?: boolean;
  /** Render percentage text to the right */
  showLabel?: boolean;
  /** Extra classes */
  className?: string;
}

/* ── Gradient fills per variant ────────────────────────────────── */

const gradientMap: Record<GlowProgressVariant, string> = {
  default: 'bg-gradient-to-r from-[var(--accent)] to-[var(--accent-2)]',
  success: 'bg-gradient-to-r from-emerald-400 to-teal-400',
  warning: 'bg-gradient-to-r from-amber-400 to-orange-400',
  danger:  'bg-gradient-to-r from-red-400 to-rose-400',
  cyber:   'bg-gradient-to-r from-cyan-400 via-teal-400 to-emerald-400',
};

/* ── Neon glow shadows per variant ─────────────────────────────── */

const glowShadowMap: Record<GlowProgressVariant, string> = {
  default: '0 0 10px hsla(217,91%,60%,0.45), 0 0 24px hsla(271,91%,65%,0.20)',
  success: '0 0 10px hsla(160,84%,45%,0.50), 0 0 24px hsla(160,84%,45%,0.18)',
  warning: '0 0 10px hsla(38,92%,56%,0.50), 0 0 24px hsla(38,92%,56%,0.18)',
  danger:  '0 0 10px hsla(0,72%,51%,0.50), 0 0 24px hsla(0,72%,51%,0.18)',
  cyber:   '0 0 10px hsla(187,92%,53%,0.50), 0 0 24px hsla(160,84%,50%,0.18)',
};

/* ── Size map ──────────────────────────────────────────────────── */

const sizeMap: Record<GlowProgressSize, string> = {
  sm: 'h-1',
  md: 'h-2',
  lg: 'h-3',
};

/* ── Component ─────────────────────────────────────────────────── */

export const GlowProgress = forwardRef<HTMLDivElement, GlowProgressProps>(
  (
    {
      value,
      variant = 'default',
      size = 'md',
      animated = true,
      showLabel = false,
      className,
    },
    ref,
  ) => {
    const clamped = Math.min(100, Math.max(0, value));

    return (
      <div ref={ref} className={cn('flex items-center gap-3', className)}>
        {/* Track */}
        <div
          className={cn(
            'relative w-full overflow-hidden rounded-full bg-[var(--surface-2)]',
            sizeMap[size],
          )}
        >
          {/* Fill */}
          <motion.div
            className={cn(
              'absolute inset-y-0 left-0 rounded-full',
              gradientMap[variant],
            )}
            style={{
              boxShadow: glowShadowMap[variant],
            }}
            /* ── Animated width via spring physics ──────────── */
            initial={{ width: '0%' }}
            animate={{ width: `${clamped}%` }}
            transition={
              animated
                ? { type: 'spring', stiffness: 60, damping: 18, mass: 1 }
                : { duration: 0 }
            }
          >
            {/* Shimmer overlay */}
            {animated && clamped > 0 && (
              <span
                aria-hidden
                className="pointer-events-none absolute inset-0 overflow-hidden rounded-full"
              >
                <span
                  className={cn(
                    'absolute inset-y-0 -left-full w-full',
                    'bg-gradient-to-r from-transparent via-white/20 to-transparent',
                    'animate-[shimmer_2.4s_ease-in-out_infinite]',
                  )}
                />
              </span>
            )}
          </motion.div>
        </div>

        {/* Label */}
        {showLabel && (
          <span className="shrink-0 text-xs font-medium tabular-nums text-[var(--text-secondary)]">
            {Math.round(clamped)}%
          </span>
        )}
      </div>
    );
  },
);

GlowProgress.displayName = 'GlowProgress';
