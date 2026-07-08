import { forwardRef, type ElementType, type ComponentPropsWithoutRef } from 'react';
import { motion } from 'framer-motion';
import { cn } from '@/lib/utils';

/* ── Variant types ─────────────────────────────────────────────── */

export type GlassCardVariant = 'default' | 'glow' | 'error' | 'success' | 'warning' | 'accent-top';

export interface GlassCardProps {
  /** Visual variant — controls the hover glow color */
  variant?: GlassCardVariant;
  /** Enable lift + glow hover micro-interaction */
  hoverable?: boolean;
  /** Apply default inner padding (p-5) */
  padding?: boolean;
  /** Polymorphic element type for the wrapper (rendered via motion) */
  as?: ElementType;
  /** Stagger delay for the entrance animation (seconds) */
  delay?: number;
  /** Extra classes merged via cn() */
  className?: string;
  /** Card content */
  children?: React.ReactNode;
}

/* ── Variant-specific hover glow shadows ───────────────────────── */

const hoverGlowMap: Record<GlassCardVariant, string> = {
  default: 'hover:shadow-[var(--glass-shadow)]',
  glow:    'hover:shadow-[var(--glow-accent)]',
  error:   'hover:shadow-[var(--glow-bad)]',
  success: 'hover:shadow-[var(--glow-ok)]',
  warning: 'hover:shadow-[var(--glow-warn)]',
  'accent-top': 'hover:shadow-[var(--glow-accent)]',
};

/* ── Variant-specific hover border tints ───────────────────────── */

const hoverBorderMap: Record<GlassCardVariant, string> = {
  default: 'hover:border-[rgba(255,255,255,0.10)]',
  glow:    'hover:border-[var(--accent)]',
  error:   'hover:border-[var(--bad)]',
  success: 'hover:border-[var(--ok)]',
  warning: 'hover:border-[var(--warn)]',
  'accent-top': 'hover:border-[var(--accent)]',
};

/* ── Component ─────────────────────────────────────────────────── */

export const GlassCard = forwardRef<HTMLDivElement, GlassCardProps & Omit<ComponentPropsWithoutRef<typeof motion.div>, keyof GlassCardProps>>(
  (
    {
      variant = 'default',
      hoverable = true,
      padding = true,
      as: _as = 'div',
      delay = 0,
      className,
      children,
      ...motionProps
    },
    ref,
  ) => {
    const MotionComponent = motion.create(_as) as typeof motion.div;

    return (
      <MotionComponent
        ref={ref}
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{
          duration: 0.5,
          delay,
          ease: [0.16, 1, 0.3, 1],
        }}
        className={cn(
          'relative rounded-xl border border-[var(--glass-border)] bg-[var(--glass-bg)]',
          'backdrop-blur-[var(--glass-blur)]',
          'shadow-[var(--glass-shadow)]',
          'transition-all duration-350 ease-out',
          padding && 'p-5',
          hoverable && [
            'hover:-translate-y-1',
            'hover:border-[rgba(255,255,255,0.10)]',
            'hover:shadow-[var(--glass-shadow),0_0_24px_-4px_color-mix(in_srgb,var(--accent),15%)]',
            hoverGlowMap[variant as GlassCardVariant],
            hoverBorderMap[variant as GlassCardVariant],
          ],
          variant === 'accent-top' && 'card--accent-top',
          className,
        )}
        {...motionProps}
      >
        {children}
      </MotionComponent>
    );
  },
);

GlassCard.displayName = 'GlassCard';
