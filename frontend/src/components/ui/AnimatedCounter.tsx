import { useEffect, useRef } from 'react';
import {
  useMotionValue,
  useSpring,
  useTransform,
  useInView,
  motion,
} from 'framer-motion';
import { cn } from '@/lib/utils';

/* ── Format types ──────────────────────────────────────────────── */

export type CounterFormat = 'number' | 'percent' | 'duration' | 'compact';

export interface AnimatedCounterProps {
  /** Target numeric value */
  value: number;
  /** Spring animation duration in seconds */
  duration?: number;
  /** Output formatting mode */
  format?: CounterFormat;
  /** Static prefix rendered before the number */
  prefix?: string;
  /** Static suffix rendered after the number */
  suffix?: string;
  /** Decimal places for 'number' format */
  decimals?: number;
  /** Extra classes */
  className?: string;
}

/* ── Formatting helpers ────────────────────────────────────────── */

function formatCompact(n: number): string {
  const abs = Math.abs(n);
  if (abs >= 1_000_000_000) return `${(n / 1_000_000_000).toFixed(1).replace(/\.0$/, '')}B`;
  if (abs >= 1_000_000) return `${(n / 1_000_000).toFixed(1).replace(/\.0$/, '')}M`;
  if (abs >= 1_000) return `${(n / 1_000).toFixed(1).replace(/\.0$/, '')}K`;
  return String(Math.round(n));
}

function formatDuration(ms: number): string {
  if (ms < 1) return '0ms';
  if (ms < 1000) return `${Math.round(ms)}ms`;
  return `${(ms / 1000).toFixed(1).replace(/\.0$/, '')}s`;
}

function formatValue(raw: number, format: CounterFormat, decimals: number): string {
  switch (format) {
    case 'percent':
      return `${raw.toFixed(decimals)}%`;
    case 'duration':
      return formatDuration(raw);
    case 'compact':
      return formatCompact(raw);
    case 'number':
    default:
      return raw.toFixed(decimals).replace(/\B(?=(\d{3})+(?!\d))/g, ',');
  }
}

/* ── Component ─────────────────────────────────────────────────── */

export function AnimatedCounter({
  value,
  duration = 1.5,
  format = 'number',
  prefix = '',
  suffix = '',
  decimals = 0,
  className,
}: AnimatedCounterProps) {
  const spanRef = useRef<HTMLSpanElement>(null);
  const isInView = useInView(spanRef, { once: true, margin: '0px 0px -40px 0px' });

  // Raw motion value that drives the spring
  const motionVal = useMotionValue(0);

  // Spring-animated version of motionVal
  const springVal = useSpring(motionVal, {
    duration: duration * 1000,
    bounce: 0,
  });

  // Derived formatted string
  const display = useTransform(springVal, (latest: number) =>
    `${prefix}${formatValue(latest, format, decimals)}${suffix}`,
  );

  // Start / re-start animation when value changes AND element is in view
  useEffect(() => {
    if (isInView) {
      motionVal.set(value);
    }
  }, [value, isInView, motionVal]);

  return (
    <motion.span
      ref={spanRef}
      className={cn('tabular-nums', className)}
    >
      {display}
    </motion.span>
  );
}

AnimatedCounter.displayName = 'AnimatedCounter';
