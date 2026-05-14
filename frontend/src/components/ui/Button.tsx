import { forwardRef } from 'react';
import { cn } from '@/lib/utils';
import type { VisualVariantProps } from '@/types/ui';

export type ButtonVariant = 'primary' | 'secondary' | 'danger' | 'ghost';
export type ButtonSize = 'sm' | 'md' | 'lg';

export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement>, VisualVariantProps {
  variant?: ButtonVariant;
  size?: ButtonSize;
  loading?: boolean;
  children: React.ReactNode;
}

const variantClasses: Record<ButtonVariant, string> = {
  primary:
    'bg-[var(--accent)] text-[var(--bg)] border border-[var(--accent)] hover:bg-[var(--accent-hover)] hover:border-[var(--accent-hover)] focus-visible:ring-2 focus-visible:ring-[var(--accent)] focus-visible:ring-offset-2 focus-visible:ring-offset-[var(--bg)]',
  secondary:
    'bg-transparent text-[var(--text)] border border-[var(--line)] hover:bg-[var(--hover-bg)] hover:border-[var(--accent)] focus-visible:ring-2 focus-visible:ring-[var(--accent)] focus-visible:ring-offset-2 focus-visible:ring-offset-[var(--bg)]',
  danger:
    'bg-[var(--bad)] text-white border border-[var(--bad)] hover:opacity-90 focus-visible:ring-2 focus-visible:ring-[var(--bad)] focus-visible:ring-offset-2 focus-visible:ring-offset-[var(--bg)]',
  ghost:
    'bg-transparent text-[var(--text)] border border-transparent hover:bg-[var(--hover-bg)] hover:text-[var(--accent)] focus-visible:ring-2 focus-visible:ring-[var(--accent)] focus-visible:ring-offset-2 focus-visible:ring-offset-[var(--bg)]',
};

const sizeClasses: Record<ButtonSize, string> = {
  sm: 'px-2 py-1 text-[length:var(--text-xs)]',
  md: 'px-3 py-1.5 text-[length:var(--text-sm)]',
  lg: 'px-4 py-2 text-[length:var(--text-base)]',
};

const toneClasses: Record<NonNullable<VisualVariantProps['tone']>, string> = {
  neutral: '',
  accent: 'ring-1 ring-[var(--accent)]/40',
  success: 'ring-1 ring-[var(--ok)]/40',
  warning: 'ring-1 ring-[var(--warn)]/40',
  danger: 'ring-1 ring-[var(--bad)]/40',
  info: 'ring-1 ring-[var(--line)]',
};

const intensityClasses: Record<NonNullable<VisualVariantProps['intensity']>, string> = {
  subtle: 'shadow-none',
  balanced: 'shadow-[0_6px_16px_rgba(0,0,0,0.25)]',
  bold: 'shadow-[0_10px_24px_rgba(0,0,0,0.45)]',
};

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  (
    {
      variant = 'primary',
      size = 'md',
      loading = false,
      tone = 'neutral',
      intensity = 'balanced',
      status = 'idle',
      interactive = true,
      className,
      children,
      disabled,
      type = 'button',
      ...props
    },
    ref
  ) => {
    return (
      <button
        ref={ref}
        type={type}
        disabled={disabled || loading}
        className={cn(
          'inline-flex items-center justify-center gap-2 font-mono font-bold uppercase tracking-wider cursor-pointer transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed',
          toneClasses[tone],
          intensityClasses[intensity],
          !interactive && 'pointer-events-none',
          status === 'running' && 'animate-pulse',
          status === 'failed' && 'ring-2 ring-[var(--bad)]/60',
          status === 'completed' && 'ring-2 ring-[var(--ok)]/60',
          variantClasses[variant],
          sizeClasses[size],
          className
        )}
        aria-busy={loading}
        {...props}
      >
        {loading && (
          <span
            className="inline-block h-3 w-3 animate-spin rounded-full border-2 border-current border-t-transparent"
            aria-hidden="true"
          />
        )}
        {children}
      </button>
    );
  }
);

Button.displayName = 'Button';
