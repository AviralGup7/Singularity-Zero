import { forwardRef } from 'react';
import { motion } from 'framer-motion';
import { cn } from '@/lib/utils';

export interface PageHeaderProps {
  /** Page title text */
  title: string;
  /** Optional subtitle / description */
  subtitle?: React.ReactNode;
  /** Optional icon element (typically a Lucide icon) */
  icon?: React.ReactNode;
  /** Optional actions slot rendered on the right side (buttons, controls, etc.) */
  actions?: React.ReactNode;
  /** Additional class names */
  className?: string;
}

export const PageHeader = forwardRef<HTMLDivElement, PageHeaderProps>(
  ({ title, subtitle, icon, actions, className, ...props }, ref) => {
    return (
      <motion.div
        ref={ref}
        initial={{ opacity: 0, y: -6 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4, ease: 'easeOut' }}
        className={cn(
          'flex items-center justify-between gap-4 pb-4',
          'border-b border-[var(--border-soft)]',
          className
        )}
        {...props}
      >
        {/* ── Left: icon + title / subtitle ── */}
        <div className="flex items-center gap-3 min-w-0">
          {icon && (
            <div
              className={cn(
              'flex h-10 w-10 shrink-0 items-center justify-center rounded-xl',
                'bg-gradient-to-br from-[var(--accent-soft)] to-[var(--accent-muted)] text-[var(--accent)] border border-[var(--accent)]/10'
              )}
            >
              {icon}
            </div>
          )}

          <div className="min-w-0">
            <h1
              className={cn(
                'text-[length:var(--text-page-title)] font-[var(--weight-title)] text-[var(--text-primary)]',
                'truncate leading-tight'
              )}
            >
              {title}
            </h1>

            {subtitle && (
              <div
                className={cn(
                  'text-[length:var(--text-page-subtitle)] text-[var(--text-secondary)]',
                  'mt-0.5 truncate'
                )}
              >
                {subtitle}
              </div>
            )}
          </div>
        </div>

        {/* ── Right: actions slot ── */}
        {actions && (
          <div className="flex shrink-0 items-center gap-2">
            {actions}
          </div>
        )}
      </motion.div>
    );
  }
);

PageHeader.displayName = 'PageHeader';
