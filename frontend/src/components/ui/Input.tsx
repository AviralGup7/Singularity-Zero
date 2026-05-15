import { forwardRef } from 'react';
import { cn } from '@/lib/utils';

export interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  label?: string;
  error?: string;
  helperText?: string;
  id: string;
}

export const Input = forwardRef<HTMLInputElement, InputProps>(
  ({ label, error, helperText, id, className, required, ...props }, ref) => {
    const helperId = error ? `${id}-error` : helperText ? `${id}-helper` : undefined;

    return (
      <div className="flex flex-col gap-1">
        {label && (
          <label
            htmlFor={id}
            className="font-mono text-[length:var(--text-sm)] text-[var(--muted)] uppercase tracking-wider"
          >
            {label}
            {required && (
              <span className="text-[var(--bad)] ml-1" aria-hidden="true">
                *
              </span>
            )}
          </label>
        )}
        <input
          ref={ref}
          id={id}
          required={required}
          aria-invalid={!!error}
          aria-describedby={helperId}
          className={cn(
            'bg-[var(--input-bg)] border border-[var(--line)] text-[var(--text)] font-mono px-3 py-1.5 text-[length:var(--text-sm)] transition-all duration-200 focus:outline-none focus:border-[var(--accent)] focus:ring-1 focus:ring-[var(--accent)] placeholder:text-[var(--muted)]/50',
            error && 'border-[var(--bad)] focus:border-[var(--bad)] focus:ring-[var(--bad)]',
            className
          )}
          {...props}
        />
        {error && (
          <p id={`${id}-error`} className="text-[var(--bad)] text-[length:var(--text-xs)] font-mono" role="alert">
            {error}
          </p>
        )}
        {helperText && !error && (
          <p id={`${id}-helper`} className="text-[var(--muted)] text-[length:var(--text-xs)] font-mono">
            {helperText}
          </p>
        )}
      </div>
    );
  }
);

Input.displayName = 'Input';
