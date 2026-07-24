import { forwardRef } from 'react';
import { cn } from '@/lib/utils';
import { Input as ShadcnInput } from '@/components/ui-shadcn/input';

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
            className="font-mono text-[length:var(--text-sm)] text-muted uppercase tracking-wider"
          >
            {label}
            {required && (
              <span className="text-bad ml-1" aria-hidden="true">
                *
              </span>
            )}
          </label>
        )}
        <ShadcnInput
          ref={ref}
          id={id}
          required={required}
          aria-invalid={!!error}
          aria-describedby={helperId}
          className={cn(
            'bg border-line text-text font-mono focus:border-accent focus:ring-accent placeholder:text-muted/50',
            error && 'border-bad focus:border-bad focus:ring-bad',
            className
          )}
          {...props}
        />
        {error && (
          <p id={`${id}-error`} className="text-bad text-[length:var(--text-xs)] font-mono" role="alert">
            {error}
          </p>
        )}
        {helperText && !error && (
          <p id={`${id}-helper`} className="text-muted text-[length:var(--text-xs)] font-mono">
            {helperText}
          </p>
        )}
      </div>
    );
  }
);

Input.displayName = 'Input';
