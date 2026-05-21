import { useId } from 'react';

interface FormFieldProps {
  label: string;
  children: React.ReactNode;
  id?: string;
  error?: string;
  hint?: string;
  required?: boolean;
}

export function FormField({ label, children, id, error, hint, required }: FormFieldProps) {
  const generatedId = useId();
  const inputId = id ?? generatedId;
  const errorId = error ? `${inputId}-error` : undefined;
  const hintId = hint ? `${inputId}-hint` : undefined;

  return (
    <div className="form-field" style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-1)' }}>
      <label className="form-label" htmlFor={inputId} style={{ fontSize: 'var(--text-small)', fontWeight: 500, color: 'var(--text-secondary)' }}>
        {label}
        {required && <span style={{ color: 'var(--bad)', marginLeft: '4px' }} aria-hidden="true">*</span>}
      </label>
      {children}
      {hint && !error && (
        <span id={hintId} style={{ fontSize: 'var(--text-micro)', color: 'var(--text-tertiary)' }}>{hint}</span>
      )}
      {error && (
        <span id={errorId} role="alert" style={{ fontSize: 'var(--text-micro)', color: 'var(--bad)', fontWeight: 500 }}>{error}</span>
      )}
    </div>
  );
}
