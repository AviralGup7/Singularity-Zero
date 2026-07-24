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
      <label className="form-label text-sm font-medium text-text-secondary" htmlFor={inputId}>
        {label}
        {required && <span className="text-bad ml-1" aria-hidden="true">*</span>}
      </label>
      {children}
      {hint && !error && (
        <span id={hintId} className="text-[10px] text-text-tertiary">{hint}</span>
      )}
      {error && (
        <span id={errorId} role="alert" className="text-[10px] text-bad font-medium">{error}</span>
      )}
    </div>
  );
}
