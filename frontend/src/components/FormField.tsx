import { useId } from 'react';

export function FormField({ label, children, id }: { label: string; children: React.ReactNode; id?: string }) {
  // FIX: Generate unique ID for label/input association
  const generatedId = useId();
  const inputId = id ?? generatedId;

  return (
    <div className="form-field">
      <label className="form-label" htmlFor={inputId}>{label}</label>
      {children}
    </div>
  );
}
