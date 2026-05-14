import React, { useId } from 'react';

export function SettingToggle({ label, checked, onChange, description, id }: { label: string; checked: boolean; onChange: (v: boolean) => void; description?: string; id?: string }) {
  const generatedId = useId();
  const inputId = id ?? generatedId;
  return (
    <label className="setting-toggle" htmlFor={inputId}>
      <input type="checkbox" id={inputId} checked={checked} onChange={e => onChange(e.target.checked)} />
      <span className="toggle-track"><span className="toggle-thumb" /></span>
      <span className="toggle-label">
        <span className="toggle-title">{label}</span>
        {description && <span className="toggle-desc">{description}</span>}
      </span>
    </label>
  );
}

export function SettingSelect({ label, value, onChange, options, description, id }: { label: string; value: string | number; onChange: (v: string) => void; options: { label: string; value: string | number }[]; description?: string; id?: string }) {
  const generatedId = useId();
  const inputId = id ?? generatedId;
  return (
    <div className="setting-select">
      <div className="setting-label">
        <label htmlFor={inputId} className="setting-title">{label}</label>
        {description && <span className="setting-desc">{description}</span>}
      </div>
      <select id={inputId} value={value} onChange={e => onChange(e.target.value)} className="setting-select-input">
        {options.map(opt => (
          <option key={opt.value} value={opt.value}>{opt.label}</option>
        ))}
      </select>
    </div>
  );
}

export function SettingInput({ label, value, onChange, type = 'text', placeholder, description, id }: { label: string; value: string; onChange: (v: string) => void; type?: string; placeholder?: string; description?: string; id?: string }) {
  const generatedId = useId();
  const inputId = id ?? generatedId;
  return (
    <div className="setting-input-row">
      <div className="setting-label">
        <label htmlFor={inputId} className="setting-title">{label}</label>
        {description && <span className="setting-desc">{description}</span>}
      </div>
      <input id={inputId} type={type} value={value} onChange={e => onChange(e.target.value)} placeholder={placeholder} className="setting-input" />
    </div>
  );
}

export function SettingNumberInput({ label, value, onChange, min, max, description, id }: { label: string; value: number; onChange: (v: number) => void; min?: number; max?: number; description?: string; id?: string }) {
  const generatedId = useId();
  const inputId = id ?? generatedId;
  return (
    <div className="setting-input-row">
      <div className="setting-label">
        <label htmlFor={inputId} className="setting-title">{label}</label>
        {description && <span className="setting-desc">{description}</span>}
      </div>
      <input id={inputId} type="number" value={value} onChange={e => onChange(Number(e.target.value))} min={min} max={max} className="setting-input setting-input-number" />
    </div>
  );
}

export function SettingsSectionCard({ title, icon, children }: { title: string; icon: string; children: React.ReactNode }) {
  return (
    <div className="settings-section-card">
      <h3 className="settings-section-title">
        <span aria-hidden="true">{icon}</span> {title}
      </h3>
      <div className="settings-section-content">{children}</div>
    </div>
  );
}
