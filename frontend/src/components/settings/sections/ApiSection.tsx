import { useState } from 'react';
import { SettingsSectionCard, SettingSelect, SettingInput } from '../SettingsComponents';

const timeoutOptions = [
  { label: '30s', value: 30 },
  { label: '1m', value: 60 },
  { label: '5m', value: 300 },
  { label: '10m', value: 600 },
  { label: '30m', value: 1800 },
];

interface ApiSectionProps {
  apiBaseUrl: string;
  apiTimeout: number;
  apiKey: string;
  onApiBaseUrlChange: (v: string) => void;
  onApiTimeoutChange: (v: number) => void;
  onApiKeyChange: (v: string) => void;
}

export function ApiSection({ apiBaseUrl, apiTimeout, apiKey, onApiBaseUrlChange, onApiTimeoutChange, onApiKeyChange }: ApiSectionProps) {
  const [showApiKey, setShowApiKey] = useState(false);

  return (
    <SettingsSectionCard title="API" icon="\ud83d\udd17">
      <SettingInput label="Base URL" value={apiBaseUrl} onChange={onApiBaseUrlChange} placeholder="http://localhost:8080" description="Backend API endpoint" />
      <SettingSelect
        label="Timeout"
        value={apiTimeout}
        onChange={v => onApiTimeoutChange(Number(v))}
        options={timeoutOptions.map(o => ({ label: o.label, value: o.value }))}
        description="API request timeout"
      />
      <div className="setting-input-row">
        <div className="setting-label">
          <span className="setting-title">API Key</span>
          <span className="setting-desc">Optional authentication key</span>
        </div>
        <div className="setting-input-with-toggle">
          <input type={showApiKey ? 'text' : 'password'} value={apiKey} onChange={e => onApiKeyChange(e.target.value)} placeholder="sk-..." className="setting-input" />
          <button type="button" className="btn btn-sm btn-secondary" onClick={() => setShowApiKey(!showApiKey)} aria-label={showApiKey ? 'Hide API key' : 'Show API key'}>
            {showApiKey ? 'Hide' : 'Show'}
          </button>
        </div>
      </div>
    </SettingsSectionCard>
  );
}
