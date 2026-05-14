import { SettingsSectionCard } from '../SettingsComponents';

interface DataSectionProps {
  onExport: () => void;
  onImport: (e: React.ChangeEvent<HTMLInputElement>) => void;
  onReset: () => void;
  importError: string | null;
  saveConfirmation: string | null;
}

export function DataSection({ onExport, onImport, onReset, importError, saveConfirmation }: DataSectionProps) {
  return (
    <SettingsSectionCard title="Data Management" icon="\ud83d\udcbe">
      <div className="data-actions">
        <button type="button" className="btn btn-primary" onClick={onExport}>Export Settings</button>
        <label className="btn btn-secondary">
          Import Settings
          <input type="file" accept=".json" onChange={onImport} className="sr-only" />
        </label>
        <button type="button" className="btn btn-danger" onClick={() => onReset()}>Reset to Defaults</button>
      </div>
      {importError && <div className="banner error" role="alert">{importError}</div>}
      {saveConfirmation && <div className="banner ok" role="status">{saveConfirmation}</div>}
    </SettingsSectionCard>
  );
}
