import { useAuth } from '@/hooks/useAuth';
import { useSettings } from '@/hooks/useSettings';
import { useCallback, useState } from 'react';
import { SettingsSectionCard } from './SettingsComponents';
import { User, LogOut, Download, Upload } from 'lucide-react';

export function UserProfileSection() {
  const { user, logout } = useAuth();
  const { updater } = useSettings();
  const [importError, setImportError] = useState<string | null>(null);
  const [saveConfirmation, setSaveConfirmation] = useState<string | null>(null);

  const handleExport = useCallback(() => {
    try {
      const json = updater.exportSettings();
      const blob = new Blob([json], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'cyber-pipeline-settings.json';
      a.click();
      URL.revokeObjectURL(url);
      setSaveConfirmation('Settings exported successfully');
      setTimeout(() => setSaveConfirmation(null), 3000);
    } catch {
      setSaveConfirmation('Failed to export settings');
      setTimeout(() => setSaveConfirmation(null), 3000);
    }
  }, [updater]);

  const handleImport = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (event) => {
      try {
        const content = event.target?.result as string;
        const parsed = JSON.parse(content);
        if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
          throw new Error('Invalid format');
        }
        const knownKeys = ['dashboard', 'notifications', 'security', 'pipeline', 'api', 'reports', 'integrations', 'scanProfiles', 'experimental', 'performance', 'shortcuts', 'profiles', 'logging', 'rateLimiting'];
        const hasKnownKey = knownKeys.some(k => k in parsed);
        if (!hasKnownKey) {
          throw new Error('Unrecognized settings format');
        }
        updater.importSettings(parsed);
        setImportError(null);
        setSaveConfirmation('Settings imported successfully');
        setTimeout(() => setSaveConfirmation(null), 3000);
      } catch {
        setImportError('Invalid settings file. Please check the file format.');
      }
    };
    reader.readAsText(file);
    e.target.value = '';
  }, [updater]);

  return (
    <SettingsSectionCard title="User Profile" icon="👤">
      {saveConfirmation && <div className="banner ok" role="status">{saveConfirmation}</div>}
      {importError && <div className="banner error" role="alert">{importError}</div>}

      <div className="user-profile-card">
        <div className="user-profile-info">
          <div className="user-avatar">
            <User size={24} />
          </div>
          <div className="user-details">
            <div className="user-name">{user?.name || 'Guest'}</div>
            <div className="user-role">
              <span className={`role-badge role-${user?.role || 'viewer'}`}>
                {user?.role ? user.role.charAt(0).toUpperCase() + user.role.slice(1) : 'Viewer'}
              </span>
            </div>
          </div>
        </div>

        <div className="user-profile-actions">
          <button
            type="button"
            className="btn btn-sm btn-secondary"
            onClick={handleExport}
            title="Export settings"
          >
            <Download size={14} /> Export Settings
          </button>

          <label className="btn btn-sm btn-secondary" title="Import settings">
            <Upload size={14} /> Import Settings
            <input
              type="file"
              accept=".json"
              onChange={handleImport}
              className="sr-only"
              aria-label="Import settings from file"
            />
          </label>

          <button
            type="button"
            className="btn btn-sm btn-danger"
            onClick={logout}
          >
            <LogOut size={14} /> Sign Out
          </button>
        </div>
      </div>
    </SettingsSectionCard>
  );
}
