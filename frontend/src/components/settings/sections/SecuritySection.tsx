import { SettingsSectionCard, SettingToggle, SettingNumberInput } from '../SettingsComponents';

interface SecuritySectionProps {
  confirmDestructiveActions: boolean;
  showSensitiveData: boolean;
  autoLogoutMinutes: number;
  onConfirmDestructiveActionsChange: (v: boolean) => void;
  onShowSensitiveDataChange: (v: boolean) => void;
  onAutoLogoutMinutesChange: (v: number) => void;
}

export function SecuritySection({ confirmDestructiveActions, showSensitiveData, autoLogoutMinutes, onConfirmDestructiveActionsChange, onShowSensitiveDataChange, onAutoLogoutMinutesChange }: SecuritySectionProps) {
  return (
    <SettingsSectionCard title="Security" icon="\ud83d\udd12">
      <SettingToggle label="Confirm Destructive Actions" checked={confirmDestructiveActions} onChange={onConfirmDestructiveActionsChange} description="Require confirmation for destructive operations" />
      <SettingToggle label="Show Sensitive Data" checked={showSensitiveData} onChange={onShowSensitiveDataChange} description="Display API keys and tokens in plaintext" />
      <SettingNumberInput label="Auto Logout (minutes)" value={autoLogoutMinutes} onChange={onAutoLogoutMinutesChange} min={0} max={480} description="Minutes of inactivity before auto logout (0 to disable)" />
    </SettingsSectionCard>
  );
}
