import { SettingsSectionCard, SettingInput } from '../SettingsComponents';

interface ShortcutsSectionProps {
  toggleThemeShortcut: string;
  openSettingsShortcut: string;
  refreshDashboardShortcut: string;
  quickScanShortcut: string;
  onToggleThemeShortcutChange: (v: string) => void;
  onOpenSettingsShortcutChange: (v: string) => void;
  onRefreshDashboardShortcutChange: (v: string) => void;
  onQuickScanShortcutChange: (v: string) => void;
}

export function ShortcutsSection({ toggleThemeShortcut, openSettingsShortcut, refreshDashboardShortcut, quickScanShortcut, onToggleThemeShortcutChange, onOpenSettingsShortcutChange, onRefreshDashboardShortcutChange, onQuickScanShortcutChange }: ShortcutsSectionProps) {
  return (
    <SettingsSectionCard title="Keyboard Shortcuts" icon="\u2328\ufe0f">
      <SettingInput label="Toggle Theme" value={toggleThemeShortcut} onChange={onToggleThemeShortcutChange} description="Keyboard shortcut to toggle theme" />
      <SettingInput label="Open Settings" value={openSettingsShortcut} onChange={onOpenSettingsShortcutChange} description="Keyboard shortcut to open settings" />
      <SettingInput label="Refresh Dashboard" value={refreshDashboardShortcut} onChange={onRefreshDashboardShortcutChange} description="Keyboard shortcut to refresh dashboard" />
      <SettingInput label="Quick Scan" value={quickScanShortcut} onChange={onQuickScanShortcutChange} description="Keyboard shortcut to start quick scan" />
    </SettingsSectionCard>
  );
}
