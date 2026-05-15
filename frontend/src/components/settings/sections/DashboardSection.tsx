import { SettingsSectionCard, SettingToggle, SettingSelect } from '../SettingsComponents';

const refreshIntervals = [
  { label: '10s', value: 10 },
  { label: '30s', value: 30 },
  { label: '1m', value: 60 },
  { label: '5m', value: 300 },
];

interface DashboardSectionProps {
  autoRefresh: boolean;
  refreshInterval: number;
  onAutoRefreshChange: (v: boolean) => void;
  onRefreshIntervalChange: (v: number) => void;
}

export function DashboardSection({ autoRefresh, refreshInterval, onAutoRefreshChange, onRefreshIntervalChange }: DashboardSectionProps) {
  return (
    <SettingsSectionCard title="Dashboard" icon="\ud83d\udcca">
      <SettingToggle label="Auto Refresh" checked={autoRefresh} onChange={onAutoRefreshChange} description="Automatically refresh dashboard data" />
      <SettingSelect
        label="Refresh Interval"
        value={refreshInterval}
        onChange={v => onRefreshIntervalChange(Number(v))}
        options={refreshIntervals.map(o => ({ label: o.label, value: o.value }))}
        description="How often to refresh data"
      />
    </SettingsSectionCard>
  );
}
