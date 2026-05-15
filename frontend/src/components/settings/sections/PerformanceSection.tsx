import { SettingsSectionCard, SettingToggle, SettingNumberInput } from '../SettingsComponents';

interface PerformanceSectionProps {
  enableCaching: boolean;
  cacheDuration: number;
  lazyLoadModules: boolean;
  maxConcurrentRequests: number;
  onEnableCachingChange: (v: boolean) => void;
  onCacheDurationChange: (v: number) => void;
  onLazyLoadModulesChange: (v: boolean) => void;
  onMaxConcurrentRequestsChange: (v: number) => void;
}

export function PerformanceSection({ enableCaching, cacheDuration, lazyLoadModules, maxConcurrentRequests, onEnableCachingChange, onCacheDurationChange, onLazyLoadModulesChange, onMaxConcurrentRequestsChange }: PerformanceSectionProps) {
  return (
    <SettingsSectionCard title="Performance" icon="\u26a1">
      <SettingToggle label="Enable Caching" checked={enableCaching} onChange={onEnableCachingChange} description="Cache API responses" />
      <SettingNumberInput label="Cache Duration (minutes)" value={cacheDuration} onChange={onCacheDurationChange} min={1} max={1440} description="How long to cache responses" />
      <SettingToggle label="Lazy Load Modules" checked={lazyLoadModules} onChange={onLazyLoadModulesChange} description="Load modules on demand" />
      <SettingNumberInput label="Max Concurrent Requests" value={maxConcurrentRequests} onChange={onMaxConcurrentRequestsChange} min={1} max={50} description="Maximum simultaneous API requests" />
    </SettingsSectionCard>
  );
}
