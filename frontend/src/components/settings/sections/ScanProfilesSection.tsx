import { type AppSettings } from '../../../context/SettingsContext';
import { SettingsSectionCard, SettingSelect, SettingToggle } from '../SettingsComponents';

interface ScanProfilesSectionProps {
  defaultScanProfile: AppSettings['scanProfiles']['defaultProfile'];
  includeNuclei: boolean;
  includePassiveAnalysis: boolean;
  includeActiveProbes: boolean;
  includeIntelligence: boolean;
  onDefaultScanProfileChange: (v: string) => void;
  onIncludeNucleiChange: (v: boolean) => void;
  onIncludePassiveAnalysisChange: (v: boolean) => void;
  onIncludeActiveProbesChange: (v: boolean) => void;
  onIncludeIntelligenceChange: (v: boolean) => void;
}

export function ScanProfilesSection({ defaultScanProfile, includeNuclei, includePassiveAnalysis, includeActiveProbes, includeIntelligence, onDefaultScanProfileChange, onIncludeNucleiChange, onIncludePassiveAnalysisChange, onIncludeActiveProbesChange, onIncludeIntelligenceChange }: ScanProfilesSectionProps) {
  return (
    <SettingsSectionCard title="Scan Profiles" icon="\ud83c\udfaf">
      <SettingSelect
        label="Default Profile"
        value={defaultScanProfile}
        onChange={onDefaultScanProfileChange}
        options={[{ label: 'Full Scan', value: 'full' }, { label: 'Quick Scan', value: 'quick' }, { label: 'Passive Only', value: 'passive' }, { label: 'Custom', value: 'custom' }]}
        description="Default scan profile for new jobs"
      />
      <SettingToggle label="Include Nuclei" checked={includeNuclei} onChange={onIncludeNucleiChange} description="Run Nuclei templates" />
      <SettingToggle label="Include Passive Analysis" checked={includePassiveAnalysis} onChange={onIncludePassiveAnalysisChange} description="Run passive reconnaissance modules" />
      <SettingToggle label="Include Active Probes" checked={includeActiveProbes} onChange={onIncludeActiveProbesChange} description="Run active probing modules" />
      <SettingToggle label="Include Intelligence" checked={includeIntelligence} onChange={onIncludeIntelligenceChange} description="Run threat intelligence modules" />
    </SettingsSectionCard>
  );
}
