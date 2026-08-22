import { SettingsSectionCard, SettingToggle } from '../SettingsComponents';
import type { AppSettings } from '@/context/SettingsContext';

interface FeaturesSectionProps {
  features: AppSettings['features'];
  onChange: (partial: Partial<AppSettings['features']>) => void;
}

type FeatureKey = keyof AppSettings['features'];

const FEATURE_TOGGLES: Array<{ key: FeatureKey; label: string; description: string }> = [
  { key: 'threatIntel', label: 'Threat Intelligence', description: 'Show CVE/CWE/EPSS context on finding detail' },
  { key: 'cvssDetails', label: 'Detailed CVSS', description: 'Vector breakdown and environmental scoring on finding detail' },
  { key: 'piiControls', label: 'PII Controls', description: 'Explicit reveal/redact control for sensitive finding text' },
  { key: 'remediationTracker', label: 'Remediation Tracking', description: 'Timeline of remediation status for the open finding' },
  { key: 'dashboardAnalytics', label: 'Dashboard Analytics', description: 'Trend charts under the dashboard KPI row' },
  { key: 'cinematicIntro', label: 'Cinematic Intro', description: 'Animated login entrance (respects reduced-motion policy)' },
  { key: 'clientPerformance', label: 'Client Performance', description: 'Show browser timing and model calibration on the Performance settings page' },
  { key: 'reconDetails', label: 'Recon Details', description: 'Show discovered host and scope URLs on completed job detail' },
  { key: 'livePipelineStatus', label: 'Live Pipeline Status', description: 'Show running-stage chips and connection state on the Jobs page (ScanStatusBar stays available either way)' },
  { key: 'compactFindingsFilters', label: 'Compact Findings Filters', description: 'Use the compact filter bar chrome on Findings. Tactical filters stay the default.' },
];

type MissingFeatureToggle = Exclude<FeatureKey, (typeof FEATURE_TOGGLES)[number]['key']>;
const _featureTogglesCoverAll: MissingFeatureToggle extends never ? true : never = true;
void _featureTogglesCoverAll;

export function FeaturesSection({ features, onChange }: FeaturesSectionProps) {
  return (
    <SettingsSectionCard title="Optional Features" icon="✨">
      <p className="text-xs text-muted mb-4">
        Core pages stay as they are. These toggles only add extra panels. Defaults avoid dumping a wall of previously hidden UI.
      </p>
      {FEATURE_TOGGLES.map((item) => (
        <SettingToggle
          key={item.key}
          label={item.label}
          checked={features[item.key]}
          onChange={(value) => onChange({ [item.key]: value })}
          description={item.description}
        />
      ))}
    </SettingsSectionCard>
  );
}
