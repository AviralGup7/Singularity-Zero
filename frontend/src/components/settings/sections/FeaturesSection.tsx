import { SettingsSectionCard, SettingToggle } from '../SettingsComponents';
import type { AppSettings } from '@/context/SettingsContext';

interface FeaturesSectionProps {
  features: AppSettings['features'];
  onChange: (partial: Partial<AppSettings['features']>) => void;
}

export function FeaturesSection({ features, onChange }: FeaturesSectionProps) {
  return (
    <SettingsSectionCard title="Optional Features" icon="✨">
      <p className="text-xs text-muted mb-4">
        Core pages stay as they are. These toggles only add extra panels. Defaults avoid dumping a wall of previously hidden UI.
      </p>
      <SettingToggle
        label="Threat Intelligence"
        checked={features.threatIntel}
        onChange={(v) => onChange({ threatIntel: v })}
        description="Show CVE/CWE/EPSS context on finding detail"
      />
      <SettingToggle
        label="Detailed CVSS"
        checked={features.cvssDetails}
        onChange={(v) => onChange({ cvssDetails: v })}
        description="Vector breakdown and environmental scoring on finding detail"
      />
      <SettingToggle
        label="PII Controls"
        checked={features.piiControls}
        onChange={(v) => onChange({ piiControls: v })}
        description="Explicit reveal/redact control for sensitive finding text"
      />
      <SettingToggle
        label="Remediation Tracking"
        checked={features.remediationTracker}
        onChange={(v) => onChange({ remediationTracker: v })}
        description="Timeline of remediation status for the open finding"
      />
      <SettingToggle
        label="Dashboard Analytics"
        checked={features.dashboardAnalytics}
        onChange={(v) => onChange({ dashboardAnalytics: v })}
        description="Trend charts under the dashboard KPI row"
      />
      <SettingToggle
        label="Cinematic Intro"
        checked={features.cinematicIntro}
        onChange={(v) => onChange({ cinematicIntro: v })}
        description="Animated login entrance (respects reduced-motion policy)"
      />
    </SettingsSectionCard>
  );
}
