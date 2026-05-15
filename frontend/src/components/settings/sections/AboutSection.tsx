import { SettingsSectionCard } from '../SettingsComponents';

export function AboutSection() {
  return (
    <SettingsSectionCard title="About" icon="\u2139\ufe0f">
      <div className="about-info">
        <p><strong>Cyber Security Test Pipeline</strong></p>
        <p>Version: 1.0.0</p>
        <p>A comprehensive security testing pipeline for web applications.</p>
      </div>
    </SettingsSectionCard>
  );
}
