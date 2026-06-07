import type { WorkflowMode } from '../../../stores/displayStore';
import { SettingsSectionCard, SettingSelect } from '../SettingsComponents';

const workflowModeOptions: { value: WorkflowMode; label: string; description: string }[] = [
  { value: 'pentest', label: 'Pentest', description: 'Full live data, presence, telemetry, 3D theatre' },
  { value: 'appsec', label: 'AppSec', description: 'Quieter surface — reduces live telemetry by default' },
];

interface WorkflowModeSectionProps {
  mode: WorkflowMode;
  onChange: (mode: WorkflowMode) => void;
}

export function WorkflowModeSection({ mode, onChange }: WorkflowModeSectionProps) {
  return (
    <SettingsSectionCard title="Workflow Mode" icon="briefcase">
      <SettingSelect
        label="Active role"
        value={mode}
        onChange={v => onChange(v as WorkflowMode)}
        options={workflowModeOptions.map(o => ({ label: o.label, value: o.value }))}
        description={workflowModeOptions.find(o => o.value === mode)?.description}
      />
      <p className="text-xs text-muted mt-2">
        Pentest mode shows presence indicators, live terminal streams, and the 3D job theatre by default.
        AppSec mode hides or collapses these so reviewers can focus on findings and reports.
      </p>
    </SettingsSectionCard>
  );
}
