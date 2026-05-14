import { FormField } from '../FormField';
import ScanPresets from '../ScanPresets';
import AnalysisOptionsPanel from '../AnalysisOptionsPanel';
import type { ModuleOption } from '../../types/api';

interface ConfigStepProps {
  selectedModules: Set<string>;
  executionOptions: Record<string, boolean>;
  runtimeOverrides: Record<string, string>;
  moduleOptions: ModuleOption[];
  currentConfig: {
    mode: string;
    modules: Set<string>;
    executionOptions: Record<string, boolean>;
    runtimeOverrides: Record<string, string>;
  };
  onLoadPreset: (config: {
    mode: string;
    modules: string[];
    executionOptions: Record<string, boolean>;
    runtimeOverrides: Record<string, string>;
  }) => void;
  onToggleExecutionOption: (key: string) => void;
  onUpdateRuntimeOverride: (key: string, value: string) => void;
}

export function ConfigStep({
  executionOptions,
  runtimeOverrides,
  moduleOptions,
  currentConfig,
  onLoadPreset,
  onToggleExecutionOption,
  onUpdateRuntimeOverride,
}: ConfigStepProps) {
  const overrideModules = moduleOptions.filter(
    m => 'hasRuntimeOverride' in m && (m as Record<string, unknown>).hasRuntimeOverride
  ) as (ModuleOption & { hasRuntimeOverride?: boolean; key?: string; label?: string; placeholder?: string; type?: string })[];

  return (
    <div className="wizard-step-content">
      <h3 className="wizard-step-title">Configuration</h3>

      <ScanPresets
        currentConfig={currentConfig}
        onLoadPreset={onLoadPreset}
      />

      <fieldset className="form-fieldset">
        <legend className="form-legend">Execution Options</legend>
        <div className="grid grid-cols-auto-fill-lg px-12 gap-6">
          {Object.entries(executionOptions).map(([key, value]) => (
            <label key={key} className="toggle-label">
              <input
                type="checkbox"
                checked={value}
                onChange={() => onToggleExecutionOption(key)}
              />
              <span className="toggle-track"><span className="toggle-thumb" /></span>
              <span>{key.replace(/_/g, ' ')}</span>
            </label>
          ))}
        </div>
      </fieldset>

      {overrideModules.length > 0 && (
        <fieldset className="form-fieldset">
          <legend className="form-legend">Runtime Overrides</legend>
          <div className="grid grid-cols-auto-fill-lg gap-8">
            {overrideModules.map((opt) => (
              <FormField
                key={opt.key ?? opt.name}
                label={opt.label ?? opt.name}
              >
                <input
                  className="form-input"
                  placeholder={opt.placeholder}
                  type={opt.type ?? 'text'}
                  value={runtimeOverrides[opt.key ?? opt.name] ?? ''}
                  onChange={(e) => onUpdateRuntimeOverride(opt.key ?? opt.name, e.target.value)}
                />
              </FormField>
            ))}
          </div>
        </fieldset>
      )}

      <AnalysisOptionsPanel />
    </div>
  );
}
