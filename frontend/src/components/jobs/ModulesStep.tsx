import type { ModuleOption, ModuleGroup, ModePreset } from '../../types/api';

interface ModulesStepProps {
  selectedMode: string;
  modePresets: ModePreset[];
  selectedModules: Set<string>;
  moduleGroups: ModuleGroup[];
  moduleOptions: ModuleOption[];
  depWarnings: { type: string; message: string }[];
  onModeSelect: (mode: string) => void;
  onToggleModule: (name: string) => void;
  onAutoResolve: () => void;
}

export function ModulesStep({
  selectedMode,
  modePresets,
  selectedModules,
  moduleGroups,
  moduleOptions,
  depWarnings,
  onModeSelect,
  onToggleModule,
  onAutoResolve,
}: ModulesStepProps) {
  return (
    <div className="wizard-step-content">
      <h3 className="wizard-step-title">Module Selection</h3>

      {depWarnings.length > 0 && (
        <div className="module-dependency-warnings">
          <div className="banner warning">
            <strong>Module Dependency Warnings</strong>
            <ul className="dependency-warnings-list">
              {depWarnings.map((w, i) => (
                <li key={i}>{w.message}</li>
              ))}
            </ul>
            {depWarnings.some(w => w.type === 'missing') && (
              <button
                type="button"
                className="btn btn-sm btn-warning"
                onClick={onAutoResolve}
              >
                Auto-resolve missing dependencies
              </button>
            )}
          </div>
        </div>
      )}

      <fieldset className="form-fieldset">
        <legend className="form-legend">Mode Preset</legend>
        <div className="flex gap-8 flex-wrap">
          {modePresets.map(mode => (
            <button
              key={mode.name}
              type="button"
              className={`btn btn-sm ${selectedMode === mode.name ? '' : 'btn-secondary'}`}
              onClick={() => onModeSelect(mode.name)}
              aria-pressed={selectedMode === mode.name}
            >
              {mode.label} ({mode.modules.length} modules)
            </button>
          ))}
        </div>
      </fieldset>

      <fieldset className="form-fieldset">
        <legend className="form-legend">Modules ({selectedModules.size} selected)</legend>
        {moduleGroups.map(group => {
          const groupModules = moduleOptions.filter(m => m.group === group.name);
          if (groupModules.length === 0) return null;

          return (
            <details key={group.name} open className="details-open-sm">
              <summary className="summary-text">{group.label}</summary>
              <div className="grid grid-cols-auto-fill-lg px-12 gap-6">
                {groupModules.map(mod => {
                  const isSelected = selectedModules.has(mod.name);
                  return (
                    <label
                      key={mod.name}
                      className={`module-toggle ${isSelected ? 'selected' : ''}`}
                    >
                      <input
                        type="checkbox"
                        checked={isSelected}
                        onChange={() => onToggleModule(mod.name)}
                      />
                      <span className="module-toggle-label">
                        <span className="module-toggle-name">{mod.label}</span>
                        {mod.description && (
                          <span className="module-toggle-desc">{mod.description}</span>
                        )}
                      </span>
                    </label>
                  );
                })}
              </div>
            </details>
          );
        })}
      </fieldset>
    </div>
  );
}
