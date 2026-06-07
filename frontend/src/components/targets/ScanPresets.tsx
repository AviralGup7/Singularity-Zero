import { useState, useEffect, useCallback } from 'react';
import { getDynamicPluginCatalog } from '../../api/registry';
import { useToast } from '../../hooks/useToast';
import type { DynamicPluginManifest } from '../../types/api';

interface ScanPreset {
  id: string;
  name: string;
  description: string;
  createdAt: number;
  config: {
    mode: string;
    modules: string[];
    executionOptions: Record<string, boolean>;
    runtimeOverrides: Record<string, string>;
  };
}

interface ScanPresetsProps {
  currentConfig: {
    mode: string;
    modules: Set<string>;
    executionOptions: Record<string, boolean>;
    runtimeOverrides: Record<string, string>;
  };
   
  onLoadPreset: (config: ScanPreset['config']) => void;
}

const PRESETS_STORAGE_KEY = 'cyber-pipeline-scan-presets';

function loadPresets(): ScanPreset[] {
  try {
    const raw = localStorage.getItem(PRESETS_STORAGE_KEY);
    return raw ? JSON.parse(raw) : [];
  } catch {
    return [];
  }
}

function savePresets(presets: ScanPreset[]) {
  try {
    localStorage.setItem(PRESETS_STORAGE_KEY, JSON.stringify(presets));
  } catch {
    // Storage quota exceeded
  }
}

export default function ScanPresets({ currentConfig, onLoadPreset }: ScanPresetsProps) {
   
  const [presets, setPresets] = useState<ScanPreset[]>([]);
   
  const [showSaveForm, setShowSaveForm] = useState(false);
   
  const [presetName, setPresetName] = useState('');
   
  const [presetDescription, setPresetDescription] = useState('');
   
  const [saveError, setSaveError] = useState<string | null>(null);
  const [dynamicPlugins, setDynamicPlugins] = useState<DynamicPluginManifest[]>([]);
  const [invalidPlugins, setInvalidPlugins] = useState<DynamicPluginManifest[]>([]);
  const toast = useToast();

  useEffect(() => {
    let mounted = true;
    Promise.resolve().then(() => {
      if (mounted) setPresets(loadPresets());
    });
    return () => { mounted = false; };
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    getDynamicPluginCatalog(controller.signal)
      .then((catalog) => {
        setDynamicPlugins(catalog.plugins);
        setInvalidPlugins(catalog.invalid);
      })
      .catch(() => {
        setDynamicPlugins([]);
        setInvalidPlugins([]);
      });
    return () => controller.abort();
  }, []);

  const handleSave = useCallback(() => {
    if (!presetName.trim()) {
      setSaveError('Preset name is required.');
      return;
    }
    const existing = presets.find(p => p.name.toLowerCase() === presetName.trim().toLowerCase());
    if (existing) {
      setSaveError('A preset with this name already exists.');
      return;
    }
    const newPreset: ScanPreset = {
      id: crypto.randomUUID?.() || Date.now().toString(36),
      name: presetName.trim(),
      description: presetDescription.trim(),
      createdAt: Date.now(),
      config: {
        mode: currentConfig.mode,
        modules: Array.from(currentConfig.modules),
        executionOptions: { ...currentConfig.executionOptions },
        runtimeOverrides: { ...currentConfig.runtimeOverrides },
      },
    };
   
    const updated = [...presets, newPreset];
    savePresets(updated);
    setPresets(updated);
    setPresetName('');
    setPresetDescription('');
    setShowSaveForm(false);
    setSaveError(null);
    toast.success(`Preset "${newPreset.name}" saved.`);
   
  }, [presetName, presetDescription, presets, currentConfig, toast]);

  const handleLoad = useCallback((preset: ScanPreset) => {
    onLoadPreset(preset.config);
    toast.success(`Loaded preset "${preset.name}".`);
   
  }, [onLoadPreset, toast]);

  const handleDelete = useCallback((id: string) => {
    const preset = presets.find(p => p.id === id);
    const updated = presets.filter(p => p.id !== id);
    savePresets(updated);
    setPresets(updated);
    if (preset) toast.info(`Deleted preset "${preset.name}".`);
   
  }, [presets, toast]);

  return (
    <div className="scan-presets-section">
      <div className="scan-presets-header">
        <h4 className="scan-presets-title">Saved Presets</h4>
        <button
          type="button"
          className="btn btn-sm"
          onClick={() => setShowSaveForm(!showSaveForm)}
        >
          {showSaveForm ? 'Cancel' : '+ Save Current'}
        </button>
      </div>

      {showSaveForm && (
        <div className="card card-padded scan-preset-save-form">
          {saveError && <div className="banner error" role="alert">{saveError}</div>}
          <div className="mb-12">
            <label className="form-label-accent" htmlFor="preset-name">Preset Name</label>
            <input
              id="preset-name"
              type="text"
              className="form-input"
              value={presetName}
              onChange={e => { setPresetName(e.target.value); setSaveError(null); }}
              placeholder="e.g. Quick Auth Scan"
            />
          </div>
          <div className="mb-12">
            <label className="form-label-accent" htmlFor="preset-desc">Description</label>
            <textarea
              id="preset-desc"
              className="form-textarea"
              rows={2}
              value={presetDescription}
              onChange={e => setPresetDescription(e.target.value)}
              placeholder="Optional description..."
            />
          </div>
          <button type="button" className="btn btn-primary btn-sm" onClick={handleSave}>
            Save Preset
          </button>
        </div>
      )}

      {presets.length === 0 && !showSaveForm && (
        <p className="scan-presets-empty">No saved presets. Configure a scan and save it for reuse.</p>
      )}

      {presets.length > 0 && (
        <div className="scan-presets-list">
          {presets.map(preset => (
            <div key={preset.id} className="scan-preset-card card">
              <div className="scan-preset-info">
                <span className="scan-preset-name">{preset.name}</span>
                {preset.description && (
                  <span className="scan-preset-desc">{preset.description}</span>
                )}
                <span className="scan-preset-meta">
                  {preset.config.modules.length} modules &middot; {new Date(preset.createdAt).toLocaleDateString()}
                </span>
              </div>
              <div className="scan-preset-actions">
                <button
                  type="button"
                  className="btn btn-sm"
                  onClick={() => handleLoad(preset)}
                >
                  Load
                </button>
                <button
                  type="button"
                  className="btn btn-sm btn-danger"
                  onClick={() => {
                    if (window.confirm(`Delete preset "${preset.name}"?`)) {
                      handleDelete(preset.id);
                    }
                  }}
                >
                  Delete
                </button>
              </div>
            </div>
          ))}
        </div>
      )}

      {(dynamicPlugins.length > 0 || invalidPlugins.length > 0) && (
        <div className="mt-4">
          <div className="scan-presets-header">
            <h4 className="scan-presets-title">Dynamic Plugins</h4>
            <span className="scan-preset-meta">
              {dynamicPlugins.length} loaded
              {invalidPlugins.length > 0 ? ` - ${invalidPlugins.length} invalid` : ''}
            </span>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
            {dynamicPlugins.map((plugin) => (
              <div key={plugin.id} className="scan-preset-card card">
                <div className="scan-preset-info">
                  <span className="scan-preset-name">{plugin.name}</span>
                  <span className="scan-preset-desc">{plugin.description}</span>
                  <span className="scan-preset-meta">
                    {plugin.kind} &middot; {plugin.group} &middot; {plugin.sandbox}
                  </span>
                </div>
              </div>
            ))}
            {invalidPlugins.map((plugin) => (
              <div key={plugin.id} className="scan-preset-card card border-[var(--warn)]/60">
                <div className="scan-preset-info">
                  <span className="scan-preset-name">{plugin.name}</span>
                  <span className="scan-preset-desc">
                    {plugin.errors?.[0] || 'Manifest validation failed.'}
                  </span>
                  <span className="scan-preset-meta">invalid</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
