import { useState, useEffect, useCallback, useRef } from 'react';
import { getRegistry } from '@/api/client';
import type { AnalysisCheckOption, AnalysisControlGroup, AnalysisFocusPreset } from '@/types/api';

interface AnalysisOptionsPanelProps {
  onChange?: (enabledChecks: Set<string>) => void;
  initialEnabled?: Set<string>;
}

export default function AnalysisOptionsPanel({ onChange, initialEnabled }: AnalysisOptionsPanelProps) {
   
  const [loading, setLoading] = useState(true);
   
  const [error, setError] = useState<string | null>(null);
   
  const [expanded, setExpanded] = useState(false);

   
  const [checkOptions, setCheckOptions] = useState<AnalysisCheckOption[]>([]);
   
  const [controlGroups, setControlGroups] = useState<AnalysisControlGroup[]>([]);
   
  const [focusPresets, setFocusPresets] = useState<AnalysisFocusPreset[]>([]);

   
  const [enabledChecks, setEnabledChecks] = useState<Set<string>>(initialEnabled || new Set());

  const onChangeRef = useRef(onChange);
  useEffect(() => {
    onChangeRef.current = onChange;
   
  }, [onChange]);

  useEffect(() => {
    async function loadRegistry() {
      try {
        const registry = await getRegistry();
        const analysis = registry.analysis || {};
        setCheckOptions(analysis.check_options || []);
        setControlGroups(analysis.control_groups || []);
        setFocusPresets(analysis.focus_presets || []);

        const allChecks = new Set((analysis.check_options || []).map((c: AnalysisCheckOption) => c.name));
        setEnabledChecks(allChecks);
        onChangeRef.current?.(allChecks);

        setError(null);
      } catch {
        setError('Failed to load analysis options.');
      } finally {
        setLoading(false);
      }
    }
    loadRegistry();
  }, []);

  const toggleCheck = useCallback((checkName: string) => {
    setEnabledChecks(prev => {
      const next = new Set(prev);
      if (next.has(checkName)) {
        next.delete(checkName);
      } else {
        next.add(checkName);
      }
      onChange?.(next);
      return next;
    });
   
  }, [onChange]);

  const enableGroup = useCallback((groupName: string) => {
    setEnabledChecks(prev => {
      const next = new Set(prev);
      checkOptions
        .filter(opt => opt.group === groupName)
        .forEach(opt => next.add(opt.name));
      onChange?.(next);
      return next;
    });
   
  }, [checkOptions, onChange]);

  const disableGroup = useCallback((groupName: string) => {
    setEnabledChecks(prev => {
      const next = new Set(prev);
      checkOptions
        .filter(opt => opt.group === groupName)
        .forEach(opt => next.delete(opt.name));
      onChange?.(next);
      return next;
    });
   
  }, [checkOptions, onChange]);

  const applyFocusPreset = useCallback((preset: AnalysisFocusPreset) => {
    if (preset.checks) {
      const next = new Set(preset.checks);
      setEnabledChecks(next);
      onChange?.(next);
    } else {
      const allChecks = new Set(checkOptions.map(c => c.name));
      setEnabledChecks(allChecks);
      onChange?.(allChecks);
    }
   
  }, [checkOptions, onChange]);

  if (loading) {
    return <div className="card loading">Loading analysis options...</div>;
  }

  if (error) {
    return <div className="banner error">{error}</div>;
  }

  const enabledCount = enabledChecks.size;
  const totalCount = checkOptions.length;

  return (
    <div className="section">
      <div
        className="section-title-clickable section-title"
        onClick={() => setExpanded(!expanded)}
        onKeyDown={e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); setExpanded(!expanded); } }}
        role="button"
        tabIndex={0}
        aria-expanded={expanded}
      >
        <span>Analysis Options ({enabledCount}/{totalCount} enabled)</span>
        <span className="text-md">{expanded ? 'v' : '>'}</span>
      </div>

      {expanded && (
        <div className="card card-padded">
          {focusPresets.length > 0 && (
            <div className="mb-20">
              <span className="block mb-8 text-md text-accent">
                Focus Presets
              </span>
              <div className="flex gap-8 flex-wrap">
                {focusPresets.map(preset => (
                  <button
                    key={preset.name}
                    type="button"
                    className="btn btn-secondary btn-sm"
                    onClick={() => applyFocusPreset(preset)}
                  >
                    {preset.label}
                  </button>
                ))}
              </div>
            </div>
          )}

          {controlGroups.map(group => {
            const groupChecks = checkOptions.filter(opt => opt.group === group.name);
            if (groupChecks.length === 0) return null;
            const groupEnabled = groupChecks.filter(c => enabledChecks.has(c.name)).length;

            return (
              <details key={group.name} open className="details-open">
                <summary className="summary-clickable">
                  {group.icon || '🔍'} {group.label} ({groupEnabled}/{groupChecks.length})
                  <button type="button" className="btn-link-small ml-8" onClick={e => { e.preventDefault(); enableGroup(group.name); }}>
                    Enable All
                  </button>
                  <button type="button" className="btn-link-small ml-4" onClick={e => { e.preventDefault(); disableGroup(group.name); }}>
                    Disable All
                  </button>
                </summary>
                <div className="grid grid-cols-auto-fill-xl px-12 gap-6">
                  {groupChecks.map(check => {
                    const isChecked = enabledChecks.has(check.name);
                    return (
                      <label
                        key={check.name}
                        className={`check-label ${isChecked ? 'checked' : ''}`}
                      >
                        <input
                          type="checkbox"
                          checked={isChecked}
                          onChange={() => toggleCheck(check.name)}
                        />
                        <div>
                          <div className="check-label-title">{check.label}</div>
                          {check.description && (
                            <div className="check-label-desc">{check.description}</div>
                          )}
                        </div>
                      </label>
                    );
                  })}
                </div>
              </details>
            );
          })}
        </div>
      )}
    </div>
  );
}
