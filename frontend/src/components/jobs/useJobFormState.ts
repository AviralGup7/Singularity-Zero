import { useState, useEffect, useCallback } from 'react';
import { getDefaults, getRegistry } from '../../api/client';
import { useToast } from '../../hooks/useToast';
import { checkModuleDependencies, autoResolveDependencies } from '../../utils/moduleDependencies';
import type { ModuleOption, ModuleGroup, ModePreset } from '../../types/api';

export function useJobFormState() {
  const toast = useToast();
   
  const [loading, setLoading] = useState(true);
   
  const [error, setError] = useState<string | null>(null);
   
  const [baseUrl, setBaseUrl] = useState('');
   
  const [scopeText, setScopeText] = useState('');
   
  const [selectedMode, setSelectedMode] = useState('full');
   
  const [selectedModules, setSelectedModules] = useState<Set<string>>(new Set());
   
  const [runtimeOverrides, setRuntimeOverrides] = useState<Record<string, string>>({});
   
  const [executionOptions, setExecutionOptions] = useState<Record<string, boolean>>({
    skip_crtsh: false,
    refresh_cache: false,
  });
   
  const [modePresets, setModePresets] = useState<ModePreset[]>([]);
   
  const [moduleGroups, setModuleGroups] = useState<ModuleGroup[]>([]);
   
  const [moduleOptions, setModuleOptions] = useState<ModuleOption[]>([]);

  useEffect(() => {
    const controller = new AbortController();

    const getConfigLoadErrorMessage = (err: unknown): string => {
      const wrapped = err as {
        status?: number;
        message?: string;
        original?: { response?: { status?: number; data?: { detail?: string; message?: string } } };
      };
      const status = wrapped.status ?? wrapped.original?.response?.status;
      const rawMessage = wrapped.message || '';
      const message = rawMessage.toLowerCase();
      const detail = wrapped.original?.response?.data?.detail || wrapped.original?.response?.data?.message;

      if (status === 401 || status === 403) {
        return 'Failed to load configuration: authentication required. Please sign in again.';
      }

      if (status && status >= 500) {
        return `Failed to load configuration: server error (HTTP ${status}).`;
      }

      if (status) {
        return `Failed to load configuration (HTTP ${status})${detail ? `: ${detail}` : ''}.`;
      }

      if (message.includes('network error')) {
        return 'Failed to load configuration: cannot reach backend. Check that the dashboard API is running.';
      }

      if (rawMessage) {
        return `Failed to load configuration: ${rawMessage}`;
      }

      return 'Failed to load configuration. Please try refreshing the page.';
    };

    async function loadConfig(signal?: AbortSignal) {
      try {
   
        const [defaults, registry] = await Promise.all([
          getDefaults(signal),
          getRegistry(signal),
        ]);

        const presets = registry?.modes?.presets ?? [];
        const options = registry?.modules?.options ?? [];
        const groups = registry?.modules?.groups ?? [];

        const requestedMode = defaults.default_mode;
        const resolvedMode = presets.some(p => p.name === requestedMode)
          ? requestedMode
   
          : (presets[0]?.name ?? requestedMode);

        setSelectedMode(resolvedMode);
        setModePresets(presets);
        setModuleOptions(options);
        setModuleGroups(groups);

        const defaultPreset = presets.find(m => m.name === resolvedMode);
        if (defaultPreset) {
          setSelectedModules(new Set(defaultPreset.modules));
        }

        const overrides: Record<string, string> = {};
   
        for (const [key, value] of Object.entries(defaults.form_defaults ?? {})) {
          overrides[key] = value;
        }
        setRuntimeOverrides(overrides);
        setError(null);
      } catch (err: unknown) {
        if (signal?.aborted) return;
        const message = getConfigLoadErrorMessage(err);
        setError(message);
        toast.error(message);
      } finally {
        if (!signal?.aborted) setLoading(false);
      }
    }
    loadConfig(controller.signal);
    return () => controller.abort();
   
  }, [toast]);

  const handleModeSelect = useCallback((modeName: string) => {
    setSelectedMode(modeName);
    const preset = modePresets.find(m => m.name === modeName);
    if (preset) {
      setSelectedModules(new Set(preset.modules));
    }
   
  }, [modePresets]);

  const toggleModule = useCallback((moduleName: string) => {
    setSelectedModules(prev => {
      const next = new Set(prev);
      if (next.has(moduleName)) {
        next.delete(moduleName);
      } else {
        next.add(moduleName);
      }
      return next;
    });
  }, []);

  const toggleExecutionOption = useCallback((key: string) => {
    setExecutionOptions(prev => ({ ...prev, [key]: !prev[key] }));
  }, []);

  const updateRuntimeOverride = useCallback((key: string, value: string) => {
   
    setRuntimeOverrides(prev => ({ ...prev, [key]: value }));
  }, []);

  const handleLoadPreset = useCallback((config: {
    mode: string;
    modules: string[];
    executionOptions: Record<string, boolean>;
    runtimeOverrides: Record<string, string>;
  }) => {
    setSelectedMode(config.mode);
    setSelectedModules(new Set(config.modules));
    setExecutionOptions(config.executionOptions);
    setRuntimeOverrides(config.runtimeOverrides);
  }, []);

  const handleAutoResolve = useCallback(() => {
    const resolved = autoResolveDependencies(selectedModules, moduleOptions);
    setSelectedModules(resolved);
    toast.info('Missing dependencies added automatically.');
   
  }, [selectedModules, moduleOptions, toast]);

  const depWarnings = checkModuleDependencies(selectedModules, moduleOptions);

  return {
    loading,
    error,
    setError,
    baseUrl,
    setBaseUrl,
    scopeText,
    setScopeText,
    selectedMode,
    setSelectedMode,
    selectedModules,
    setSelectedModules,
    runtimeOverrides,
    executionOptions,
    modePresets,
    moduleGroups,
    moduleOptions,
    handleModeSelect,
    toggleModule,
    toggleExecutionOption,
    updateRuntimeOverride,
    handleLoadPreset,
    handleAutoResolve,
    depWarnings,
  };
}
