import { useState, useCallback, useMemo, type ReactNode } from 'react';
import { AppSettingsSchema } from '@/api/schemas';
import { safeStorage } from '@/utils/storage';
import { useDebouncedPersist } from '@/hooks/useDebouncedPersist';
import { SettingsContext } from './settings-context';

export type { AppSettings, SettingsUpdater } from './settings-context';

import type { AppSettings } from './settings-context';

const defaultSettings: AppSettings = AppSettingsSchema.parse({});

function deepMerge<T extends Record<string, unknown>>(target: T, source: Partial<T>): T {
  const result: Record<string, unknown> = { ...target };
  for (const key of Object.keys(source)) {
    const sourceVal = source[key as keyof T];
    const targetVal = target[key as keyof T];

    if (sourceVal !== undefined) {
      if (sourceVal !== null && typeof sourceVal === 'object' && !Array.isArray(sourceVal) &&
          targetVal !== null && typeof targetVal === 'object' && !Array.isArray(targetVal)) {
        Object.assign(result, { [key]: deepMerge(targetVal as Record<string, unknown>, sourceVal as Record<string, unknown>) });
      } else {
        Object.assign(result, { [key]: sourceVal });
      }
    }
  }
  return result as T;
}

const STORAGE_KEY = 'cyber-pipeline-settings';
const DEBOUNCE_MS = 300;

export function SettingsProvider({ children }: { children: ReactNode }) {
  const [settings, setSettings] = useState<AppSettings>(() => {
    const stored = safeStorage.get(STORAGE_KEY);
    if (stored) {
      try {
        const parsed = JSON.parse(stored);
        return AppSettingsSchema.parse({ ...defaultSettings, ...parsed });
      } catch { /* ignore */ }
    }
    return defaultSettings;
  });

  const persistSettings = useCallback((data: AppSettings) => {
    safeStorage.set(STORAGE_KEY, JSON.stringify(data));
  }, []);

  useDebouncedPersist(settings, persistSettings, DEBOUNCE_MS);

  const updateSection = useCallback(<T extends keyof AppSettings>(section: T, partial: Partial<AppSettings[T]>) => {
    setSettings(prev => {
      const entries = Object.entries(prev as Record<string, unknown>);
      const found = entries.find(([k]) => k === (section as string));
      const existingSection = found ? found[1] : undefined;
      if (existingSection !== null && existingSection !== undefined && typeof existingSection === 'object' && !Array.isArray(existingSection)) {
        const merged = deepMerge(existingSection as Record<string, unknown>, partial as Record<string, unknown>);
        return { ...prev, [section]: merged };
      }
      return { ...prev, [section]: partial as AppSettings[T] };
    });
  }, []);

  const resetToDefaults = useCallback(() => setSettings(defaultSettings), []);

  const exportSettings = useCallback((): string => JSON.stringify(settings, null, 2), [settings]);

  const importSettings = useCallback((newSettings: Partial<AppSettings>) => {
    try {
      const validated = AppSettingsSchema.partial().parse(newSettings);
      setSettings(prev => ({ ...prev, ...validated } as AppSettings));
    } catch (err) {
      console.error('Settings import failed validation:', err);
      throw err;
    }
  }, []);

  const saveProfile = useCallback((name: string) => {
    const id = `profile_${Date.now()}`;
    const profile = { id, name, settings: { ...settings }, createdAt: new Date().toISOString() };
    setSettings(prev => ({
      ...prev,
      profiles: { ...prev.profiles, savedProfiles: [...prev.profiles.savedProfiles, profile], activeProfileId: id },
    }));
  }, [settings]);

  const loadProfile = useCallback((id: string) => {
    const profile = settings.profiles.savedProfiles.find(p => p.id === id);
    if (profile) setSettings(prev => ({ ...prev, ...profile.settings, profiles: { ...prev.profiles, activeProfileId: id } }));
  }, [settings.profiles.savedProfiles]);

  const deleteProfile = useCallback((id: string) => {
    setSettings(prev => ({
      ...prev,
      profiles: { savedProfiles: prev.profiles.savedProfiles.filter(p => p.id !== id), activeProfileId: prev.profiles.activeProfileId === id ? null : prev.profiles.activeProfileId },
    }));
  }, []);

  const setActiveProfile = useCallback((id: string | null) => {
    setSettings(prev => ({ ...prev, profiles: { ...prev.profiles, activeProfileId: id } }));
  }, []);

  const updater = useMemo(() => ({
    updateSection, resetToDefaults, exportSettings, importSettings,
    saveProfile, loadProfile, deleteProfile, setActiveProfile
  }), [updateSection, resetToDefaults, exportSettings, importSettings, saveProfile, loadProfile, deleteProfile, setActiveProfile]);

  const contextValue = useMemo(() => ({ settings, updater }), [settings, updater]);

  return (
    <SettingsContext.Provider value={contextValue}>
      {children}
    </SettingsContext.Provider>
  );
}
