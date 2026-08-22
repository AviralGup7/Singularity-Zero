import { create } from 'zustand';
import { AppSettingsSchema } from '@/api/schemas';
import type { AppSettings, SettingsUpdater } from '@/context/SettingsContext';
import { tenantSafeStorage } from '@/utils/tenantStorage';
import { apiClient } from '@/api/core';
import { useAuthStore } from './authStore';
import { deepMergeSettings } from './settingsHydrate';

const defaultSettings: AppSettings = AppSettingsSchema.parse({});

function deepMerge<T extends Record<string, unknown>>(target: T, source: Partial<T>): T {
  return deepMergeSettings(target, source);
}

const STORAGE_KEY = 'cyber-pipeline-settings';
const DEBOUNCE_MS = 300;

let debounceTimeout: ReturnType<typeof setTimeout> | null = null;
const persistSettingsDebounced = (settings: AppSettings) => {
  if (debounceTimeout) clearTimeout(debounceTimeout);
  debounceTimeout = setTimeout(() => {
    try {
      tenantSafeStorage.set(STORAGE_KEY, JSON.stringify(settings));
    } catch (err) {
      console.warn('[settings] local persist failed', err);
    }
    apiClient.post('/api/settings', settings).catch(() => {
      // Backend persistence is best-effort; local storage is the source of truth
    });
  }, DEBOUNCE_MS);
};

const clearSettingsDebounce = () => {
  if (debounceTimeout) {
    clearTimeout(debounceTimeout);
    debounceTimeout = null;
  }
};

function getInitialSettings(): AppSettings {
  const stored = tenantSafeStorage.get(STORAGE_KEY);
  if (stored) {
    try {
      const parsed = JSON.parse(stored);
      return AppSettingsSchema.parse(deepMerge(defaultSettings as Record<string, unknown>, parsed));
    } catch (err) {
      console.warn('[settings] ignored corrupt stored settings', err);
    }
  }
  return defaultSettings;
}

export interface SettingsStore {
  settings: AppSettings;
  updater: SettingsUpdater & { clearDebounce?: () => void };
}

export const useSettingsStore = create<SettingsStore>((set, get) => {
  const initialSettings = getInitialSettings();

  const updateSection = <T extends keyof AppSettings>(section: T, partial: Partial<AppSettings[T]>) => {
    set((state) => {
      let nextSection = partial as AppSettings[T];
      // ``section`` is typed as ``keyof AppSettings``; the dynamic
      // key is statically bounded to the union members of the
      // settings record, so the warning is a false positive.
      // eslint-disable-next-line security/detect-object-injection
      const existingSection = state.settings[section];

      if (existingSection !== null && existingSection !== undefined && typeof existingSection === 'object' && !Array.isArray(existingSection)) {
        nextSection = deepMerge(existingSection as Record<string, unknown>, partial as Record<string, unknown>) as AppSettings[T];
      }

      const nextSettings = { ...state.settings, [section]: nextSection };
      persistSettingsDebounced(nextSettings);
      return { settings: nextSettings };
    });
  };

  const resetToDefaults = () => {
    persistSettingsDebounced(defaultSettings);
    set({ settings: defaultSettings });
  };

  const importSettings = (newSettings: Partial<AppSettings>) => {
    try {
      const validated = AppSettingsSchema.partial().parse(newSettings);
      set((state) => {
        const nextSettings = AppSettingsSchema.parse(
          deepMerge(state.settings as Record<string, unknown>, validated as Record<string, unknown>),
        );
        persistSettingsDebounced(nextSettings);
        return { settings: nextSettings };
      });
    } catch (err) {
      console.error('Settings import failed validation:', err);
      throw err;
    }
  };

  const saveProfile = (name: string) => {
    const id = `profile_${Date.now()}`;
    set((state) => {
      const profile = { id, name, settings: { ...state.settings }, createdAt: new Date().toISOString() };
      const nextSettings = {
        ...state.settings,
        profiles: {
          ...state.settings.profiles,
          savedProfiles: [...state.settings.profiles.savedProfiles, profile],
          activeProfileId: id,
        },
      };
      persistSettingsDebounced(nextSettings);
      return { settings: nextSettings };
    });
  };

  const loadProfile = (id: string) => {
    set((state) => {
      const profile = state.settings.profiles.savedProfiles.find(p => p.id === id);
      if (!profile) return {};
      const nextSettings = {
        ...state.settings,
        ...profile.settings,
        profiles: { ...state.settings.profiles, activeProfileId: id },
      };
      persistSettingsDebounced(nextSettings);
      return { settings: nextSettings };
    });
  };

  const deleteProfile = (id: string) => {
    set((state) => {
      const nextSettings = {
        ...state.settings,
        profiles: {
          savedProfiles: state.settings.profiles.savedProfiles.filter(p => p.id !== id),
          activeProfileId: state.settings.profiles.activeProfileId === id ? null : state.settings.profiles.activeProfileId,
        },
      };
      persistSettingsDebounced(nextSettings);
      return { settings: nextSettings };
    });
  };

  const setActiveProfile = (id: string | null) => {
    set((state) => {
      const nextSettings = {
        ...state.settings,
        profiles: { ...state.settings.profiles, activeProfileId: id },
      };
      persistSettingsDebounced(nextSettings);
      return { settings: nextSettings };
    });
  };

  return {
    settings: initialSettings,
    updater: {
      updateSection,
      resetToDefaults,
      exportSettings: () => JSON.stringify(get().settings, null, 2),
      importSettings,
      saveProfile,
      loadProfile,
      deleteProfile,
      setActiveProfile,
      clearDebounce: clearSettingsDebounce,
    },
  };
});

export function settingsScopeKey(user: { tenantId?: string; id?: string } | null | undefined): string {
  if (!user) return 'anon';
  return String(user.tenantId || user.id || 'session');
}

let currentScope = settingsScopeKey(useAuthStore.getState().user);
let tenantDebounceTimer: ReturnType<typeof setTimeout> | null = null;
useAuthStore.subscribe((state) => {
  const nextScope = settingsScopeKey(state.user);
  if (nextScope === currentScope) return;
  currentScope = nextScope;
  if (tenantDebounceTimer) clearTimeout(tenantDebounceTimer);
  tenantDebounceTimer = setTimeout(() => {
    useSettingsStore.setState({ settings: getInitialSettings() });
  }, 100);
});
