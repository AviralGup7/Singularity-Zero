import { create } from 'zustand';
import { AppSettingsSchema } from '@/api/schemas';
import { safeStorage } from '@/utils/storage';
import type { AppSettings, SettingsUpdater } from '@/context/settings-context';
import { useAuthStore } from './authStore';

const defaultSettings: AppSettings = AppSettingsSchema.parse({});

function deepMerge<T extends Record<string, unknown>>(target: T, source: Partial<T>): T {
  const result = { ...target } as Record<string, unknown>;
  for (const key of Object.keys(source)) {
    const sourceVal = source[key as keyof T];
    const targetVal = target[key as keyof T];

    if (sourceVal !== undefined) {
      if (sourceVal !== null && typeof sourceVal === 'object' && !Array.isArray(sourceVal) &&
          targetVal !== null && typeof targetVal === 'object' && !Array.isArray(targetVal)) {
        // ``key`` is a member of ``Object.keys(source)``, i.e. a known
        // setting key from the validated settings schema. The
        // dynamic-key warning is a false positive.
        /* eslint-disable-next-line security/detect-object-injection */
        result[key] = deepMerge(targetVal as Record<string, unknown>, sourceVal as Record<string, unknown>);
      } else {
        /* eslint-disable-next-line security/detect-object-injection */
        result[key] = sourceVal;
      }
    }
  }
  return result as T;
}

const STORAGE_KEY = 'cyber-pipeline-settings';
const DEBOUNCE_MS = 300;

const getScopedStorageKey = () => {
  const tenantId = useAuthStore.getState().user?.tenantId || 'tenant-default';
  return `${STORAGE_KEY}:${tenantId}`;
};

let debounceTimeout: ReturnType<typeof setTimeout> | null = null;
const persistSettingsDebounced = (settings: AppSettings) => {
  if (debounceTimeout) clearTimeout(debounceTimeout);
  debounceTimeout = setTimeout(() => {
    safeStorage.set(getScopedStorageKey(), JSON.stringify(settings));
  }, DEBOUNCE_MS);
};

const clearSettingsDebounce = () => {
  if (debounceTimeout) {
    clearTimeout(debounceTimeout);
    debounceTimeout = null;
  }
};

function getInitialSettings(): AppSettings {
  const key = getScopedStorageKey();
  const stored = safeStorage.get(key) || safeStorage.get(STORAGE_KEY);
  if (stored) {
    try {
      const parsed = JSON.parse(stored);
      return AppSettingsSchema.parse({ ...defaultSettings, ...parsed });
    } catch {
      /* ignore */
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
        const nextSettings = { ...state.settings, ...validated } as AppSettings;
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

let currentTenantId = useAuthStore.getState().user?.tenantId;
useAuthStore.subscribe((state) => {
  const nextTenantId = state.user?.tenantId;
  if (nextTenantId !== currentTenantId) {
    currentTenantId = nextTenantId;
    useSettingsStore.setState({ settings: getInitialSettings() });
  }
});
