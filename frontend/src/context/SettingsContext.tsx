import { createContext, type ReactNode } from 'react';
import { AppSettingsSchema } from '@/api/schemas';
import { z } from 'zod';
import { useSettingsStore } from '@/stores/settingsStore';

export type AppSettings = z.infer<typeof AppSettingsSchema>;

export interface SettingsUpdater {
  updateSection: <T extends keyof AppSettings>(section: T, partial: Partial<AppSettings[T]>) => void;
  resetToDefaults: () => void;
  exportSettings: () => string;
  importSettings: (settings: Partial<AppSettings>) => void;
  saveProfile: (name: string) => void;
  loadProfile: (id: string) => void;
  deleteProfile: (id: string) => void;
  setActiveProfile: (id: string | null) => void;
}

export const SettingsContext = createContext<{ settings: AppSettings; updater: SettingsUpdater } | undefined>(undefined);

export function SettingsProvider({ children }: { children: ReactNode }) {
  const store = useSettingsStore();

  return (
    <SettingsContext.Provider value={store}>
      {children}
    </SettingsContext.Provider>
  );
}
