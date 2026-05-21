import { type ReactNode } from 'react';
import { SettingsContext } from './settings-context';
import { useSettingsStore } from '@/stores/settingsStore';

export type { AppSettings, SettingsUpdater } from './settings-context';

export function SettingsProvider({ children }: { children: ReactNode }) {
  const store = useSettingsStore();

  return (
    <SettingsContext.Provider value={store}>
      {children}
    </SettingsContext.Provider>
  );
}
