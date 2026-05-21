import { type ReactNode } from 'react';
import { ThemeContext } from './theme-context';
import { useThemeStore } from '@/stores/themeStore';

export type { ThemeMode, ThemeState, ThemeUpdater } from './theme-context';

export function ThemeProvider({ children }: { children: ReactNode }) {
  const store = useThemeStore();

  return (
    <ThemeContext.Provider value={store}>
      {children}
    </ThemeContext.Provider>
  );
}
