import { createContext, type ReactNode } from 'react';
import type { EffectCapability, MotionIntensity } from '@/lib/motionPolicy';
import { useThemeStore } from '@/stores/themeStore';

export type ThemeMode = 'dark' | 'light';

export interface ThemeState {
  mode: ThemeMode;
  accentColor: string;
  motionIntensity: MotionIntensity;
  effectCapability: EffectCapability;
}

export interface ThemeUpdater {
  updateTheme: (partial: Partial<ThemeState>) => void;
  setThemeMode: (mode: ThemeMode) => void;
  setAccentColor: (color: string) => void;
  setMotionIntensity: (intensity: MotionIntensity) => void;
  setEffectCapability: (capability: EffectCapability) => void;
}

export const ThemeContext = createContext<{ theme: ThemeState; updater: ThemeUpdater } | undefined>(undefined);

export function ThemeProvider({ children }: { children: ReactNode }) {
  const store = useThemeStore();

  return (
    <ThemeContext.Provider value={store}>
      {children}
    </ThemeContext.Provider>
  );
}
