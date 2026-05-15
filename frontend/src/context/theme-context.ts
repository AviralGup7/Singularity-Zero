import { createContext } from 'react';
import type { EffectCapability, MotionIntensity } from '@/lib/motionPolicy';

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
