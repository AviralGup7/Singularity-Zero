import { createContext  } from 'react';
import type {ReactNode} from 'react';
import type { EffectCapability, MotionIntensity } from '@/lib/motionPolicy';
import { useThemeStore } from '@/stores/themeStore';

export type ThemeMode = 'dark' | 'light';

export type ThemePreset = 'midnight' | 'ocean' | 'forest' | 'sunset' | 'arctic' | 'neon-void';

export const THEME_PRESETS: Record<ThemePreset, { label: string; icon: string; description: string; preview: string[] }> = {
  'midnight':  { label: 'Midnight',     icon: '\ud83c\udf19', description: 'Classic cyberpunk dark with neon blue accents',    preview: ['#080B12', '#4A8EFF', '#A078FF', '#FF2D55'] },
  'ocean':     { label: 'Ocean Deep',   icon: '\ud83c\udf0a', description: 'Deep sea blue tones with cool cyan highlights',    preview: ['#0A1628', '#38BDF8', '#818CF8', '#F43F5E'] },
  'forest':    { label: 'Forest',       icon: '\ud83c\udf32', description: 'Emerald green palette inspired by deep forests',   preview: ['#0A1410', '#34D399', '#22D3EE', '#EF4444'] },
  'sunset':    { label: 'Sunset',       icon: '\ud83c\udf05', description: 'Warm amber and coral tones for a cozy feel',      preview: ['#140E0A', '#FB923C', '#F472B6', '#EF4444'] },
  'arctic':    { label: 'Arctic Frost', icon: '\u2744\ufe0f', description: 'Icy cool blue-white with frosted glass effects',  preview: ['#0C1218', '#7DD3FC', '#C4B5FD', '#F43F5E'] },
  'neon-void': { label: 'Neon Void',    icon: '\ud83c\udf1f', description: 'Deep purple void with vivid neon highlights',     preview: ['#06060A', '#C084FC', '#F472B6', '#FF2D87'] },
};

export interface ThemeState {
  mode: ThemeMode;
  preset: ThemePreset;
  accentColor: string;
  motionIntensity: MotionIntensity;
  effectCapability: EffectCapability;
}

export interface ThemeUpdater {
  updateTheme: (partial: Partial<ThemeState>) => void;
  setThemeMode: (mode: ThemeMode) => void;
  setThemePreset: (preset: ThemePreset) => void;
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
