import { create } from 'zustand';
import type { EffectCapability, MotionIntensity } from '@/lib/motionPolicy';
import { safeStorage } from '@/utils/storage';
import type { ThemeMode, ThemeState, ThemeUpdater } from '@/context/theme-context';

function detectSystemTheme(): ThemeMode {
  if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') {
    return 'dark';
  }
  return window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
}

const defaultTheme: ThemeState = {
  mode: detectSystemTheme(),
  accentColor: '#3B82F6',
  motionIntensity: 'high' as MotionIntensity,
  effectCapability: 'auto' as EffectCapability,
};

function getInitialTheme(): ThemeState {
  const stored = safeStorage.get('cyber-pipeline-theme');
  if (stored) {
    try {
      const parsed = JSON.parse(stored);
      return { ...defaultTheme, ...(parsed.theme || {}) };
    } catch {
      /* ignore */
    }
  }
  return defaultTheme;
}

const applyThemeSideEffects = (theme: ThemeState) => {
  if (typeof window === 'undefined') return;
  document.documentElement.setAttribute('data-theme', theme.mode);
  if (theme.accentColor !== '#3B82F6') {
    document.documentElement.style.setProperty('--accent', theme.accentColor);
  } else {
    document.documentElement.style.removeProperty('--accent');
  }
  document.documentElement.setAttribute('data-motion-intensity', theme.motionIntensity);
  document.documentElement.setAttribute('data-effect-capability', theme.effectCapability);
  safeStorage.set('cyber-pipeline-theme', JSON.stringify({ theme }));
};

export interface ThemeStore {
  theme: ThemeState;
  updater: ThemeUpdater;
}

export const useThemeStore = create<ThemeStore>((set) => {
  const initialTheme = getInitialTheme();
  
  // Apply initial side effects on load
  applyThemeSideEffects(initialTheme);

  const updateTheme = (partial: Partial<ThemeState>) => {
    set((state) => {
      const nextTheme = { ...state.theme, ...partial };
      applyThemeSideEffects(nextTheme);
      return { theme: nextTheme };
    });
  };

  return {
    theme: initialTheme,
    updater: {
      updateTheme,
      setThemeMode: (mode: ThemeMode) => updateTheme({ mode }),
      setAccentColor: (accentColor: string) => updateTheme({ accentColor }),
      setMotionIntensity: (motionIntensity: MotionIntensity) => updateTheme({ motionIntensity }),
      setEffectCapability: (effectCapability: EffectCapability) => updateTheme({ effectCapability }),
    },
  };
});
