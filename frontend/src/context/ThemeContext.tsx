import { createContext, useContext, useState, useEffect, type ReactNode, useCallback } from 'react';
import type { EffectCapability, MotionIntensity } from '@/lib/motionPolicy';
import { safeStorage } from '@/utils/storage';

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

const ThemeContext = createContext<{ theme: ThemeState; updater: ThemeUpdater } | undefined>(undefined);

function detectSystemTheme(): ThemeMode {
  if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') {
    return 'dark';
  }
  return window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
}

const defaultTheme: ThemeState = {
  mode: detectSystemTheme(),
  accentColor: '#00f3ff',
  motionIntensity: 'high',
  effectCapability: 'auto',
};

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [theme, setTheme] = useState<ThemeState>(() => {
    const stored = safeStorage.get('cyber-pipeline-theme');
    if (stored) {
      try {
        const parsed = JSON.parse(stored);
        return { ...defaultTheme, ...(parsed.theme || {}) };
      } catch { /* ignore */ }
    }
    return defaultTheme;
  });

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme.mode);
    document.documentElement.style.setProperty('--accent', theme.accentColor);
    document.documentElement.setAttribute('data-motion-intensity', theme.motionIntensity);
    document.documentElement.setAttribute('data-effect-capability', theme.effectCapability);
    safeStorage.set('cyber-pipeline-theme', JSON.stringify({ theme }));
  }, [theme]);

  const updateTheme = useCallback((partial: Partial<ThemeState>) => {
    setTheme(prev => ({ ...prev, ...partial }));
  }, []);

  const setThemeMode = useCallback((mode: ThemeMode) => updateTheme({ mode }), [updateTheme]);
  const setAccentColor = useCallback((accentColor: string) => updateTheme({ accentColor }), [updateTheme]);
  const setMotionIntensity = useCallback((motionIntensity: MotionIntensity) => updateTheme({ motionIntensity }), [updateTheme]);
  const setEffectCapability = useCallback((effectCapability: EffectCapability) => updateTheme({ effectCapability }), [updateTheme]);

  return (
    <ThemeContext.Provider value={{ theme, updater: { updateTheme, setThemeMode, setAccentColor, setMotionIntensity, setEffectCapability } }}>
      {children}
    </ThemeContext.Provider>
  );
}

export function useTheme() {
  const context = useContext(ThemeContext);
  if (!context) throw new Error('useTheme must be used within a ThemeProvider');
  return context;
}
