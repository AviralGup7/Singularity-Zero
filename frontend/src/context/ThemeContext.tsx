import { useState, useEffect, type ReactNode, useCallback } from 'react';
import type { EffectCapability, MotionIntensity } from '@/lib/motionPolicy';
import { safeStorage } from '@/utils/storage';
import { ThemeContext } from './theme-context';

export type { ThemeMode, ThemeState, ThemeUpdater } from './theme-context';

import type { ThemeMode, ThemeState } from './theme-context';

function detectSystemTheme(): ThemeMode {
  if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') {
    return 'dark';
  }
  return window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
}

const defaultTheme: ThemeState = {
  mode: detectSystemTheme(),
  accentColor: '#00f3ff',
  motionIntensity: 'high' as MotionIntensity,
  effectCapability: 'auto' as EffectCapability,
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
