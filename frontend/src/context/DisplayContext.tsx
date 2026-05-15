import { useState, useEffect, type ReactNode, useCallback } from 'react';
import { safeStorage } from '@/utils/storage';
import { DisplayContext } from './display-context';

export type { DensityMode, FontSize, DisplayState, DisplayUpdater } from './display-context';

import type { DisplayState } from './display-context';

const defaultDisplay: DisplayState = {
  density: 'comfortable',
  fontSize: 'medium',
  animations: true,
  gridBackground: true,
  reduceMotion: false,
  highContrast: false,
  focusIndicators: true,
  screenReaderOptimizations: false,
  systemReducedMotion: false,
  constrainedDevice: false,
};

function detectSystemReducedMotion(): boolean {
  if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') {
    return false;
  }
  return window.matchMedia('(prefers-reduced-motion: reduce)').matches;
}

function detectConstrainedDevice(): boolean {
  if (typeof navigator === 'undefined') {
    return false;
  }
  const cores = typeof navigator.hardwareConcurrency === 'number' ? navigator.hardwareConcurrency : 8;
  const memoryValue = (navigator as Navigator & { deviceMemory?: number }).deviceMemory;
  const memory = typeof memoryValue === 'number' ? memoryValue : 8;
  return cores <= 2 || memory <= 2;
}

export function DisplayProvider({ children }: { children: ReactNode }) {
  const [display, setDisplay] = useState<DisplayState>(() => {
    const stored = safeStorage.get('cyber-pipeline-display');
    if (stored) {
      try {
        const parsed = JSON.parse(stored);
        return {
          ...defaultDisplay,
          ...parsed,
          systemReducedMotion: detectSystemReducedMotion(),
          constrainedDevice: detectConstrainedDevice(),
        };
      } catch { /* ignore */ }
    }
    return {
      ...defaultDisplay,
      systemReducedMotion: detectSystemReducedMotion(),
      constrainedDevice: detectConstrainedDevice(),
    };
  });

  useEffect(() => {
    document.documentElement.setAttribute('data-density', display.density);
    document.documentElement.setAttribute('data-font-size', display.fontSize);
    document.documentElement.setAttribute('data-animations', display.animations ? 'true' : 'false');
    document.documentElement.setAttribute('data-grid-bg', display.gridBackground ? 'true' : 'false');
    document.documentElement.setAttribute('data-reduce-motion', display.reduceMotion ? 'true' : 'false');
    document.documentElement.setAttribute('data-system-reduced-motion', display.systemReducedMotion ? 'true' : 'false');
    document.documentElement.setAttribute('data-constrained-device', display.constrainedDevice ? 'true' : 'false');
    document.documentElement.setAttribute('data-accessibility',
      display.highContrast ? 'high-contrast' :
      display.reduceMotion ? 'reduce-motion' :
      display.focusIndicators ? 'focus-indicators' : 'default'
    );
  }, [display]);

  useEffect(() => {
    const media = typeof window !== 'undefined' && typeof window.matchMedia === 'function'
      ? window.matchMedia('(prefers-reduced-motion: reduce)')
      : null;
    const applySystemFlags = () => {
      setDisplay(prev => ({
        ...prev,
        systemReducedMotion: detectSystemReducedMotion(),
        constrainedDevice: detectConstrainedDevice(),
      }));
    };
    applySystemFlags();
    if (!media) return undefined;
    const onChange = () => applySystemFlags();
    media.addEventListener('change', onChange);
    return () => media.removeEventListener('change', onChange);
  }, []);

  const updateDisplay = useCallback((partial: Partial<DisplayState>) => {
    setDisplay(prev => {
      const next = { ...prev, ...partial };
      safeStorage.set('cyber-pipeline-display', JSON.stringify(next));
      return next;
    });
  }, []);

  const setDensity = useCallback((density: DisplayState['density']) => updateDisplay({ density }), [updateDisplay]);
  const setFontSize = useCallback((fontSize: DisplayState['fontSize']) => updateDisplay({ fontSize }), [updateDisplay]);
  const setAnimations = useCallback((animations: boolean) => updateDisplay({ animations }), [updateDisplay]);
  const setGridBackground = useCallback((gridBackground: boolean) => updateDisplay({ gridBackground }), [updateDisplay]);
  const setReduceMotion = useCallback((reduceMotion: boolean) => updateDisplay({ reduceMotion }), [updateDisplay]);
  const setHighContrast = useCallback((highContrast: boolean) => updateDisplay({ highContrast }), [updateDisplay]);
  const setFocusIndicators = useCallback((focusIndicators: boolean) => updateDisplay({ focusIndicators }), [updateDisplay]);
  const setScreenReaderOptimizations = useCallback((screenReaderOptimizations: boolean) => updateDisplay({ screenReaderOptimizations }), [updateDisplay]);

  return (
    <DisplayContext.Provider value={{ display, updater: { updateDisplay, setDensity, setFontSize, setAnimations, setGridBackground, setReduceMotion, setHighContrast, setFocusIndicators, setScreenReaderOptimizations } }}>
      {children}
    </DisplayContext.Provider>
  );
}
