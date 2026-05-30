import { create } from 'zustand';
import { safeStorage } from '@/utils/storage';
import type { DensityMode, FontSize, DisplayState, DisplayUpdater } from '@/context/display-context';

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

function getInitialDisplay(): DisplayState {
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
    } catch {
      /* ignore */
    }
  }
  return {
    ...defaultDisplay,
    systemReducedMotion: detectSystemReducedMotion(),
    constrainedDevice: detectConstrainedDevice(),
  };
}

const applyDisplaySideEffects = (display: DisplayState) => {
  if (typeof window === 'undefined') return;
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
  safeStorage.set('cyber-pipeline-display', JSON.stringify(display));
};

export interface DisplayStore {
  display: DisplayState;
  updater: DisplayUpdater;
}

export const useDisplayStore = create<DisplayStore>((set) => {
  const initialDisplay = getInitialDisplay();

  // Apply initial side effects on load
  applyDisplaySideEffects(initialDisplay);

  const updateDisplay = (partial: Partial<DisplayState>) => {
    set((state) => {
      const nextDisplay = { ...state.display, ...partial };
      applyDisplaySideEffects(nextDisplay);
      return { display: nextDisplay };
    });
  };

  return {
    display: initialDisplay,
    updater: {
      updateDisplay,
      setDensity: (density: DensityMode) => updateDisplay({ density }),
      setFontSize: (fontSize: FontSize) => updateDisplay({ fontSize }),
      setAnimations: (animations: boolean) => updateDisplay({ animations }),
      setGridBackground: (gridBackground: boolean) => updateDisplay({ gridBackground }),
      setReduceMotion: (reduceMotion: boolean) => updateDisplay({ reduceMotion }),
      setHighContrast: (highContrast: boolean) => updateDisplay({ highContrast }),
      setFocusIndicators: (focusIndicators: boolean) => updateDisplay({ focusIndicators }),
      setScreenReaderOptimizations: (screenReaderOptimizations: boolean) => updateDisplay({ screenReaderOptimizations }),
    },
  };
});

// Setup dynamic media query listener for system reduced motion
if (typeof window !== 'undefined' && typeof window.matchMedia === 'function') {
  const media = window.matchMedia('(prefers-reduced-motion: reduce)');
  const handleMediaChange = () => {
    useDisplayStore.getState().updater.updateDisplay({
      systemReducedMotion: media.matches,
    });
  };
  media.addEventListener('change', handleMediaChange);
}
