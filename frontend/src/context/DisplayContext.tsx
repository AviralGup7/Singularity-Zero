import { createContext, type ReactNode } from 'react';
import { useDisplayStore } from '@/stores/displayStore';

export type DensityMode = 'compact' | 'comfortable' | 'spacious';
export type FontSize = 'small' | 'medium' | 'large';

export interface DisplayState {
  density: DensityMode;
  fontSize: FontSize;
  animations: boolean;
  gridBackground: boolean;
  reduceMotion: boolean;
  highContrast: boolean;
  focusIndicators: boolean;
  screenReaderOptimizations: boolean;
  systemReducedMotion: boolean;
  constrainedDevice: boolean;
}

export interface DisplayUpdater {
  updateDisplay: (partial: Partial<DisplayState>) => void;
  setDensity: (density: DensityMode) => void;
  setFontSize: (size: FontSize) => void;
  setAnimations: (enabled: boolean) => void;
  setGridBackground: (enabled: boolean) => void;
  setReduceMotion: (enabled: boolean) => void;
  setHighContrast: (enabled: boolean) => void;
  setFocusIndicators: (enabled: boolean) => void;
  setScreenReaderOptimizations: (enabled: boolean) => void;
}

export const DisplayContext = createContext<{ display: DisplayState; updater: DisplayUpdater } | undefined>(undefined);

export function DisplayProvider({ children }: { children: ReactNode }) {
  const store = useDisplayStore();

  return (
    <DisplayContext.Provider value={store}>
      {children}
    </DisplayContext.Provider>
  );
}
