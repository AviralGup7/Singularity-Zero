import { createContext, type ReactNode, useEffect, useMemo, useState } from 'react';
import { DEFAULT_VISUAL_STATE, type VisualState } from '@/lib/visualState';

export interface VisualContextValue {
  state: VisualState;
  setState: (state: VisualState) => void;
}

export const VisualContext = createContext<VisualContextValue>({
  state: DEFAULT_VISUAL_STATE,
  setState: () => {},
});

interface VisualProviderProps {
  children: ReactNode;
  initialValue?: VisualState;
}

export function VisualProvider({ children, initialValue }: VisualProviderProps) {
  const [state, setState] = useState<VisualState>(initialValue || DEFAULT_VISUAL_STATE);

  useEffect(() => {
    if (initialValue) {
      const stateChanged =
        state.intensity !== initialValue.intensity ||
        state.urgency !== initialValue.urgency ||
        state.instability !== initialValue.instability ||
        state.flow !== initialValue.flow ||
        state.confidence !== initialValue.confidence;
      if (stateChanged) {
        setState(initialValue);
      }
    }
  }, [initialValue, state]);

  const contextValue = useMemo(() => ({ state, setState }), [state, setState]);

  return (
    <VisualContext.Provider value={contextValue}>
      {children}
    </VisualContext.Provider>
  );
}
