import { type ReactNode, useEffect, useMemo, useState } from 'react';
import { VisualContext } from './visual-context';
import { DEFAULT_VISUAL_STATE, type VisualState } from '@/lib/visualState';

export type { VisualContextValue } from './visual-context';

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
        // eslint-disable-next-line react-hooks/set-state-in-effect
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

