import { type ReactNode, useEffect, useMemo } from 'react';
import { VisualContext } from './visual-context';
import { useVisualStore } from '@/stores/visualStore';
import { type VisualState } from '@/lib/visualState';

export type { VisualContextValue } from './visual-context';

interface VisualProviderProps {
  children: ReactNode;
  initialValue?: VisualState;
}

export function VisualProvider({ children, initialValue }: VisualProviderProps) {
  const state = useVisualStore((s) => s.state);
  const setState = useVisualStore((s) => s.setState);

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
  }, [initialValue, setState, state]);

  const contextValue = useMemo(() => ({ state, setState }), [state, setState]);

  return (
    <VisualContext.Provider value={contextValue}>
      {children}
    </VisualContext.Provider>
  );
}

