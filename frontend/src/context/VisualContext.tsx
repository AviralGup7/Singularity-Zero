import { createContext, useContext, useState, type ReactNode } from 'react';
import { DEFAULT_VISUAL_STATE, type VisualState } from '@/lib/visualState';

interface VisualContextValue {
  state: VisualState;
  setState: (state: VisualState) => void;
}

const VisualContext = createContext<VisualContextValue>({
  state: DEFAULT_VISUAL_STATE,
  setState: () => {},
});

interface VisualProviderProps {
  children: ReactNode;
  initialValue?: VisualState;
}

export function VisualProvider({ children, initialValue }: VisualProviderProps) {
  const [state, setState] = useState<VisualState>(initialValue ?? DEFAULT_VISUAL_STATE);

  return (
    <VisualContext.Provider value={{ state, setState }}>
      {children}
    </VisualContext.Provider>
  );
}

export function useVisual() {
  return useContext(VisualContext);
}

