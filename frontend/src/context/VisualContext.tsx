import { useState, type ReactNode } from 'react';
import { DEFAULT_VISUAL_STATE, type VisualState } from '@/lib/visualState';
import { VisualContext } from './visual-context';

export type { VisualContextValue } from './visual-context';

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
