import { type ReactNode, useEffect } from 'react';
import { VisualContext } from './visual-context';
import { useVisualStore } from '@/stores/visualStore';
import { type VisualState } from '@/lib/visualState';

export type { VisualContextValue } from './visual-context';

interface VisualProviderProps {
  children: ReactNode;
  initialValue?: VisualState;
}

export function VisualProvider({ children, initialValue }: VisualProviderProps) {
  const store = useVisualStore();

  useEffect(() => {
    if (initialValue) {
      store.setState(initialValue);
    }
  }, [initialValue, store]);

  return (
    <VisualContext.Provider value={store}>
      {children}
    </VisualContext.Provider>
  );
}
