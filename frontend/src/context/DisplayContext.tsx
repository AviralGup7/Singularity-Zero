import { type ReactNode } from 'react';
import { DisplayContext } from './display-context';
import { useDisplayStore } from '@/stores/displayStore';

export type { DensityMode, FontSize, DisplayState, DisplayUpdater } from './display-context';

export function DisplayProvider({ children }: { children: ReactNode }) {
  const store = useDisplayStore();

  return (
    <DisplayContext.Provider value={store}>
      {children}
    </DisplayContext.Provider>
  );
}
