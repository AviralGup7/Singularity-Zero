import { createContext } from 'react';
import { DEFAULT_VISUAL_STATE, type VisualState } from '@/lib/visualState';

export interface VisualContextValue {
  state: VisualState;
  setState: (state: VisualState) => void;
}

export const VisualContext = createContext<VisualContextValue>({
  state: DEFAULT_VISUAL_STATE,
  setState: () => {},
});
