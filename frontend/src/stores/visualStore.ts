import { create } from 'zustand';
import { DEFAULT_VISUAL_STATE, type VisualState } from '@/lib/visualState';
import type { VisualContextValue } from '@/context/visual-context';
export type VisualStore = VisualContextValue;

export const useVisualStore = create<VisualStore>((set) => ({
  state: DEFAULT_VISUAL_STATE,
  setState: (state: VisualState) => set({ state }),
}));
