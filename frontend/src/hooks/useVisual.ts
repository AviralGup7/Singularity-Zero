import { useContext } from 'react';
import { VisualContext } from '@/context/VisualContext';

export function useVisual() {
  return useContext(VisualContext);
}
