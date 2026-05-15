import { useContext } from 'react';
import { VisualContext } from '../context/visual-context';

export function useVisual() {
  return useContext(VisualContext);
}
