import { useContext } from 'react';
import { DisplayContext } from '../context/display-context';

export function useDisplay() {
  const context = useContext(DisplayContext);
  if (!context) throw new Error('useDisplay must be used within a DisplayProvider');
  return context;
}
