import { useDisplayStore } from '../stores/displayStore';

export function useDisplay() {
  return useDisplayStore();
}
