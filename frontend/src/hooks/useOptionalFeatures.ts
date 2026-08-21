import { useSettingsStore } from '@/stores/settingsStore';

export function useOptionalFeatures() {
  return useSettingsStore((state) => state.settings.features);
}
