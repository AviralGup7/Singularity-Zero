import { useState, useCallback } from 'react';

interface SavedFilterPreset {
  id: string;
  name: string;
  filters: Record<string, string>;
  createdAt: string;
}

const STORAGE_KEY = 'cyber-pipeline-saved-filters';

export function getSavedFilterPresets(): SavedFilterPreset[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    return raw ? JSON.parse(raw) : [];
  } catch {
    return [];
  }
}

export function saveFilterPreset(name: string, filters: Record<string, string>): SavedFilterPreset {
  const preset: SavedFilterPreset = {
    id: `preset-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    name,
    filters,
    createdAt: new Date().toISOString(),
  };
  const presets = getSavedFilterPresets();
  presets.push(preset);
  localStorage.setItem(STORAGE_KEY, JSON.stringify(presets));
  return preset;
}

export function loadFilterPreset(id: string): SavedFilterPreset | null {
  const presets = getSavedFilterPresets();
  return presets.find((p) => p.id === id) || null;
}

export function deleteFilterPreset(id: string): void {
  const presets = getSavedFilterPresets();
  const filtered = presets.filter((p) => p.id !== id);
  localStorage.setItem(STORAGE_KEY, JSON.stringify(filtered));
}

export function useSavedFilterPresets() {
   
  const [presets, setPresets] = useState<SavedFilterPreset[]>(getSavedFilterPresets);

  const save = useCallback((name: string, filters: Record<string, string>) => {
    const preset = saveFilterPreset(name, filters);
    setPresets(getSavedFilterPresets());
    return preset;
  }, []);

  const load = useCallback((id: string): SavedFilterPreset | null => {
    return loadFilterPreset(id);
  }, []);

  const remove = useCallback((id: string) => {
    deleteFilterPreset(id);
    setPresets(getSavedFilterPresets());
  }, []);

  return { presets, save, load, remove };
}
